
#include "base/std_def.h"
#include "base/std_mem.h"
#include "base/mem_base.h"
#include "base/std_str.h"

#include "api.h"
#define LIBEC_API C_EXPORT

#include <crypto.h>
#include <sha256.h>
#include <strs.h>

#include "fe25519.h"
#include "sc25519.h"
#include "ge25519.h"

extern int crypto_verify_32(const unsigned char *x, const unsigned char *y);

OS_API_C_FUNC(int) crypto_sign_open(const struct string *sign, struct string *msg, const struct string *pk)
{
	unsigned char hram[64];
	unsigned char tmp[128];
	unsigned char pkcopy[32];
	unsigned char rcopy[32];
	unsigned char rcheck[32];
	ge25519 get1, get2;
	sc25519 schram, scs;

	if (sign->len < 64) goto badsig;
	if (sign->str[63] & 224) goto badsig;
	if (ge25519_unpackneg_vartime(&get1, pk->str)) goto badsig;

	memmove_c(pkcopy, pk->str, 32);
	memmove_c(rcopy, sign->str, 32);

	sc25519_from32bytes(&scs, sign->str + 32);

	memmove_c(tmp, sign->str, sign->len);
	memmove_c(tmp + 32, pkcopy, 32);
	crypto_hash_sha512(hram, tmp, sign->len);

	sc25519_from64bytes(&schram, hram);
	ge25519_double_scalarmult_vartime(&get2, &get1, &schram, &ge25519_base, &scs);
	ge25519_pack(rcheck, &get2);
	
	if (crypto_verify_32(rcopy, rcheck) == 0) {
		msg->len  = sign->len - 64;
		msg->size = msg->len+1;
		msg->str  = malloc_c(msg->size);
		memmove_c(msg->str, sign->str + 64, msg->len);
		msg->str[msg->len] = 0;
	}
badsig:
	return 1;
}



#ifdef FORWARD_CRYPTO
OS_API_C_FUNC(int) crypto_extract_key(dh_key_t pk, const dh_key_t sk)
{
	unsigned char az[64];
	sc25519 scsk;
	ge25519 gepk;


	crypto_hash_sha512(az, sk, 32);
	az[0] &= 248;
	az[31] &= 127;
	az[31] |= 64;

	sc25519_from32bytes(&scsk, az);

	ge25519_scalarmult_base(&gepk, &scsk);
	ge25519_pack(pk, &gepk);
	memmove_c(sk + 32, pk, 32);
	return 0;
}

OS_API_C_FUNC(struct string) crypto_sign(struct string *msg, const dh_key_t sk)
{
	struct string sign = { PTR_NULL };
	unsigned char az[64], nonce[64], hram[64];
	unsigned char pk[32];
	sc25519 sck, scs, scsk;
	ge25519 ger;

	memmove_c(pk, sk + 32, 32);
	crypto_hash_sha512(az, sk, 32);
	az[0] &= 248;
	az[31] &= 127;
	az[31] |= 64;
	sign.len	= msg->len + 64;
	sign.size	= sign.len + 1;
	sign.str	= malloc_c(sign.size);
	
	memmove_c(sign.str + 64, msg->str, msg->len);
	memmove_c(sign.str + 32, az + 32, 32);
	/* sm: 32-byte uninit, 32-byte z, mlen-byte m */
	crypto_hash_sha512(nonce, sign.str + 32, msg->len + 32);
	/* nonce: 64-byte H(z,m) */

	sc25519_from64bytes(&sck, nonce);
	ge25519_scalarmult_base(&ger, &sck);
	ge25519_pack(sign.str, &ger);
	/* sm: 32-byte R, 32-byte z, mlen-byte m */
	memmove_c(sign.str + 32, pk, 32);

	crypto_hash_sha512(hram, sign.str, sign.len);
	/* hram: 64-byte H(R,A,m) */
	sc25519_from64bytes(&scs, hram);
	sc25519_from32bytes(&scsk, az);
	sc25519_mul(&scs, &scs, &scsk);
	sc25519_add(&scs, &scs, &sck);
	/* scs: S = nonce + H(R,A,m)a */
	sc25519_to32bytes(sign.str + 32, &scs);
	/* sm: 32-byte R, 32-byte S, mlen-byte m */

	return sign;
}
#endif