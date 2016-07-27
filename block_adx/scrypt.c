#include <base/std_def.h>
#include <base/std_mem.h>
#include <base/mem_base.h>
#include <base/std_str.h>

#include <sha256.h>

#include <strs.h>
#include <tree.h>

typedef unsigned char uint8_t;
typedef unsigned int  uint32_t;
typedef unsigned int  uintptr_t;


#define SCRYPT_BUFFER_SIZE (131072 + 63)
#define inline __inline

#define SHA256_Init(a)  mbedtls_sha256_init(a); mbedtls_sha256_starts(a,0);
#define SHA256_Update(a,b,c)  mbedtls_sha256_update(a,b,c)
#define SHA256_Final(a,b)  mbedtls_sha256_finish(b,a); 	mbedtls_sha256_free(b)

//#include <openssl/sha.h>

typedef struct HMAC_SHA256Context {
	mbedtls_sha256_context ictx;
	mbedtls_sha256_context octx;
} HMAC_SHA256_CTX;

static inline uint32_t be32dec(const void *pp)
{
	const uint8_t *p = (uint8_t const *)pp;

	return ((uint32_t)(p[3]) + ((uint32_t)(p[2]) << 8) +
		((uint32_t)(p[1]) << 16) + ((uint32_t)(p[0]) << 24));
}

static inline void
be32enc(void *pp, uint32_t x)
{
	uint8_t * p = (uint8_t *)pp;

	p[3] = x & 0xff;
	p[2] = (x >> 8) & 0xff;
	p[1] = (x >> 16) & 0xff;
	p[0] = (x >> 24) & 0xff;
}



/* Initialize an HMAC-SHA256 operation with the given key. */
void
HMAC_SHA256_Init(HMAC_SHA256_CTX * ctx, const void * _K, size_t Klen)
{
	unsigned char pad[64];
	unsigned char khash[32];
	const unsigned char * K = (const unsigned char *)_K;
	size_t i;

	/* If Klen > 64, the key is really SHA256(K). */
	if (Klen > 64) {
		SHA256_Init(&ctx->ictx);
		SHA256_Update(&ctx->ictx, K, Klen);
		SHA256_Final(khash, &ctx->ictx);
		K = khash;
		Klen = 32;
	}

	/* Inner SHA256 operation is SHA256(K xor [block of 0x36] || data). */
	SHA256_Init(&ctx->ictx);
	memset_c(pad, 0x36, 64);
	for (i = 0; i < Klen; i++)
		pad[i] ^= K[i];
	SHA256_Update(&ctx->ictx, pad, 64);

	/* Outer SHA256 operation is SHA256(K xor [block of 0x5c] || hash). */
	SHA256_Init(&ctx->octx);
	memset_c(pad, 0x5c, 64);
	for (i = 0; i < Klen; i++)
		pad[i] ^= K[i];
	SHA256_Update(&ctx->octx, pad, 64);

	/* Clean the stack. */
	memset_c(khash, 0, 32);
}

/* Add bytes to the HMAC-SHA256 operation. */
void
HMAC_SHA256_Update(HMAC_SHA256_CTX * ctx, const void *in, size_t len)
{

	/* Feed data to the inner SHA256 operation. */
	SHA256_Update(&ctx->ictx, in, len);
}

/* Finish an HMAC-SHA256 operation. */
void
HMAC_SHA256_Final(unsigned char digest[32], HMAC_SHA256_CTX * ctx)
{
	unsigned char ihash[32];

	/* Finish the inner SHA256 operation. */
	SHA256_Final(ihash, &ctx->ictx);

	/* Feed the inner hash to the outer SHA256 operation. */
	SHA256_Update(&ctx->octx, ihash, 32);

	/* Finish the outer SHA256 operation. */
	SHA256_Final(digest, &ctx->octx);

	/* Clean the stack. */
	memset_c(ihash, 0, 32);
}

/**
* PBKDF2_SHA256(passwd, passwdlen, salt, saltlen, c, buf, dkLen):
* Compute PBKDF2(passwd, salt, c, dkLen) using HMAC-SHA256 as the PRF, and
* write the output to buf.  The value dkLen must be at most 32 * (2^32 - 1).
*/
void
PBKDF2_SHA256(const uint8_t * passwd, size_t passwdlen, const uint8_t * salt,
size_t saltlen, uint64_t c, uint8_t * buf, size_t dkLen)
{
	HMAC_SHA256_CTX PShctx, hctx;
	size_t i;
	uint8_t ivec[4];
	uint8_t U[32];
	uint8_t T[32];
	uint64_t j;
	int k;
	size_t clen;

	/* Compute HMAC state after processing P and S. */
	HMAC_SHA256_Init(&PShctx, passwd, passwdlen);
	HMAC_SHA256_Update(&PShctx, salt, saltlen);

	/* Iterate through the blocks. */
	for (i = 0; i * 32 < dkLen; i++) {
		/* Generate INT(i + 1). */
		be32enc(ivec, (uint32_t)(i + 1));

		/* Compute U_1 = PRF(P, S || INT(i)). */
		memcpy_c(&hctx, &PShctx, sizeof(HMAC_SHA256_CTX));
		HMAC_SHA256_Update(&hctx, ivec, 4);
		HMAC_SHA256_Final(U, &hctx);

		/* T_i = U_1 ... */
		memcpy_c(T, U, 32);

		for (j = 2; j <= c; j++) {
			/* Compute U_j. */
			HMAC_SHA256_Init(&hctx, passwd, passwdlen);
			HMAC_SHA256_Update(&hctx, U, 32);
			HMAC_SHA256_Final(U, &hctx);

			/* ... xor U_j ... */
			for (k = 0; k < 32; k++)
				T[k] ^= U[k];
		}

		/* Copy as many bytes as necessary into buf. */
		clen = dkLen - i * 32;
		if (clen > 32)
			clen = 32;
		memcpy_c(&buf[i * 32], T, clen);
	}

	/* Clean PShctx, since we never called _Final on it. */
	memset_c(&PShctx, 0, sizeof(HMAC_SHA256_CTX));
}

/*
#if defined (OPTIMIZED_SALSA) && ( defined (__x86_64__) || defined (__i386__) || defined(__arm__) )
extern "C" void scrypt_core(unsigned int *X, unsigned int *V);
#else
*/
// Generic scrypt_core implementation

void xor_salsa8(unsigned int B[16], const unsigned int Bx[16])
{
	unsigned int x00, x01, x02, x03, x04, x05, x06, x07, x08, x09, x10, x11, x12, x13, x14, x15;
	int i;

	x00 = (B[0] ^= Bx[0]);
	x01 = (B[1] ^= Bx[1]);
	x02 = (B[2] ^= Bx[2]);
	x03 = (B[3] ^= Bx[3]);
	x04 = (B[4] ^= Bx[4]);
	x05 = (B[5] ^= Bx[5]);
	x06 = (B[6] ^= Bx[6]);
	x07 = (B[7] ^= Bx[7]);
	x08 = (B[8] ^= Bx[8]);
	x09 = (B[9] ^= Bx[9]);
	x10 = (B[10] ^= Bx[10]);
	x11 = (B[11] ^= Bx[11]);
	x12 = (B[12] ^= Bx[12]);
	x13 = (B[13] ^= Bx[13]);
	x14 = (B[14] ^= Bx[14]);
	x15 = (B[15] ^= Bx[15]);
	for (i = 0; i < 8; i += 2) {
#define R(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
		/* Operate on columns. */
		x04 ^= R(x00 + x12, 7); x09 ^= R(x05 + x01, 7);
		x14 ^= R(x10 + x06, 7); x03 ^= R(x15 + x11, 7);

		x08 ^= R(x04 + x00, 9); x13 ^= R(x09 + x05, 9);
		x02 ^= R(x14 + x10, 9); x07 ^= R(x03 + x15, 9);

		x12 ^= R(x08 + x04, 13); x01 ^= R(x13 + x09, 13);
		x06 ^= R(x02 + x14, 13); x11 ^= R(x07 + x03, 13);

		x00 ^= R(x12 + x08, 18); x05 ^= R(x01 + x13, 18);
		x10 ^= R(x06 + x02, 18); x15 ^= R(x11 + x07, 18);

		/* Operate on rows. */
		x01 ^= R(x00 + x03, 7); x06 ^= R(x05 + x04, 7);
		x11 ^= R(x10 + x09, 7); x12 ^= R(x15 + x14, 7);

		x02 ^= R(x01 + x00, 9); x07 ^= R(x06 + x05, 9);
		x08 ^= R(x11 + x10, 9); x13 ^= R(x12 + x15, 9);

		x03 ^= R(x02 + x01, 13); x04 ^= R(x07 + x06, 13);
		x09 ^= R(x08 + x11, 13); x14 ^= R(x13 + x12, 13);

		x00 ^= R(x03 + x02, 18); x05 ^= R(x04 + x07, 18);
		x10 ^= R(x09 + x08, 18); x15 ^= R(x14 + x13, 18);
#undef R
	}
	B[0] += x00;
	B[1] += x01;
	B[2] += x02;
	B[3] += x03;
	B[4] += x04;
	B[5] += x05;
	B[6] += x06;
	B[7] += x07;
	B[8] += x08;
	B[9] += x09;
	B[10] += x10;
	B[11] += x11;
	B[12] += x12;
	B[13] += x13;
	B[14] += x14;
	B[15] += x15;
}

void scrypt_core(unsigned int *X, unsigned int *V)
{
	unsigned int i, j, k;

	for (i = 0; i < 1024; i++) {
		memcpy_c(&V[i * 32], X, 128);
		xor_salsa8(&X[0], &X[16]);
		xor_salsa8(&X[16], &X[0]);
	}
	for (i = 0; i < 1024; i++) {
		j = 32 * (X[16] & 1023);
		for (k = 0; k < 32; k++)
			X[k] ^= V[j + k];
		xor_salsa8(&X[0], &X[16]);
		xor_salsa8(&X[16], &X[0]);
	}
}

//#endif

/* cpu and memory intensive function to transform a 80 byte buffer into a 32 byte output
scratchpad size needs to be at least 63 + (128 * r * p) + (256 * r + 64) + (128 * r * N) bytes
r = 1, p = 1, N = 1024
*/

int scrypt_nosalt(const void* input, size_t inputlen, void *scratchpad, hash_t result)
{
	unsigned int *V;
	unsigned int X[32];
	V = (unsigned int *)(((uintptr_t)(scratchpad)+63) & ~(uintptr_t)(63));

	PBKDF2_SHA256((const uint8_t*)input, inputlen, (const uint8_t*)input, inputlen, 1, (uint8_t *)X, 128);
	scrypt_core(X, V);
	PBKDF2_SHA256((const uint8_t*)input, inputlen, (uint8_t *)X, 128, 1, (uint8_t*)result, 32);

	return 1;
}
unsigned char *scratchpad = PTR_INVALID;;

void allocate_scratchpad()
{
	scratchpad=malloc_c(SCRYPT_BUFFER_SIZE);
}

int scrypt_blockhash(const void* input,hash_t hash)
{
	if (scratchpad == PTR_INVALID)
		allocate_scratchpad();
		
	memset_c(scratchpad, 0, SCRYPT_BUFFER_SIZE);
	return scrypt_nosalt(input, 80, scratchpad, hash);
}

