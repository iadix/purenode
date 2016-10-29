//copyright iadix 2016
#include <base/std_def.h>
#include <base/std_mem.h>
#include <base/mem_base.h>
#include <base/std_str.h>

#include <sha256.h>
#include <crypto.h>
#include <strs.h>
#include <tree.h>
#ifdef _DEBUG
LIBEC_API int			C_API_FUNC crypto_extract_key	(dh_key_t pk, const dh_key_t sk);
LIBEC_API int			C_API_FUNC crypto_sign_open(const struct string *sign, struct string *msgh, struct string *pk);
#ifdef FORWARD_CRYPTO
LIBEC_API struct string	C_API_FUNC crypto_sign			(struct string *msg, const dh_key_t sk);
#endif
#else
extern crypto_extract_key_func_ptr	crypto_extract_key;
extern crypto_sign_open_func_ptr	crypto_sign_open;
#ifdef FORWARD_CRYPTO
extern crypto_sign_func_ptr			crypto_sign_func;
#endif
#endif

extern unsigned char	pubKeyPrefix;

char* base58(unsigned char *s, char *out) {
	static const char *tmpl = "123456789"
		"ABCDEFGHJKLMNPQRSTUVWXYZ"
		"abcdefghijkmnopqrstuvwxyz";
	static char buf[40];

	int c, i, n;
	if (!out) out = buf;

	n = 34;
	while (n--) {
		for (c = i = 0; i < 25; i++) {
			c = c * 256 + s[i];
			s[i] = c / 58;
			c %= 58;
		}
		out[n] = tmpl[c];
	}

	for (n = 0; out[n] == '1'; n++);
	memmove_c(out, out + n, 33 - n);

	return out;
}


int compute_script_size(mem_zone_ref_ptr script_node)
{
	mem_zone_ref_ptr	key;
	mem_zone_ref		my_list = { PTR_NULL };
	size_t				length;

	length = 0;

	for (tree_manager_get_first_child(script_node, &my_list, &key); ((key != NULL) && (key->zone != NULL)); tree_manager_get_next_child(&my_list, &key))
	{
		unsigned char	*data;

		switch (tree_mamanger_get_node_type(key))
		{
		case NODE_BITCORE_VSTR:
			data = (unsigned char	*)tree_mamanger_get_node_data_ptr(key, 0);
			if (*data == 0x00)
				length++;
			else if (*data < 0xFD)
				length += 1 + (*data);
			else if (*data == 0xFD)
				length += 3 + (*((unsigned short *)(data + 1)));
			else if (*data == 0xFE)
				length += 5 + (*((unsigned int *)(data + 1)));
			else if (*data == 0xFF)
				length += 9 + (*((uint64_t *)(data + 1)));
			break;
		case NODE_BITCORE_VINT:
			data = (unsigned char	*)tree_mamanger_get_node_data_ptr(key, 0);
			if (*data == 0x00)
			{
				length++;
			}
			else if (*data < 0xFD)
			{
				length += 2;
			}
			else if (*data == 0xFD)
			{
				length += 3;
			}
			else if (*data == 0xFE)
			{
				length += 5;
			}
			else if (*data == 0xFF)
			{
				length += 9;
			}
			break;
		}
	}
	return length;
}

int serialize_script(mem_zone_ref_ptr script_node, struct string *script)
{
	mem_zone_ref_ptr	key;
	mem_zone_ref		my_list = { PTR_NULL };
	size_t				length;
	unsigned char		*script_data;

	length = compute_script_size(script_node);
	script->len = length;
	script->size = length + 1;
	script->str = (char	*)calloc_c(script->size, 1);

	script_data = (unsigned char *)script->str;

	for (tree_manager_get_first_child(script_node, &my_list, &key); ((key != NULL) && (key->zone != NULL)); tree_manager_get_next_child(&my_list, &key))
	{
		unsigned char	*data;

		switch (tree_mamanger_get_node_type(key))
		{
		case NODE_BITCORE_VSTR:
			data = (unsigned char *)tree_mamanger_get_node_data_ptr(key, 0);
			if (*data < 0xFD)
			{
				*(script_data++) = *data;
				memcpy_c(script_data, &data[1], *data);
				script_data += (*data);
			}
			else if (*data == 0xFD)
			{
				*(script_data++) = 0xFD;
				(*((unsigned short *)(script_data))) = (*((unsigned short *)(data + 1)));
				script_data += 2;
				memcpy_c(script_data, &data[3], (*((unsigned short *)(data + 1))));
				script_data += (*((unsigned short *)(data + 1)));
			}
			else if (*data == 0xFE)
			{
				*(script_data++) = 0xFE;
				(*((unsigned int *)(script_data))) = (*((unsigned int *)(data + 1)));
				script_data += 4;
				memcpy_c(script_data, &data[5], (*((unsigned int *)(data + 1))));
				script_data += (*((unsigned int *)(data + 1)));
			}
			else if (*data == 0xFF)
			{
				*(script_data++) = 0xFF;
				(*((uint64_t *)(script_data))) = (*((uint64_t *)(data + 1)));
				script_data += 8;
				memcpy_c(script_data, &data[9], (*((uint64_t *)(data + 1))));
				script_data += (*((uint64_t *)(data + 1)));
			}
			break;
		case NODE_BITCORE_VINT:
			data = (unsigned char *)tree_mamanger_get_node_data_ptr(key, 0);
			if (*data == 0x00)
			{
				*(script_data++) = *data;
			}
			else if (*data < 0xFD)
			{
				*(script_data++) = 1;
				*(script_data++) = *data;
			}
			else if (*data == 0xFD)
			{
				*(script_data++) = 2;
				(*((unsigned short *)(script_data))) = (*((unsigned short *)(data + 1)));
				script_data += 2;
			}
			else if (*data == 0xFE)
			{
				*(script_data++) = 4;
				(*((unsigned int *)(script_data))) = (*((unsigned int *)(data + 1)));
				script_data += 4;
			}
			else if (*data == 0xFF)
			{
				*(script_data++) = 8;
				(*((uint64_t *)(script_data))) = (*((uint64_t *)(data + 1)));
				script_data += 8;
			}
			break;
		}
	}
	return 1;
}
void keyh_to_addr(unsigned char *pkeyh, btc_addr_t addr)
{
	hash_t			tmp_hash, fhash;
	unsigned char	hin[32];

	hin[0] = pubKeyPrefix;
	ripemd160(pkeyh, 32, &hin[1]);

	mbedtls_sha256(hin, 21, tmp_hash, 0);
	mbedtls_sha256(tmp_hash, 32, fhash, 0);
	memcpy_c(&hin[21], fhash, 4);
	base58(hin, addr);
}

void key_to_addr(unsigned char *pkey,btc_addr_t addr)
{
	hash_t			tmp_hash;
	mbedtls_sha256	(pkey, 33, tmp_hash, 0);
	keyh_to_addr	(tmp_hash, addr);
}


struct string get_next_script_var(const struct string *script,size_t *offset)
{
	struct string var = { PTR_NULL };
	unsigned char *p = (unsigned char *)(&script->str[*offset]);

	if ((*p) < 80)
	{
		var.len		= (*p);
		var.size	= var.len + 1;
		var.str		= malloc_c(var.size);
		memcpy_c(var.str, p + 1, var.len);
		var.str[var.len] = 0;
		(*offset) += var.len + 1;
	}
	else
		(*offset)++;

	return var;
}

int parse_sig_seq(struct string *sign_seq, struct string *sign, unsigned char *hashtype)
{
	unsigned char 	seq_len;
	size_t			slen, rlen;
	if (sign_seq->len < 69)return 0;

	if ((sign_seq->str[0] == 0x30) && (sign_seq->str[2] == 0x02))
	{
		unsigned char *s, *r,*sig;
		size_t last_r, last_s;
		int n;
		seq_len  = sign_seq->str[1];
		rlen	 = sign_seq->str[3];

		if ((4 + rlen+2)>= sign_seq->len)return 0;

		if (sign_seq->str[4 + rlen] == 2)
			slen = sign_seq->str[4 + rlen + 1];

		if (seq_len != (slen + rlen + 4))return 0;

		*hashtype = sign_seq->str[sign_seq->len - 1];
		
		if (rlen == 33)
		{
			last_r = 31;
			r = sign_seq->str + 4 + 1;
		}
		else
		{
			last_r = rlen-1;
			r		= sign_seq->str + 4;
		}
			

		if (slen == 33)
		{
			last_s	= 31;
			s		= sign_seq->str + 4 + rlen + 2 + 1;
		}
		else
		{
			last_s	= slen-1;
			s		= sign_seq->str + 4 + rlen + 2;
		}

		sign->len = 64;
		sign->size = sign->len + 1;
		sign->str = malloc_c(sign->size);
		sig = sign->str;

		n = 0;
		while (n <= last_r)
		{
			sig[(last_r - n)] = r[n];
			n++;
		}

		if (rlen < 32)
			memset_c(&sig[rlen], 0, 32 - rlen);

		n = 0;
		while (n <= last_s)
		{
			sig[(last_s - n)+32] = s[n];
			n++;
		}

		if (slen < 32)
			memset_c(&sig[slen+32], 0, 32 - slen);

		
		return 1;
	}
	return 0;

}

int get_insig_info(const struct string *script, struct string *sign, struct string *pubk, unsigned char *hash_type)
{
	struct string	sigseq = { PTR_NULL };
	size_t			offset = 0;
	int				ret = 0;
	sigseq = get_next_script_var(script, &offset);
	if (sigseq.str == PTR_NULL)return 0;
	if (sigseq.len < 69)
	{
		free_string(&sigseq);
		return 0;
	}
	ret		= parse_sig_seq			(&sigseq, sign, hash_type);
	(*pubk) = get_next_script_var	(script, &offset);
	
	free_string(&sigseq);
	return ret;
}
int check_sign(struct string *sign, struct string *pubK, hash_t txh)
{
	int ret=0;
	if (pubK->len == 33)
	{
		struct string ppk = { PTR_NULL };
		struct string msg = { PTR_NULL };
		unsigned char *mp,*p,*dp;
		int n = 32;
		
		msg.len = 32;
		msg.str = malloc_c(32);
		ppk.str = malloc_c(33);
		
		ppk.len = 33;
		p		= pubK->str;
		dp      = ppk.str;
		mp		= msg.str;
		
		dp[0] = p[0];
		while (n--)
		{
			mp[n]		= txh[31-n];
			dp[n + 1]	= p[(31 - n) + 1];
		}
		ret = crypto_sign_open(sign, &msg, &ppk);
		free_string(&msg);
		free_string(&ppk);
	}
	return ret;
}


OS_API_C_FUNC(int) get_in_script_address(struct string *script, btc_addr_t addr)
{
	unsigned char  *p;
	p = (unsigned char  *)script->str;

	if ((p[0] == 72) && (script->len == 73))
	{
		return 0;
	}
	else if ((p[0] == 72) && (p[73] == 33) && (script->len == 107))
	{
		char		pkey[33];
		memcpy_c		(pkey, &p[73], 33);
		key_to_addr		(pkey, addr);
		/*
		char		pkey[33];
		memcpy_c(pkey, &p[73], 33);
		mbedtls_sha256(script->str + 1, 33, tmp_hash, 0);

		hin[0] = pubKeyPrefix;
		ripemd160(tmp_hash, 32, &hin[1]);

		mbedtls_sha256(hin, 21, tmp_hash, 0);
		mbedtls_sha256(tmp_hash, 32, fhash, 0);

		memcpy_c(&hin[21], fhash, 4);
		base58(hin, addr);
		*/
		return 1;
	}

	return 0;
}

OS_API_C_FUNC(int) get_out_script_address(struct string *script, struct string *pubk, btc_addr_t addr)
{
	unsigned char  *p = (unsigned char  *)script->str;
	
	if ((p[0] == 33) && (p[34] == 0xAC))
	{
		if (pubk != PTR_NULL)
		{
			int n;
			pubk->len = 33;
			pubk->size = pubk->len + 1;
			pubk->str = malloc_c(pubk->size);
			memcpy_c(pubk->str, script->str+1, 33);

			/*
			pubk->str[0] = script->str[1];
			n = 32;
			while (n--)
			{
				*((unsigned char *)(pubk->str + 1+ n)) = *((unsigned char *)(script->str + 2 + (31 - n)));
			}
			pubk->str[pubk->len] = 0;
			*/
		}
		key_to_addr(script->str + 1, addr);
		/*
		char			pkey[33];
		mbedtls_sha256(script->str + 1, 33, tmp_hash, 0);
		hin[0] = pubKeyPrefix;
		ripemd160		(tmp_hash, 32,&hin[1]);
		
		mbedtls_sha256  (hin, 21, tmp_hash, 0);
		mbedtls_sha256  (tmp_hash, 32, fhash, 0);
				
		memcpy_c(&hin[21], fhash, 4);
		base58(hin, addr);
		*/
		return 1;
	}
	else if ((p[0] == 0x76) && (p[1] == 0xA9) && (p[24] == 0xAC))
	{
		keyh_to_addr(script->str + 3, addr);
		/*
		hash[0] = pubKeyPrefix;
		memcpy_c(&hash[1], script->str + 3, 20);

		mbedtls_sha256(hash, 21, tmp_hash, 0);
		mbedtls_sha256(tmp_hash, 32, fhash, 0);

		memcpy_c(hin, hash, 21);
		memcpy_c(&hin[21], fhash, 4);
		base58	(hin, addr);
		*/
		return 2;
	}
	return 0;
}
int check_txout_key(mem_zone_ref_ptr output, unsigned char *pkey)
{
	btc_addr_t inaddr;
	struct string oscript = { PTR_NULL };
	int ret;


	if (tree_manager_get_child_value_istr(output, NODE_HASH("script"), &oscript, 0))
	{
		btc_addr_t outaddr;
		if (pkey[0] != 0)
		{ 
			unsigned char ppk[33];
			int n = 32;
			

			key_to_addr(ppk, inaddr);
			get_out_script_address	(&oscript, PTR_NULL, outaddr);
			ret = (memcmp_c(outaddr, inaddr, sizeof(btc_addr_t)) == 0) ? 1 : 0;
		}
		free_string(&oscript);
		
	}
	return ret;
}