//copyright antoine bentue-ferrer 2016
#include <base/std_def.h>
#include <base/std_mem.h>
#include <base/mem_base.h>
#include <base/std_str.h>

#include <sha256.h>
#include <crypto.h>
#include <strs.h>
#include <tree.h>


#ifdef _DEBUG
	LIBEC_API int	C_API_FUNC			crypto_sign_open(const struct string *sign, struct string *msgh, struct string *pk);
#else
	extern	crypto_sign_open_func_ptr	crypto_sign_open;
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

static const unsigned char b58digits_map[] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, -1, -1, -1, -1, -1, -1,
	-1, 9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1,
	22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1,
	-1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46,
	47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1,
};

int b58tobin(void *bin, size_t *binszp, const char *b58, size_t b58sz)
{
	size_t binsz = *binszp;
	const unsigned char *b58u = (void*)b58;
	unsigned char *binu = bin;
	size_t outisz = (binsz + 3) / 4;
	unsigned long outi[256];
	uint64_t t;
	unsigned long c;
	size_t i, j;
	unsigned char bytesleft = binsz % 4;
	unsigned long zeromask = bytesleft ? (0xffffffff << (bytesleft * 8)) : 0;
	unsigned zerocount = 0;

	if (!b58sz)
		b58sz = strlen_c(b58);

	memset_c(outi, 0, outisz * sizeof(*outi));

	// Leading zeros, just count
	for (i = 0; i < b58sz && b58u[i] == '1'; ++i)
		++zerocount;

	for (; i < b58sz; ++i)
	{
		if (b58u[i] & 0x80)
			// High-bit set on invalid digit
			return 0;
		if (b58digits_map[b58u[i]] == -1)
			// Invalid base58 digit
			return 0;
		c = (unsigned)b58digits_map[b58u[i]];
		for (j = outisz; j--;)
		{
			t = ((uint64_t)outi[j]) * 58 + c;
			c = (t & 0x3f00000000) >> 32;
			outi[j] = t & 0xffffffff;
		}
		if (c)
			// Output number too big (carry to the next int32)
			return 0;
		if (outi[0] & zeromask)
			// Output number too big (last int32 filled too far)
			return 0;
	}

	j = 0;
	switch (bytesleft) {
	case 3:
		*(binu++) = (outi[0] & 0xff0000) >> 16;
	case 2:
		*(binu++) = (outi[0] & 0xff00) >> 8;
	case 1:
		*(binu++) = (outi[0] & 0xff);
		++j;
	default:
		break;
	}

	for (; j < outisz; ++j)
	{
		*(binu++) = (outi[j] >> 0x18) & 0xff;
		*(binu++) = (outi[j] >> 0x10) & 0xff;
		*(binu++) = (outi[j] >> 8) & 0xff;
		*(binu++) = (outi[j] >> 0) & 0xff;
	}

	// Count canonical base58 byte count
	binu = bin;
	for (i = 0; i < binsz; ++i)
	{
		if (binu[i])
			break;
		--*binszp;
	}
	*binszp += zerocount;

	return 1;
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
			case NODE_BITCORE_SCRIPT_OPCODE:
				length++;
			break;
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

OS_API_C_FUNC(int) serialize_script(mem_zone_ref_ptr script_node, struct string *script)
{
	mem_zone_ref_ptr	key;
	mem_zone_ref		my_list = { PTR_NULL };
	size_t				length;
	unsigned char		*script_data;

	length			= compute_script_size(script_node);
	script->len		= length;
	script->size	= length + 1;
	script->str		= (char	*)calloc_c(script->size, 1);

	script_data		= (unsigned char *)script->str;

	for (tree_manager_get_first_child(script_node, &my_list, &key); ((key != NULL) && (key->zone != NULL)); tree_manager_get_next_child(&my_list, &key))
	{
		unsigned char	*data;
		unsigned char	byte;

		switch (tree_mamanger_get_node_type(key))
		{
		case NODE_BITCORE_SCRIPT_OPCODE:
			tree_mamanger_get_node_byte(key, 0, &byte);
			*(script_data++) = byte;
		break;
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

	*script_data = 0;
	return 1;
}
void keyrh_to_addr(unsigned char *pkeyh, btc_addr_t addr)
{
	hash_t			tmp_hash, fhash;
	unsigned char	hin[32];

	hin[0] = pubKeyPrefix;
	memcpy_c		(&hin[1],pkeyh, 20);
	mbedtls_sha256	(hin, 21, tmp_hash, 0);
	mbedtls_sha256	(tmp_hash, 32, fhash, 0);
	memcpy_c		(&hin[21], fhash, 4);
	base58			(hin, addr);
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

OS_API_C_FUNC(void) key_to_hash(unsigned char *pkey, unsigned char *keyHash)
{
	hash_t			tmp_hash;
	mbedtls_sha256	(pkey, 33, tmp_hash, 0);
	ripemd160		(tmp_hash, 32, keyHash);
}

OS_API_C_FUNC(void) key_to_addr(unsigned char *pkey,btc_addr_t addr)
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


int add_script_var(mem_zone_ref_ptr script_node, const struct string *val)
{
	
	mem_zone_ref new_var = { PTR_NULL };
	int ret;
	if (!tree_manager_add_child_node(script_node, "var", NODE_BITCORE_VSTR, &new_var))return 0;
	ret=tree_manager_write_node_vstr(&new_var, 0, val);
	release_zone_ref(&new_var);
	return ret;
	
	
	
}

int add_script_opcode(mem_zone_ref_ptr script_node, unsigned char opcode)
{
	mem_zone_ref new_var = { PTR_NULL };
	int ret;
	if (!tree_manager_add_child_node(script_node, "op", NODE_BITCORE_SCRIPT_OPCODE, &new_var))return 0;
	ret = tree_manager_write_node_byte(&new_var, 0, opcode);
	release_zone_ref(&new_var);
	return ret;
}

OS_API_C_FUNC(int) parse_sig_seq(const struct string *sign_seq, struct string *sign, unsigned char *hashtype, int rev)
{
	unsigned char 	seq_len;
	size_t			slen, rlen;
	if (sign_seq->len < 69)return 0;

	if ((sign_seq->str[0] == 0x30) && (sign_seq->str[2] == 0x02))
	{
		unsigned char *s, *r,*sig;
		size_t last_r, last_s;
		unsigned int n;
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

		if (rev == 1)
		{
			n = 0;
			while (n <= last_r)
			{
				sig[(last_r - n)] = r[n];
				n++;
			}
		}
		else
		{
			memcpy_c(sig, r, rlen);
		}

		if (rlen < 32)
			memset_c(&sig[rlen], 0, 32 - rlen);

		if (rev == 1)
		{
			n = 0;
			while (n <= last_s)
			{
				sig[(last_s - n) + 32] = s[n];
				n++;
			}
		}
		else
		{
			memcpy_c(sig+32, s, slen);
		}

		if (slen < 32)
			memset_c(&sig[slen + 32], 0, 32 - slen);

		
		return 1;
	}
	return 0;

}

OS_API_C_FUNC(int) get_insig_info(const struct string *script, struct string *sign, struct string *pubk, unsigned char *hash_type)
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
	ret		= parse_sig_seq			(&sigseq, sign, hash_type,1);
	(*pubk) = get_next_script_var	(script, &offset);
	
	free_string(&sigseq);
	return ret;
}

int get_insig(const struct string *script, struct string *sign_seq, struct string *pubk)
{
	size_t offset = 0;
	(*sign_seq) = get_next_script_var(script, &offset);
	if (sign_seq->str == PTR_NULL)return 0;
	if (sign_seq->len < 69)
	{
		free_string(sign_seq);
		return 0;
	}
	(*pubk) = get_next_script_var(script, &offset);
	return 1;
}


int check_sign(const struct string *sign, const struct string *pubK, const hash_t txh)
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


OS_API_C_FUNC(int) get_out_script_address(struct string *script, struct string *pubk, btc_addr_t addr)
{
	unsigned char  *p = (unsigned char  *)script->str;
	
	if ((p[0] == 33) && (p[34] == 0xAC))
	{
		if (pubk != PTR_NULL)
		{
			pubk->len = 33;
			pubk->size = pubk->len + 1;
			pubk->str = malloc_c(pubk->size);
			memcpy_c(pubk->str, script->str+1, 33);
		}
		key_to_addr(script->str + 1, addr);
		return 1;
	}
	else if ((p[0] == 0x76) && (p[1] == 0xA9) && (p[24] == 0xAC))
	{
		keyrh_to_addr(script->str + 3, addr);
		return 2;
	}
	return 0;
}

OS_API_C_FUNC(int) create_payment_script(struct string *pubk, unsigned int type, mem_zone_ref_ptr script_node)
{
	if (type == 1)
	{
		char			keyHash[20];
		struct string  strKey;

		key_to_hash		 (pubk->str, keyHash);

		strKey.str  = keyHash;
		strKey.len  = 20;
		strKey.size = 20;

		add_script_opcode(script_node, 0x76);
		add_script_opcode(script_node, 0xA9);
		add_script_var	 (script_node, &strKey);
		add_script_opcode(script_node, 0xAC);
	}
	else
	{
		add_script_var	 (script_node, pubk);
		add_script_opcode(script_node, 0xAC);
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
			

			key_to_addr				(ppk, inaddr);
			get_out_script_address	(&oscript, PTR_NULL, outaddr);
			ret = (memcmp_c(outaddr, inaddr, sizeof(btc_addr_t)) == 0) ? 1 : 0;
		}
		free_string(&oscript);
		
	}
	return ret;
}