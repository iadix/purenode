
#include <base/std_def.h>
#include <base/std_mem.h>
#include <base/mem_base.h>
#include <base/std_str.h>

#include <sha256.h>
#include <strs.h>
#include <tree.h>

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
OS_API_C_FUNC(int) get_in_script_address(struct string *script, btc_addr_t addr)
{
	hash_t			tmp_hash, fhash;
	char			hash[21];
	unsigned char	hin[32];
	unsigned char  *p;
	p = (unsigned char  *)script->str;

	if ((p[0] == 72) && (script->len == 73))
	{
		return 0;
	}
	else if ((p[0] == 72) && (p[73] == 33) && (script->len == 107))
	{
		char		pkey[33];
		memcpy_c(pkey, &p[73], 33);
		mbedtls_sha256(script->str + 1, 33, tmp_hash, 0);

		hin[0] = pubKeyPrefix;
		ripemd160(tmp_hash, 32, &hin[1]);

		mbedtls_sha256(hin, 21, tmp_hash, 0);
		mbedtls_sha256(tmp_hash, 32, fhash, 0);

		memcpy_c(&hin[21], fhash, 4);
		base58(hin, addr);
		return 1;
	}

	return 0;
}

OS_API_C_FUNC(int) get_out_script_address(struct string *script, btc_addr_t addr)
{
	hash_t			tmp_hash, fhash;
	char			hash[21];
	unsigned char	hin[32];
	unsigned char  *p;
	p = (unsigned char  *)script->str;
	if ((p[0] == 33) && (p[34] == 0xAC))
	{
		char			pkey[33];
		mbedtls_sha256(script->str + 1, 33, tmp_hash, 0);

		hin[0] = pubKeyPrefix;
		ripemd160		(tmp_hash, 32,&hin[1]);
		
		mbedtls_sha256  (hin, 21, tmp_hash, 0);
		mbedtls_sha256  (tmp_hash, 32, fhash, 0);
				
		memcpy_c(&hin[21], fhash, 4);
		base58(hin, addr);
		
		return 1;
	}
	else if ((p[0] == 0x76) && (p[1] == 0xA9) && (p[24] == 0xAC))
	{
		hash[0] = pubKeyPrefix;
		memcpy_c(&hash[1], script->str + 3, 20);

		mbedtls_sha256(hash, 21, tmp_hash, 0);
		mbedtls_sha256(tmp_hash, 32, fhash, 0);

		memcpy_c(hin, hash, 21);
		memcpy_c(&hin[21], fhash, 4);
		base58	(hin, addr);
		return 2;
	}
	return 0;
}
