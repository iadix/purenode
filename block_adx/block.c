
#include <base/std_def.h>
#include <base/std_mem.h>
#include <base/mem_base.h>
#include <base/std_str.h>

#include <sha256.h>
#include <strs.h>
#include <tree.h>
#include <fsio.h>


C_IMPORT size_t			C_API_FUNC file_size(const char *path);
C_IMPORT int			C_API_FUNC append_file(const char *path, void *data, size_t data_len);
C_IMPORT int			C_API_FUNC stat_file(const char *path);
C_IMPORT int			C_API_FUNC create_dir(const char *path);
C_IMPORT int			C_API_FUNC put_file(const char *path, void *data, size_t data_len);
C_IMPORT int			C_API_FUNC get_sub_dirs(const char *path, struct string *dir_list);
C_IMPORT int			C_API_FUNC get_sub_files(const char *path, struct string *file_list);
C_IMPORT int			C_API_FUNC get_file(const char *path, unsigned char **data, size_t *data_len);
C_IMPORT int			C_API_FUNC get_hash_idx(const char *path, size_t idx, hash_t hash);

C_IMPORT size_t			C_API_FUNC	compute_payload_size(mem_zone_ref_ptr payload_node);
C_IMPORT char*			C_API_FUNC	write_node(mem_zone_ref_const_ptr key, unsigned char *payload);
C_IMPORT size_t			C_API_FUNC	get_node_size(mem_zone_ref_ptr key);
C_IMPORT void			C_API_FUNC	serialize_children(mem_zone_ref_ptr node, unsigned char *payload);
C_IMPORT const unsigned char*	C_API_FUNC read_node(mem_zone_ref_ptr key, const unsigned char *payload);
C_IMPORT size_t			C_API_FUNC init_node(mem_zone_ref_ptr key);


hash_t					null_hash		= { 0xCD };
const char				*null_hash_str	= "0000000000000000000000000000000000000000000000000000000000000000";
static unsigned char	pubKeyPrefix = 0xCD;


#define ONE_COIN		100000000ULL
#define ONE_CENT		1000000ULL

static const uint64_t one_coin		= ONE_COIN;

static const uint64_t block_reward = (100000ULL * ONE_COIN);


extern int			scrypt_blockhash	(const void* input, hash_t hash);


char* base58(unsigned char *s, char *out) {
	static const char *tmpl = "123456789"
		"ABCDEFGHJKLMNPQRSTUVWXYZ"
		"abcdefghijkmnopqrstuvwxyz";
	static char buf[40];

	int c, i, n;
	if (!out) out = buf;

	out[n = 34] = 0;
	while (n--) {
		for (c = i = 0; i < 25; i++) {
			c = c * 256 + s[i];
			s[i] = c / 58;
			c %= 58;
		}
		out[n] = tmpl[c];
	}

	for (n = 0; out[n] == '1'; n++);
	memmove_c(out, out + n, 34 - n);

	return out;
}


OS_API_C_FUNC(void) set_pubkeyprefix(unsigned char c){
	pubKeyPrefix = c;
}

OS_API_C_FUNC(unsigned int) SetCompact(unsigned int bits, hash_t out)
{
	unsigned int  nSize = bits >> 24;
	size_t		  ofset;

	memset_c(out, 0, 32);

	if (nSize < 32)
		ofset = 32 - nSize;

	if (nSize >= 1) out[0 + ofset] = (bits >> 16) & 0xff;
	if (nSize >= 2) out[1 + ofset] = (bits >> 8) & 0xff;
	if (nSize >= 3) out[2 + ofset] = (bits >> 0) & 0xff;

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
		case NODE_BITCORE_VSTR:
			data = (unsigned char	*)tree_mamanger_get_node_data_ptr(key, 0);
			if (*data < 0xFD)
				length += 1 + (*data);
			else if (*data == 0xFD)
			{
				length += 3 + (*((unsigned short *)(data + 1)));
			}
			else if (*data == 0xFE)
			{
				length += 5 + (*((unsigned int *)(data + 1)));
			}
			else if (*data == 0xFF)
			{
				length += 9 + (*((uint64_t *)(data + 1)));
			}
		break;
		case NODE_BITCORE_VINT:
			data = (unsigned char	*)tree_mamanger_get_node_data_ptr(key, 0);
			if (*data == 0x00)
			{
				length++;
			}
			else if (*data < 0xFD)
			{
				length	+=2;
			}
			else if (*data == 0xFD)
			{
				length  +=3;
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
	script->len	 = length;
	script->size = length + 1;
	script->str  = (char	*)calloc_c(script->size, 1);
	
	script_data  = (unsigned char *)script->str;

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

OS_API_C_FUNC(int) tx_add_input(mem_zone_ref_ptr tx, const hash_t tx_hash, unsigned int index, mem_zone_ref_ptr script_node)
{
	mem_zone_ref txin_list			= { PTR_NULL },txin = { PTR_NULL }, out_point = { PTR_NULL };
	struct string script			= { PTR_NULL };


	if (!tree_manager_create_node("txin", NODE_BITCORE_TXIN, &txin))return 0;
	
	serialize_script					(script_node, &script);
	
	tree_manager_set_child_value_hash	(&txin, "tx hash", tx_hash);
	tree_manager_set_child_value_i32	(&txin, "idx", index);

	tree_manager_set_child_value_vstr	(&txin, "script"	, &script);
	tree_manager_set_child_value_i32	(&txin, "sequence"	, 0xFFFFFFFF);
		
	tree_manager_find_child_node		(tx, NODE_HASH("txsin"), NODE_BITCORE_VINLIST, &txin_list);
	tree_manager_node_add_child			(&txin_list			, &txin);
	release_zone_ref					(&txin);
	release_zone_ref					(&txin_list);

	free_string							(&script);
	return 1;
}

OS_API_C_FUNC(int) tx_add_output(mem_zone_ref_ptr tx, uint64_t value, const struct string *script)
{
	mem_zone_ref						txout_list = { PTR_NULL },txout = { PTR_NULL };

	if (!tree_manager_find_child_node(tx, NODE_HASH("txsout"), NODE_BITCORE_VOUTLIST, &txout_list))return 0;

	tree_manager_create_node			("txout", NODE_BITCORE_TXOUT, &txout);
	tree_manager_set_child_value_i64	(&txout, "value", value);
	tree_manager_set_child_value_vstr	(&txout, "script", script);
	tree_manager_node_add_child			(&txout_list, &txout);
	release_zone_ref					(&txout);
	release_zone_ref					(&txout_list);
	return 1;
}

OS_API_C_FUNC(int) new_transaction(mem_zone_ref_ptr tx, ctime_t time)
{
	tree_manager_create_node		("transaction"	, NODE_BITCORE_TX, tx);
	tree_manager_set_child_value_i32(tx, "version"	, 1);
	tree_manager_set_child_value_i32(tx, "time"		, time);
	tree_manager_add_child_node		(tx, "txsin"	, NODE_BITCORE_VINLIST , PTR_NULL);
	tree_manager_add_child_node		(tx, "txsout"	, NODE_BITCORE_VOUTLIST, PTR_NULL);
	tree_manager_set_child_value_i32(tx, "locktime"	, 0);
	return 1;
}

OS_API_C_FUNC(int) compute_tx_hash(mem_zone_ref_ptr tx, hash_t hash)
{
	hash_t		  tx_hash;
	size_t		  length;
	unsigned char *buffer;

	length = get_node_size(tx);
	buffer = (unsigned char *)malloc_c(length);
	serialize_children(tx, buffer);
	mbedtls_sha256(buffer, length, tx_hash, 0);
	mbedtls_sha256(tx_hash, 32, hash, 0);
	free_c(buffer);
	return 1;
}
OS_API_C_FUNC(int) compute_block_pow(mem_zone_ref_ptr block, hash_t hash)
{
	size_t		  length;
	unsigned char *buffer;

	length = get_node_size(block);
	buffer = malloc_c(length);
	write_node(block, buffer);

	scrypt_blockhash(buffer, hash);
	free_c(buffer);
	return 1;
}

OS_API_C_FUNC(int) compute_block_hash(mem_zone_ref_ptr block, hash_t hash)
{
	unsigned int			checksum1[8];
	size_t					length;
	unsigned char			*buffer;

	length = get_node_size(block);
	buffer = malloc_c(length);
	write_node	(block, buffer);

	mbedtls_sha256(buffer, 80, (unsigned char*)checksum1, 0);
	mbedtls_sha256((unsigned char*)checksum1, 32, hash, 0);
	free_c(buffer);

	return 1;
}

int build_merkel_tree(mem_zone_ref_ptr txs, hash_t merkleRoot)
{
	mem_zone_ref tx = { PTR_NULL };
	int				n;
	n = tree_manager_get_node_num_children(txs);
	if (n == 1)
	{
		tree_manager_get_child_at			(txs, 0, &tx);
		compute_tx_hash						(&tx, merkleRoot);
		tree_manager_set_child_value_hash	(&tx, "tx hash", merkleRoot);
		release_zone_ref					(&tx);
		return 1;
	}
	if (n == 2)
	{
		hash_t tx_hash;
		if (tree_manager_get_child_at(txs, 0, &tx))
		{
			compute_tx_hash(&tx, tx_hash);
			tree_manager_set_child_value_hash(&tx, "tx hash", tx_hash);
		}
		release_zone_ref(&tx);

		if (tree_manager_get_child_at(txs, 1, &tx))
		{
			compute_tx_hash(&tx, tx_hash);
			tree_manager_set_child_value_hash(&tx, "tx hash", tx_hash);
		}

		release_zone_ref(&tx);
		return 1;
	}
	return 1;
}

OS_API_C_FUNC(int) find_hash(hash_t hash)
{
	char				file_name[65];
	struct string		blk_path = { PTR_NULL };
	unsigned int		n;
	int					ret;

	n = 32;
	while (n--)
	{
		file_name[n * 2 + 0] = hex_chars[hash[n] >> 4];
		file_name[n * 2 + 1] = hex_chars[hash[n] & 0x0F];
	}
	file_name[64] = 0;


	make_string(&blk_path, "./blks/");
	cat_ncstring(&blk_path, file_name+0,2);
	cat_cstring(&blk_path, "/");
	cat_ncstring(&blk_path, file_name+2,2);
	cat_cstring(&blk_path, "/");
	cat_cstring(&blk_path, file_name);

	ret = (stat_file(blk_path.str)==0)?1:0;

	free_string(&blk_path);
	return ret;
}


void scale_compact(unsigned int nBits, uint64_t mop, uint64_t dop, hash_t hash)
{
	hash_t		tmp = { 0 };
	unsigned int size;
	uint64_t	data;
	int			n;

	size = (nBits >> 24) - 3;
	data = muldiv64(nBits & 0xFFFFFF, mop, dop);
	n = 0;
	while (((size + n)<32) && (data >0))
	{
		tmp[size + n] = data & 0xFF;
		data >>= 8;
		n++;
	}
	n = 32;
	while (n--)
	{
		hash[n] = tmp[31 - n];
	}
}

OS_API_C_FUNC(void) mul_compact(unsigned int nBits, uint64_t op, hash_t hash)
{
	unsigned int size;
	uint64_t	data, d;
	int			n;

	size = (nBits >> 24)-3;
	
	/*
	while ((op & 0xFF) == 0)
	{
		op >>= 8;
		size++;
	}*/
	
	d		= (nBits & 0xFFFFFF);
	data	= mul64(d , op);

	n = 0;
	while ((n<8) && ((size+n)<32))
	{
		hash[size + n] = data&0xFF;
		data >>= 8;
		n++;
	}

}

OS_API_C_FUNC(int) cmp_hashle(hash_t hash1, hash_t hash2)
{
	int n = 32;
	while (n--)
	{
		if (hash1[n] < hash2[n])
			return 1;
		if (hash1[n] > hash2[n])
			return -1;
	}
	return 1;
}

OS_API_C_FUNC(int) check_diff(unsigned int nActualSpacing, unsigned int TargetSpacing, unsigned int nTargetTimespan, hash_t limit, unsigned int pBits, unsigned int nBits)
{
	hash_t				diff_hash, odhash;
	unsigned int		nInterval;
	unsigned int		quotient, dividend;

	SetCompact(nBits, diff_hash);

	if (!memcmp_c(diff_hash, limit, sizeof(hash_t)))
		return 1;
	
	nInterval = nTargetTimespan / TargetSpacing;
	quotient  = ((nInterval - 1) * TargetSpacing + nActualSpacing + nActualSpacing);
	dividend  = ((nInterval + 1) * TargetSpacing);
	scale_compact(pBits, quotient, dividend, odhash);
	
	if (cmp_hashle(odhash,diff_hash))
		return 1;

	return 0;
}

OS_API_C_FUNC(int) load_blk_hdr(mem_zone_ref_ptr hdr, const char *blk_hash)
{
	unsigned char		*hdr_data;
	size_t				hdr_data_len;
	struct string		blk_path = { PTR_NULL };
	int    ret=0;
	
	make_string (&blk_path, "./blks/");
	cat_ncstring(&blk_path, blk_hash,2);
	cat_cstring (&blk_path, "/");
	cat_ncstring(&blk_path, blk_hash+2, 2);
	cat_cstring (&blk_path, "/");
	cat_cstring (&blk_path, blk_hash);
	cat_cstring (&blk_path,  "/header");

	if (get_file(blk_path.str, &hdr_data, &hdr_data_len) > 0)
	{
		if ((hdr->zone!=PTR_NULL)||(tree_manager_create_node("blk", NODE_BITCORE_BLK_HDR, hdr)))
		{
			hash_t hash;
			int		n=32;

			init_node(hdr);
			read_node(hdr, hdr_data);
			while (n--)
			{
				char    hex[3];
				hex[0]  = blk_hash[n * 2 + 0];
				hex[1]  = blk_hash[n * 2 + 1];
				hex[2]  = 0;
				hash[n] = strtoul_c(hex, PTR_NULL, 16);
			}
			tree_manager_set_child_value_bhash(hdr, "blk hash", hash);
			ret=1;
		}
		free_c(hdr_data);
	}
	free_string(&blk_path);

	return ret;
}
OS_API_C_FUNC(int) get_tx_input(mem_zone_ref_const_ptr tx, unsigned int idx, mem_zone_ref_ptr vout)
{
	int ret;
	mem_zone_ref txin_list = { PTR_NULL };

	if (!tree_manager_find_child_node(tx, NODE_HASH("txsin"), NODE_BITCORE_VINLIST, &txin_list))return 0;
	ret = tree_manager_get_child_at(&txin_list, idx, vout);
	release_zone_ref(&txin_list);
	return ret;

}


OS_API_C_FUNC(int) load_tx(mem_zone_ref_ptr tx, const char *tx_hash)
{
	
	unsigned char		*tx_data;
	size_t				tx_data_len;
	struct string		tx_path = { 0 };
	int    ret=0;

	make_string(&tx_path, "./txs/");
	cat_ncstring(&tx_path, tx_hash + 0, 2);
	cat_cstring(&tx_path, "/");
	cat_ncstring(&tx_path, tx_hash + 2, 2);
	cat_cstring(&tx_path, "/");
	cat_cstring(&tx_path, tx_hash);
	cat_cstring(&tx_path, "/data");

	if (get_file(tx_path.str, &tx_data, &tx_data_len) > 0)
	{
		if ((tx->zone!=PTR_NULL)||(tree_manager_create_node("tx", NODE_BITCORE_TX, tx)))
		{
			init_node(tx);
			read_node(tx, tx_data);
			ret=1;
		}
		free_c(tx_data);
	}
	free_string(&tx_path);

	return ret;
}
OS_API_C_FUNC(int) load_tx_input(mem_zone_ref_const_ptr tx, unsigned int idx, mem_zone_ref_ptr	vin , mem_zone_ref_ptr tx_out)
{
	char			prev_hash[65];
	int				ret;

	if (!get_tx_input(tx, idx, vin))return 0;

	tree_manager_get_child_value_str(vin, NODE_HASH("tx hash"), prev_hash, 65, 16);
	ret = load_tx(tx_out, prev_hash);

	/*
	ret = tree_manager_find_child_node(vin, NODE_HASH("prev tx"), NODE_BITCORE_TX, tx_out);
	if (!ret)
	{
		if(tree_manager_add_child_node(vin, "prev tx", NODE_BITCORE_TX, tx_out))
			ret=load_tx(tx_out, prev_hash);
	}
	*/
	return ret;

}
OS_API_C_FUNC(int) load_blk_txs(mem_zone_ref_ptr txs, const char *blk_hash)
{
	unsigned char		*tx_hash_list;
	size_t				tx_hash_list_len;
	struct string		blk_path = { PTR_NULL };
	int    ret = 0;
	
	make_string(&blk_path, "./blks/");
	cat_ncstring(&blk_path, blk_hash,2);
	cat_cstring(&blk_path, "/");
	cat_ncstring(&blk_path, blk_hash+2, 2);
	cat_cstring(&blk_path, "/");
	cat_cstring(&blk_path, blk_hash);
	cat_cstring(&blk_path, "/txs");

	if (get_file(blk_path.str, &tx_hash_list, &tx_hash_list_len) > 0)
	{
		if (tree_manager_create_node("txs", NODE_BITCORE_TX_LIST, txs))
		{
			while (tx_hash_list_len > 0)
			{
				mem_zone_ref	tx = { PTR_NULL };
				char			chash[65];
				unsigned int	n = 32;

				while (n--)
				{
					chash[n * 2 + 0] = hex_chars[tx_hash_list[n] >> 4];
					chash[n * 2 + 1] = hex_chars[tx_hash_list[n] & 0x0F];
				}

				load_tx(&tx, chash);
				tx_hash_list += 32;
				tx_hash_list_len -= 32;
			}
		}
		free_c(tx_hash_list);
	}
	free_string(&blk_path);

	return ret;
}


int is_coinbase(mem_zone_ref_const_ptr tx)
{
	hash_t prev_hash;
	mem_zone_ref txin_list = { PTR_NULL }, input = { PTR_NULL };
	unsigned int oidx;
	int ret;

	if (!tree_manager_find_child_node(tx, NODE_HASH("txsin"), NODE_BITCORE_VINLIST, &txin_list))return 0;
	ret = tree_manager_get_child_at(&txin_list, 0, &input);
	release_zone_ref(&txin_list);
	if (!ret)return 0;

	ret = tree_manager_get_child_value_hash(&input, NODE_HASH("tx hash"), prev_hash);
	if (ret)ret = tree_manager_get_child_value_i32(&input, NODE_HASH("idx"), &oidx);
	release_zone_ref(&input);
	if (!ret)return 0;
	if ((!memcmp_c(prev_hash, null_hash, 32)) && (oidx >= 0xFFFF))
		return 1;

	return 0;


}


OS_API_C_FUNC(int) store_tx_inputs(mem_zone_ref_ptr tx,const char *tx_hash,uint64_t *total)
{
	unsigned int	oidx;
	char			spend_path[256];
	struct string	dir_list={0};
	mem_zone_ref	txin_list = { PTR_NULL }, my_list = { PTR_NULL };
	const char		*optr;
	mem_zone_ref_ptr input = PTR_NULL;
	unsigned int	n,cur;

	
	if (!tree_manager_find_child_node(tx, NODE_HASH("txsin"), NODE_BITCORE_VINLIST, &txin_list))return 0;

	n = get_sub_dirs("./adrs/", &dir_list);
	
	for (tree_manager_get_first_child(&txin_list, &my_list, &input); ((input != NULL) && (input->zone != NULL)); tree_manager_get_next_child(&my_list, &input))
	{
		char			prev_hash[65] = { 0 };
		struct string	out_path = {0};
		char			coidx[16];
		int				sret;
		tree_manager_get_child_value_str	(input, NODE_HASH("tx hash"), prev_hash,65,16);
		tree_manager_get_child_value_i32	(input, NODE_HASH("idx")	, &oidx);
		
		if (!strcmp_c(prev_hash, null_hash_str))continue;
		
		make_string (&out_path, "./txs/");
		cat_ncstring(&out_path, prev_hash + 62, 2);
		cat_cstring (&out_path, "/");
		cat_ncstring(&out_path, prev_hash + 60, 2);
		cat_cstring (&out_path, "/");
		cat_cstring (&out_path, prev_hash);
		cat_cstring (&out_path, "/out_");
		strcat_int  (&out_path, oidx);

		sret = stat_file(out_path.str);
		if (sret == 0)
			del_file(out_path.str);
		free_string(&out_path);

		uitoa_s		(oidx, coidx, 8, 10);
		optr = dir_list.str;
		cur = 0;
		while (cur<n)
		{
			char			new_path[256];
			char			*ptr;
			size_t			sz;

			ptr =	(char*)memchr_c(optr, 10, dir_list.len);
			sz	=	mem_sub(optr, ptr);
				
			strcpy_cs(spend_path,256,"./adrs/");
			strncat_c(spend_path,optr,sz);

			strcpy_cs(new_path, 256, spend_path);
			
			strcat_cs(spend_path,256,"/unspent/");
			strcat_cs(spend_path,256,prev_hash);
			strcat_cs(spend_path,256,"_");
			strcat_cs(spend_path,256,coidx);

			if(stat_file(spend_path)!=0)
			{
				strcat_cs(new_path,256,"/spent/");
				strcat_cs(new_path, 256, prev_hash);
				strcat_cs(new_path,256 ,"_");
				strcat_cs(new_path,256 ,coidx);
				move_file(spend_path,new_path);
			}
			cur++;
			optr = ptr + 1;
		}
	}
	free_string(&dir_list);
	release_zone_ref(&txin_list);
	return 1;
}

OS_API_C_FUNC(int) store_tx_output(mem_zone_ref_ptr tx, const char * tx_hash,uint64_t *total)
{
	
	hash_t				hash;
	struct string		script={0},tx_path={0};
	mem_zone_ref		txout_list = { PTR_NULL }, my_list = { PTR_NULL };
	mem_zone_ref_ptr	out = PTR_NULL;
	unsigned int		oidx;
	
	if (!tree_manager_find_child_node(tx, NODE_HASH("txsout"), NODE_BITCORE_VOUTLIST, &txout_list))return 0;
	

	
	make_string (&tx_path, "./txs/");
	cat_ncstring(&tx_path, tx_hash+0	,2);
	cat_cstring (&tx_path, "/");
	cat_ncstring(&tx_path, tx_hash+2	,2);
	cat_cstring (&tx_path, "/");
	cat_cstring (&tx_path, tx_hash);

	for (oidx = 0,tree_manager_get_first_child(&txout_list, &my_list, &out); ((out != NULL) && (out->zone != NULL)); oidx++, tree_manager_get_next_child(&my_list, &out))
	{
		struct string	out_path = {0};
		uint64_t		amount	=	0;
		unsigned char  *p;
		if(!tree_manager_get_child_value_i64(out,NODE_HASH("value"),&amount))continue;

		clone_string(&out_path,&tx_path);
		cat_cstring (&out_path, "/out_");
		strcat_int	(&out_path,oidx);
		put_file	(out_path.str,&amount,8);
		free_string (&out_path);
		//"87158FF77BB2335F566E21332505B2CFFD2EC992E201368E919A8BF903E7A9DD"

		if (!tree_manager_get_child_value_istr(out, NODE_HASH("script"), &script, 16))continue;
		if (script.len == 0){ free_string(&script); continue; }
		p = (unsigned char  *)script.str;
		if ((p[0] == 33) && (p[34] == 0xAC))
		{
			/*
			int n;
			printf("tx "%llu out sig to\n", amount);
			memcpy_c(hash, script.str + 1, 32);
			for (n = 0; n < 32; n++)
			{
				printf("%02x", hash[31 - n]);
			}
			printf("\n");
			*/
		}
		else if ((p[0] == 0x76) && (p[1] == 0xA9) && (p[24] == 0xAC))
		{
			char			path[256];
			unsigned char	hin[32];
			hash_t			tmp_hash, fhash;

			strcpy_cs(path, 256, "./adrs/");

			hash[0]		= pubKeyPrefix;
			memcpy_c	(&hash[1], script.str + 3, 20);

			mbedtls_sha256(hash, 21, tmp_hash, 0);
			mbedtls_sha256(tmp_hash, 32, fhash, 0);

			memcpy_c	(hin, hash, 21);
			memcpy_c	(&hin[21], fhash, 4);
			base58		(hin, &path[7]);
			path[41] = 0;
			path[42] = 0;

			if(is_coinbase(tx))
				create_dir	(path);
						
			if (stat_file(path)==0)
			{
				int n = 32;
				char cidx[8] = { 0 };
				uitoa_s		(oidx, cidx, 4, 10);
				
				strcat_cs	(path, 256, "/unspent/");
				create_dir	(path);
				strcat_cs	(path, 256, tx_hash);
				strcat_cs	(path, 256, "_");
				strcat_cs	(path, 256, cidx);
				put_file	(path,&amount,8);
			}
		}
		free_string(&script);
	}
	free_string		(&tx_path);
	release_zone_ref(&txout_list);
	return 1;
}

OS_API_C_FUNC(int) get_tx_output(mem_zone_ref_const_ptr tx, unsigned int idx, mem_zone_ref_ptr vout)
{
	int ret;
	mem_zone_ref txout_list={PTR_NULL};

	if (!tree_manager_find_child_node(tx, NODE_HASH("txsout"), NODE_BITCORE_VOUTLIST, &txout_list))return 0;
	ret = tree_manager_get_child_at(&txout_list,idx,vout);
	release_zone_ref(&txout_list);
	return ret;

}



OS_API_C_FUNC(int) get_tx_output_amount(const char *tx_hash, unsigned int idx, uint64_t *amount)
{
	mem_zone_ref	tx = { PTR_NULL }, vout={PTR_NULL};
	int				ret;

	if (!load_tx(&tx, tx_hash))return 0;
	ret=get_tx_output	(&tx,idx,&vout);
	if (ret)
	{
		ret = tree_manager_get_child_value_i64(&vout, NODE_HASH("value"), amount);
		release_zone_ref(&vout);
	}
	release_zone_ref	(&tx);
	return ret;
}


OS_API_C_FUNC(int) check_tx_outputs(mem_zone_ref_ptr tx, uint64_t *total, unsigned int coinstake, unsigned int *is_staking)
{
	mem_zone_ref		txout_list = { PTR_NULL }, my_list = { PTR_NULL };
	mem_zone_ref_ptr	out = PTR_NULL;
	unsigned int		idx;
	unsigned int		seenstake;
	int ret;

	*is_staking = 0;

	if (!tree_manager_find_child_node(tx, NODE_HASH("txsout"), NODE_BITCORE_VOUTLIST, &txout_list))return 0;

	seenstake = 0;
	ret = 1;

	for (idx = 0, tree_manager_get_first_child(&txout_list, &my_list, &out); ((out != NULL) && (out->zone != NULL)); idx++,tree_manager_get_next_child(&my_list, &out))
	{
		uint64_t		amount=0;
		if (!tree_manager_get_child_value_i64(out, NODE_HASH("value"), &amount))continue;
		if ((coinstake == 1) && (idx == 0) && (amount == 0))
		{
			struct string script = { 0 };
			ret = tree_manager_get_child_value_istr(out, NODE_HASH("script"), &script, 16);
			if (ret)
			{
				unsigned int is_null;
				is_null = (script.str[0] == 0) ? 1 : 0;
				free_string(&script);
				if (is_null)
				{
					if (seenstake)
					{
						release_zone_ref(&my_list);
						ret = 0;
						break;
					}
					seenstake = 1;
					*is_staking = 1;
				}
			}
		}
		else
		{
			*total += amount;
		}
	}
	release_zone_ref(&txout_list);
	return ret;
}


OS_API_C_FUNC(int) is_vout_null(mem_zone_ref_const_ptr tx, unsigned int idx)
{
	uint64_t		amount;
	struct string	script = { PTR_NULL };
	mem_zone_ref vout = { PTR_NULL };
	int			ret;
	if (!get_tx_output(tx, idx, &vout))return 0;

	ret = tree_manager_get_child_value_i64(&vout, NODE_HASH("value"), &amount);
	if ((ret) && (amount > 0))
		ret = 0;

	if (ret)
		ret = tree_manager_get_child_value_istr(&vout, NODE_HASH("script"), &script, 0);

	if ((ret) && (script.str[0]!=0))
		ret = 0;

	free_string(&script);
	release_zone_ref(&vout);

	return ret;
}


OS_API_C_FUNC(int) is_tx_null(mem_zone_ref_const_ptr tx)
{
	struct string	script={0};
	mem_zone_ref	vout = {PTR_NULL};
	uint64_t		amount;
	int				ret;

	ret	= get_tx_output	(tx,0,&vout);
	if(!ret)return -1;

	ret = tree_manager_get_child_value_i64(&vout,NODE_HASH("value"),&amount);
	if (ret)ret = tree_manager_get_child_value_istr(&vout, NODE_HASH("script"), &script,0);
	release_zone_ref(&vout);
	if(!ret)return -1;
	if((amount==0)&&(script.str[0]==0))
		ret=1;
	else
		ret=0;

	free_string(&script);
	return ret;
}
OS_API_C_FUNC(int) hash_equal(hash_t hash, const char *shash)
{
	int n = 0;
	while (n < 32)
	{
		char hex[3] = { shash[n * 2], shash[n * 2 + 1], 0 };
		unsigned char uc;
		uc = strtoul_c(hex, PTR_NULL, 16);
		if (hash[31-n] != uc)
			return 0;

		n++;
	}

	return 1;
	
}
OS_API_C_FUNC(int) check_block_hdr(mem_zone_ref_ptr hdr)
{
	hash_t	blk_hash, prev_hash;

	tree_manager_get_child_value_hash(hdr, NODE_HASH("prev"), prev_hash);
	if (!find_hash(prev_hash))return 0;

	if (!tree_manager_get_child_value_hash(hdr, NODE_HASH("blk hash"), blk_hash))
	{
		compute_block_hash(hdr, blk_hash);
		tree_manager_set_child_value_bhash(hdr, "blk hash", blk_hash);
	}
	if (find_hash(blk_hash))
		return 0;

	return 1;
}


OS_API_C_FUNC(int) get_hash_list(mem_zone_ref_ptr hdr_list, mem_zone_ref_ptr hash_list)
{
	mem_zone_ref		my_list = { PTR_NULL };
	mem_zone_ref_ptr	hdr;
	int					n = 0;

	tree_manager_create_node("hash list", NODE_BITCORE_HASH_LIST, hash_list);

	for (n = 0, tree_manager_get_first_child(hdr_list, &my_list, &hdr); ((hdr != NULL) && (hdr->zone != NULL)); n++, tree_manager_get_next_child(&my_list, &hdr))
	{
		hash_t blk_hash;
		char	idx[32] = { 0 };

		itoa_s(n, idx, 32, 16);
		tree_manager_get_child_value_hash(hdr, NODE_HASH("blk hash"), blk_hash);
		tree_manager_set_child_value_bhash(hash_list, idx, blk_hash);


	}
	return n;
}

OS_API_C_FUNC(int) load_block_indexes(mem_zone_ref_ptr hdr_list)
{
	char			idx[16];
	unsigned int	n;

	unsigned char	*data;
	size_t			data_len;

	if (!get_file("./blk_indexes", &data, &data_len))return 0;

	n = (data_len > (32 * 1000)) ? (data_len - 32 * 1000) : 0;
	while (n < data_len)
	{
		mem_zone_ref list = { PTR_NULL }, header = { PTR_NULL };

		memset_c(idx, 0, 16);
		uitoa_s(n / 32, idx, 16, 16);

		if (!tree_manager_add_child_node(hdr_list, idx, NODE_BITCORE_BLK_HDR, &header))
		{
			//printf("error import %d block \n",n);
			break;
		}
		tree_manager_set_child_value_bhash(&header, "blk hash", data + n);
		release_zone_ref(&header);

		n += 32;
	}
	free_c(data);
	return 1;
}

OS_API_C_FUNC(int) last_block_locator_index(mem_zone_ref_ptr node, mem_zone_ref_ptr hash_list)
{
	hash_t hash;
	mem_zone_ref hash_node = { PTR_NULL };
	size_t nc;

	if (!tree_manager_create_node("locator", NODE_BITCORE_LOCATOR, hash_list))return 0;
	nc = file_size("./blk_indexes") / 32;
	get_hash_idx("./blk_indexes", nc - 1, hash);

	tree_manager_add_child_node(hash_list, "hash", NODE_BITCORE_HASH, &hash_node);
	tree_manager_write_node_hash(&hash_node, 0, hash);
	release_zone_ref(&hash_node);

	return 1;
}

OS_API_C_FUNC(int) block_locator_indexes(mem_zone_ref_ptr node, size_t top_height, mem_zone_ref_ptr hash_list)
{
	hash_t hash;
	mem_zone_ref n = { PTR_NULL };
	mem_zone_ref hash_node = { PTR_NULL };
	int64_t index;
	int64_t cnt = 0;
	// Modify the step in the iteration.
	int64_t step = 1;
	int	cn = 0;

	if (!tree_manager_create_node("locator", NODE_BITCORE_LOCATOR, hash_list))return 0;
	// Start at the top of the chain and work backwards.
	for (cn = 0, index = (int64_t)top_height; index > 0; cn++, index -= step)
	{
		char idx[32];
		if (!get_hash_idx("./blk_indexes", index, hash))continue;

		strcpy_c(idx, "hash_");
		uitoa_s(cn, &idx[5], 27, 10);


		tree_manager_add_child_node(hash_list, idx, NODE_BITCORE_HASH, &hash_node);
		tree_manager_write_node_hash(&hash_node, 0, hash);
		release_zone_ref(&hash_node);

		// Push top 10 indexes first, then back off exponentially.
		cnt++;
		if (cnt == 10)
		{
			step *= 2;
			cnt = 0;
		}
	}

	log_message("block locator:\n%hash_0%\n%hash_1%\n", hash_list);
	//  Push the genesis block index.
	if (get_hash_idx("./blk_indexes", 0, hash))
	{
		tree_manager_add_child_node(hash_list, "hash", NODE_BITCORE_HASH, &hash_node);
		tree_manager_write_node_hash(&hash_node, 0, hash);
		release_zone_ref(&hash_node);
	}
	return 1;
}



OS_API_C_FUNC(int) check_tx_list(mem_zone_ref_ptr tx_list,uint64_t staking_reward)
{
	hash_t				merkleRoot;
	mem_zone_ref		my_list = { PTR_NULL };
	mem_zone_ref_ptr	tx = PTR_NULL;
	unsigned int		list_reward;
	int					ret;
	unsigned int		coinbase, coinstaking, is_staking;
	uint64_t			txFee, fees;
	
	build_merkel_tree				(tx_list, merkleRoot);
	tree_manager_get_first_child	(tx_list, &my_list, &tx);

	if (staking_reward == 0)
	{
		coinbase	= 1;
		coinstaking = 0;
	}
	else
	{
		tree_manager_get_next_child(&my_list, &tx);
		coinbase		= 0;
		coinstaking		= 1;
	}

	list_reward = 0;
	fees = 0;

	ret = 1;
	for (; ((tx != PTR_NULL) && (tx->zone != PTR_NULL)); tree_manager_get_next_child(&my_list, &tx))
	{
		struct string		tx_path = { 0 };
		uint64_t			total_in, total_out;
		mem_zone_ref		txin_list = { PTR_NULL }, my_llist = { PTR_NULL };
		mem_zone_ref_ptr	input = PTR_NULL;

		if (!tree_manager_find_child_node(tx, NODE_HASH("txsin"), NODE_BITCORE_VINLIST, &txin_list))
		{ 
			release_zone_ref(&my_list); 
			return 0; 
		}
		total_in = 0;

		for (tree_manager_get_first_child(&txin_list, &my_llist, &input); ((input != PTR_NULL) && (input->zone != PTR_NULL)); tree_manager_get_next_child(&my_llist, &input))
		{
			char				cphash[65] = { 0 };
			hash_t				prev_hash = { 0 };
			uint64_t			amount = 0;
			unsigned int		oidx = 0;
			int					n = 0;
			
			tree_manager_get_child_value_hash(input, NODE_HASH("tx hash"), prev_hash);
			tree_manager_get_child_value_i32(input, NODE_HASH("idx"), &oidx);

			
			if ((!memcmp_c(prev_hash, null_hash, 32)) && (oidx >= 0xFFFF))
			{
				if ((coinstaking==0)&&(coinbase != 0))
				{
					total_in += block_reward;
					coinbase = 0;
					continue;
				}
				release_zone_ref(&my_list); 
				release_zone_ref(&my_llist); 
				return 0;
			}
			else
			{
				mem_zone_ref		prevout = { PTR_NULL }, prev_tx = { PTR_NULL };
				struct string		script = { 0 }, oscript = { 0 };
				unsigned char		sig[72];
				unsigned char		pubK[33];
				unsigned char		*cscript;
				

				n = 0;
				while (n<32)
				{
					cphash[n * 2 + 0] = hex_chars[prev_hash[n] >> 0x04];
					cphash[n * 2 + 1] = hex_chars[prev_hash[n] & 0x0F];
					n++;
				}
				cphash[64] = 0;

				tree_manager_get_child_value_istr(input, NODE_HASH("script"), &script, 0);
				cscript = (unsigned char *)script.str;
				if ((cscript[0] == 72) && (cscript[73] == 33) && (script.len == 107))
				{
					memcpy_c(sig, &cscript[1], 72);
					memcpy_c(pubK, &cscript[73], 33);
				}
				free_string(&script);
				
				if (!tree_manager_find_child_node(input, NODE_HASH("prev tx"), NODE_BITCORE_TX, &prev_tx))
					load_tx(&prev_tx, cphash);

				if (get_tx_output(&prev_tx, oidx, &prevout))
				{
					if (tree_manager_get_child_value_istr(&prevout, NODE_HASH("script"), &oscript, 0))
					{
						/*
						bool Verify(const uint256 &hash, const std::vector<unsigned char>& vchSig) {
						// -1 = error, 0 = bad sig, 1 = good
						if (ECDSA_verify(0, (unsigned char*)&hash, sizeof(hash), &vchSig[0], vchSig.size(), pkey) != 1)
						return false;
						return true;
						}
						*/
						free_string(&oscript);
					}
					release_zone_ref(&prevout);
				}
				release_zone_ref(&prev_tx);
			}

			make_string(&tx_path, "./txs/");
			cat_ncstring(&tx_path, cphash + 0, 2);
			cat_cstring(&tx_path, "/");
			cat_ncstring(&tx_path, cphash + 2, 2);
			cat_cstring(&tx_path, "/");
			cat_cstring(&tx_path, cphash);
			cat_cstring(&tx_path, "/out_");
			strcat_int(&tx_path, oidx);

			ret = (stat_file(tx_path.str) == 0) ? 1 : 0;
			free_string(&tx_path);
			if (!ret)
			{
				release_zone_ref(&my_list);
				release_zone_ref(&my_llist);
				return 0;
			}

			if (get_tx_output_amount(cphash, oidx, &amount))
				total_in += amount;
		}
		release_zone_ref(&txin_list);
		
		total_out = 0;
		check_tx_outputs(tx, &total_out,coinstaking, &is_staking);
		
		if (is_staking)
		{
			if (coinstaking == 0)
			{
				release_zone_ref(&my_list);
				return 0;
			}
			coinstaking = 0;
			list_reward = total_out - total_in;
		}
		else
		{
			if (total_in < total_out)
			{
				ret = 0;
				release_zone_ref(&my_list);
				break;
			}
			txFee = total_in - total_out;
			fees += txFee;
		}
	}


	if (!ret)return 0;

	if (list_reward > (staking_reward+fees))
		return 0;

	return 1;
}


OS_API_C_FUNC(int) check_block_pow(mem_zone_ref_ptr hdr)
{
	hash_t				blk_pow, diff_hash;
	mem_zone_ref		log={PTR_NULL};
	unsigned int		bits;
	char				rpow[32];
	hash_t				bhash;
	int					n= 32;
	
	//pow block
	tree_manager_get_child_value_i32		(hdr, NODE_HASH("bits"), &bits);

	if (!tree_manager_get_child_value_hash(hdr, NODE_HASH("blk hash"), bhash))
	{
		compute_block_hash					(hdr, bhash);
		tree_manager_set_child_value_bhash	(hdr, "blk hash", bhash);
	}
	if (!tree_manager_get_child_value_hash(hdr, NODE_HASH("blk pow"), blk_pow))
	{
		compute_block_pow					(hdr, blk_pow);
		tree_manager_set_child_value_hash	(hdr, "blk pow", blk_pow);
	}
	SetCompact (bits, diff_hash);
	//compare pow & diff

	while (n--)
	{
		rpow[n] = blk_pow[31 - n];
	}
	tree_manager_create_node		 ("log", NODE_LOG_PARAMS, &log);
	tree_manager_set_child_value_hash(&log,"diff" ,diff_hash);
	tree_manager_set_child_value_hash(&log, "pow", rpow);
	tree_manager_set_child_value_hash(&log, "hash", bhash);
	log_message						 ("----------------\nNEW POW BLOCK\n%diff%\n%pow%\n%hash%\n",&log);
	release_zone_ref				 (&log);
	return 1;
}

void make_blk_path(const char *chash, struct string *blk_path)
{

	make_string	(blk_path, "./blks/");
	cat_ncstring(blk_path, chash + 0, 2);
	cat_cstring	(blk_path, "/");
	cat_ncstring(blk_path, chash + 2, 2);
	cat_cstring	(blk_path, "/");
	cat_cstring	(blk_path, chash);
}

OS_API_C_FUNC(int)  get_prev_block_time(mem_zone_ref_ptr header, ctime_t *time)
{
	char prevHash[65];
	struct string blk_path;
	int ret;

	if (!tree_manager_get_child_value_str(header, NODE_HASH("prev"), prevHash,65,16))
		return 0;
	
	make_blk_path(prevHash, &blk_path);
	ret=get_ftime(blk_path.str, time);
	free_string(&blk_path);

	return ret;
}

OS_API_C_FUNC(int) store_block(mem_zone_ref_ptr header, mem_zone_ref_ptr tx_list)
{
	mem_zone_ref_ptr	tx = PTR_NULL;
	mem_zone_ref		my_list = { PTR_NULL };
	size_t				length;
	mem_ptr				buffer;
	hash_t				blk_hash;
	char				chash[65];
	struct string		blk_path={0},blk_data_path={0};
	unsigned int		n, nc, block_time;
	hash_t				*blk_txs;

	if (!tree_manager_get_child_value_hash(header, NODE_HASH("blk hash"), blk_hash))return 0;

	n = 0;
	while (n<32)
	{
		chash[n * 2 + 0] = hex_chars[blk_hash[n] >> 4];
		chash[n * 2 + 1] = hex_chars[blk_hash[n] & 0x0F];
		n++;
	}
	chash[64] = 0;

	make_string		(&blk_path, "./blks/");
	create_dir		(blk_path.str);
	
	cat_ncstring	(&blk_path, chash + 0, 2);
	cat_cstring		(&blk_path, "/");
	create_dir		(blk_path.str);
	
	cat_ncstring	(&blk_path, chash + 2, 2);
	cat_cstring		(&blk_path, "/");
	create_dir		(blk_path.str);
	
	cat_cstring		(&blk_path, chash);
	create_dir		(blk_path.str);

	if (tree_manager_get_child_value_i32(header, NODE_HASH("time"), &block_time))
		set_ftime(blk_path.str, block_time);
		
	length = compute_payload_size(header);
	buffer = malloc_c(length);

	write_node		(header, (unsigned char *)buffer);
	
	clone_string	(&blk_data_path, &blk_path);
	cat_cstring		(&blk_data_path, "/header");
	
	put_file		(blk_data_path.str, buffer, length);
	
	free_c			(buffer);
	free_string		(&blk_data_path);

	nc		=	tree_manager_get_node_num_children(tx_list);
	if (nc > 0)
	{
		blk_txs = calloc_c(sizeof(hash_t), nc);
		n = 0;
		for (tree_manager_get_first_child(tx_list, &my_list, &tx); ((tx != NULL) && (tx->zone != NULL)); tree_manager_get_next_child(&my_list, &tx))
		{
			uint64_t			total_out,total_in;
			hash_t				tx_hash;
			struct string		tx_path = { 0 };
			hash_t				tmp_hash;

			length = get_node_size(tx);
			buffer = malloc_c(length);
			write_node(tx, (unsigned char *)buffer);

			if (!tree_manager_get_child_value_hash(tx, NODE_HASH("tx hash"), tx_hash))
			{
				mbedtls_sha256((unsigned char *)buffer, length, tmp_hash, 0);
				mbedtls_sha256(tmp_hash, 32, tx_hash, 0);
			}
			memcpy_c		(&blk_txs[n++], tx_hash, 32);
			n = 0;
			while (n<32)
			{
				chash[n * 2 + 0] = hex_chars[tx_hash[n] >> 4];
				chash[n * 2 + 1] = hex_chars[tx_hash[n] & 0x0F];
				n++;
			}
			chash[64] = 0;


			make_string	(&tx_path	, "./txs/");
			create_dir	(tx_path.str);
			
			cat_ncstring(&tx_path, chash + 0, 2);
			cat_cstring	(&tx_path, "/");
			create_dir	(tx_path.str);
			
			cat_ncstring(&tx_path, chash + 2, 2);
			cat_cstring	(&tx_path, "/");
			create_dir	(tx_path.str);
			
			cat_cstring(&tx_path, chash);
			create_dir	(tx_path.str);
			
			cat_cstring	(&tx_path, "/data");
			put_file	(tx_path.str, buffer, length);
			
			free_c(buffer);
			free_string(&tx_path);

			store_tx_output(tx, chash, &total_out);
			store_tx_inputs(tx, chash, &total_in);
		}

		clone_string	(&blk_data_path, &blk_path);
		cat_cstring		(&blk_data_path, "/txs");
		put_file		(blk_data_path.str, blk_txs, nc*sizeof(hash_t));
		free_c			(blk_txs);
	}
	free_string(&blk_data_path);

	append_file("./blk_indexes", blk_hash, 32);

	free_string(&blk_path);

	return 1;
}



int make_iadix_merkle(mem_zone_ref_ptr genesis,mem_zone_ref_ptr txs,hash_t merkle)
{
	mem_zone_ref	newtx = { PTR_NULL };
	mem_zone_ref	script_node = { PTR_NULL };
	struct string	out_script = { PTR_NULL };
	struct string	timeproof = { PTR_NULL };

	make_string(&timeproof, "1 Sep 2016 Iadix coin");
	tree_manager_create_node("script", NODE_BITCORE_SCRIPT, &script_node);
	tree_manager_set_child_value_vint32(&script_node, "0", 0);
	tree_manager_set_child_value_vint32(&script_node, "1", 42);
	tree_manager_set_child_value_vstr(&script_node, "2", &timeproof);

	new_transaction(&newtx, 1466419086);
	tx_add_input(&newtx, null_hash, 0xFFFFFFFF, &script_node);
	tx_add_output(&newtx, 0, &out_script);
	release_zone_ref(&script_node);
	free_string(&timeproof);

	
	tree_manager_node_add_child(txs, &newtx);
	release_zone_ref			(&newtx);

	build_merkel_tree			(txs, merkle);
	
	return 0;
}
OS_API_C_FUNC(int) make_genesis_block(mem_zone_ref_ptr genesis_conf,mem_zone_ref_ptr genesis)
{
	hash_t								blk_pow, merkle;
	mem_zone_ref						txs = { PTR_NULL };
	uint64_t							StakeMod;
	unsigned int						version, time, bits, nonce;
	hash_t								hmod;
	memset_c							(null_hash, 0, 32);
	
	tree_manager_create_node			("genesis", NODE_BITCORE_BLK_HDR	, genesis);
	tree_manager_create_node			("txs"	  , NODE_BITCORE_TX_LIST	, &txs);
	
	if (!tree_manager_get_child_value_hash(genesis_conf, NODE_HASH("merkle_root"), merkle))
	{
		make_iadix_merkle					(genesis, &txs, merkle);

		/*
		printf("genesis merkle:\n");
		for (n = 0; n < 32; n++){printf("%02x", merkle[31 - n]);}
		printf("\n");
		*/
	}
	
	tree_manager_set_child_value_hash	(genesis, "merkle_root"			, merkle);
	tree_manager_set_child_value_hash	(genesis, "prev"					, null_hash);

	tree_manager_get_child_value_i32	(genesis_conf, NODE_HASH("version")	, &version);
	tree_manager_get_child_value_i32	(genesis_conf, NODE_HASH("time")	, &time);
	tree_manager_get_child_value_i32	(genesis_conf, NODE_HASH("bits")	, &bits);
	tree_manager_get_child_value_i32	(genesis_conf, NODE_HASH("nonce")	, &nonce);

	tree_manager_set_child_value_i32	(genesis, "version"		, version);
	tree_manager_set_child_value_i32	(genesis, "time"			, time);
	tree_manager_set_child_value_i32	(genesis, "bits"			, bits);
	tree_manager_set_child_value_i32	(genesis, "nonce"			, nonce);
	
	tree_manager_node_add_child			(genesis, &txs);

	compute_block_pow					(genesis, blk_pow);
	tree_manager_set_child_value_bhash	(genesis, "blk hash", blk_pow);
	tree_manager_set_child_value_hash	(genesis, "blk pow" , blk_pow);

	/*
	printf("genesis block hash :\n");
	for (n = 0; n < 32; n++){ printf("%02x", blk_pow[31 - n]); }
	printf("\n");
	*/
	
	if (tree_manager_get_child_value_i64(genesis_conf, NODE_HASH("InitialStakeModifier"), &StakeMod))
		tree_manager_set_child_value_i64(genesis, "StakeMod", StakeMod);

	if (tree_manager_get_child_value_hash(genesis_conf, NODE_HASH("InitialStakeModifier2"), hmod))
		tree_manager_set_child_value_hash(genesis, "StakeMod2", hmod);

	if (!find_hash(blk_pow))
		store_block(genesis, &txs);

	release_zone_ref(&txs);
	return 1;

}
