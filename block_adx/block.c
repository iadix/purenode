
#include <base/std_def.h>
#include <base/std_mem.h>
#include <base/mem_base.h>
#include <base/std_str.h>

#include <sha256.h>
#include <strs.h>
#include <tree.h>
#include <fsio.h>



C_IMPORT size_t			C_API_FUNC	compute_payload_size(mem_zone_ref_ptr payload_node);
C_IMPORT char*			C_API_FUNC	write_node(mem_zone_ref_const_ptr key, unsigned char *payload);
C_IMPORT size_t			C_API_FUNC	get_node_size(mem_zone_ref_ptr key);
C_IMPORT void			C_API_FUNC	serialize_children(mem_zone_ref_ptr node, unsigned char *payload);
C_IMPORT const unsigned char*	C_API_FUNC read_node(mem_zone_ref_ptr key, const unsigned char *payload);
C_IMPORT size_t			C_API_FUNC init_node(mem_zone_ref_ptr key);

extern int C_API_FUNC get_out_script_address(struct string *script, btc_addr_t addr);

extern int compute_script_size(mem_zone_ref_ptr script_node);
extern int serialize_script(mem_zone_ref_ptr script_node, struct string *script);

extern int scrypt_blockhash(const void* input, hash_t hash);

#define ONE_COIN		100000000ULL
#define ONE_CENT		1000000ULL

hash_t					null_hash		= { 0xCD };
const char				*null_hash_str	= "0000000000000000000000000000000000000000000000000000000000000000";
unsigned char			pubKeyPrefix	= 0xCD;
static const uint64_t	one_coin		= ONE_COIN;
static const uint64_t	block_reward = (100000ULL * ONE_COIN);


OS_API_C_FUNC(void) set_pubkeyprefix(unsigned char c){
	memset_c(null_hash, 0, 32);
	pubKeyPrefix = c;
}
OS_API_C_FUNC(uint64_t) get_blockreward(uint64_t block)
{

	return block_reward;
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
OS_API_C_FUNC(void) mul_compact(unsigned int nBits, uint64_t op, hash_t hash)
{
	unsigned int size;
	uint64_t	data, d;
	int			n;
	size	= (nBits >> 24)-3;
	d		= (nBits & 0xFFFFFF);

	data	= mul64(d , op);

	n = 0;
	while ((n<8) && ((size+n)<32))
	{
		hash[size + n] = (unsigned int )(data) & 0xFF;
		data = shr64(data,8);
		n++;
	}
}

unsigned int scale_compact(unsigned int nBits, uint64_t mop, uint64_t dop)
{
	unsigned int size;
	unsigned int ret;
	unsigned int bdata;
	uint64_t	data;
	size = (nBits >> 24);
	data = muldiv64(nBits & 0xFFFFFF, mop, dop);
	
	while (data&(~0xFFFFFFUL))
	{
		data=shr64(data, 8);
		size++;
	}
	bdata = data & 0x00FFFFFF;
	ret = ((size & 0xFF) << 24) | bdata;

	return ret;
}


OS_API_C_FUNC(unsigned int) calc_new_target(unsigned int nActualSpacing, unsigned int TargetSpacing, unsigned int nTargetTimespan,unsigned int pBits)
{
	unsigned int		nInterval;
	uint64_t			mulop , dividend;
	nInterval = nTargetTimespan / TargetSpacing;
	mulop  = ((nInterval - 1) * TargetSpacing + nActualSpacing + nActualSpacing);
	dividend  = ((nInterval + 1) * TargetSpacing);
	return scale_compact(pBits, mulop, dividend);
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
OS_API_C_FUNC(int) find_blk_hash(const hash_t tx_hash, hash_t blk_hash)
{
	char				cthash[65];
	unsigned int		n = 32;
	struct string		tx_path = { 0 };
	unsigned char		*buffer;
	mem_size			size;
	int					ret;
	while (n--)
	{
		cthash[n * 2 + 0] = hex_chars[tx_hash[n] >> 4];
		cthash[n * 2 + 1] = hex_chars[tx_hash[n] & 0x0F];
	}

	cthash[64] = 0;

	make_string(&tx_path, "txs");
	cat_ncstring_p(&tx_path, cthash, 2);
	cat_ncstring_p(&tx_path, cthash + 2, 2);

	ret = get_file(tx_path.str, &buffer, &size);
	free_string(&tx_path);
	if (ret<=0)return 0;

	ret = 0;
	n = 0;
	while (n<size)
	{
		if (!memcmp_c(&buffer[n], tx_hash, sizeof(hash_t)))
		{
			memcpy_c(blk_hash, &buffer[n + 32], sizeof(hash_t));
			ret = 1;
			break;
		}
		n += 64;
	}
	free_c(buffer);
	return ret;
}



OS_API_C_FUNC(int) get_tx_blk_height(const hash_t tx_hash, uint64_t *height, uint64_t *block_time, uint64_t *tx_time)
{
	char chash[65], tchash[65];
	hash_t blk_hash;
	struct string blk_path = { PTR_NULL }, tx_path = { PTR_NULL };
	unsigned char *data;
	size_t len;
	ctime_t ctime;
	unsigned int n;
	
	if (!find_blk_hash(tx_hash, blk_hash))
		return 0;

	n = 32;
	while (n--)
	{
		chash[n * 2 + 0] = hex_chars[blk_hash[n] >> 4];
		chash[n * 2 + 1] = hex_chars[blk_hash[n] & 0x0F];
	}
	chash[64] = 0;

	n = 32;
	while (n--)
	{
		tchash[n * 2 + 0] = hex_chars[tx_hash[n] >> 4];
		tchash[n * 2 + 1] = hex_chars[tx_hash[n] & 0x0F];
	}
	tchash[64] = 0;

	make_string		(&blk_path, "blks");
	cat_ncstring_p	(&blk_path, chash + 0, 2);
	cat_ncstring_p	(&blk_path, chash + 2, 2);
	cat_cstring_p	(&blk_path, chash);
	get_ftime		(blk_path.str, &ctime);
	(*block_time) = ctime;

	clone_string	(&tx_path, &blk_path);
	cat_cstring_p	(&tx_path, "tx_");
	cat_cstring		(&tx_path, tchash);
	get_ftime		(tx_path.str, &ctime);
	(*tx_time) = ctime;
	free_string(&tx_path);

	cat_cstring_p	(&blk_path, "height");
	if (get_file(blk_path.str, &data, &len))
	{
		(*height) = *((uint64_t *)data);
		free_c(data);
	}
	free_string(&blk_path);




	return 1;
}

OS_API_C_FUNC(int) load_tx(mem_zone_ref_ptr tx, hash_t blk_hash, const hash_t tx_hash)
{
	char				chash[65],cthash[65];
	unsigned char		*tx_data;
	size_t				tx_data_len;
	struct string		tx_path = { 0 };
	unsigned char		*buffer;
	mem_size			size;
	int					ret=0;
	
	unsigned int		n = 32;

	while (n--)
	{
		cthash[n * 2 + 0] = hex_chars[tx_hash[n] >> 4];
		cthash[n * 2 + 1] = hex_chars[tx_hash[n] & 0x0F];
	}

	cthash[64] = 0;



	make_string		(&tx_path, "txs");
	cat_ncstring_p	(&tx_path, cthash,2);
	cat_ncstring_p	(&tx_path, cthash+2,2);

	ret=get_file	(tx_path.str, &buffer, &size);
	free_string		(&tx_path);
	if (ret<=0)return 0;

	ret = 0;
	n	= 0;
	while (n<size)
	{
		if (!memcmp_c(&buffer[n], tx_hash, sizeof(hash_t)))
		{
			memcpy_c(blk_hash, &buffer[n + 32], sizeof(hash_t));
			ret = 1;
			break;
		}	

		n += 64;
	}
	free_c(buffer);
	if (!ret)
		return 0;

	n = 32;
	while (n--)
	{
		chash[n * 2 + 0] = hex_chars[blk_hash[n] >> 4];
		chash[n * 2 + 1] = hex_chars[blk_hash[n] & 0x0F];
	}
	chash[64] = 0;

	make_string		(&tx_path, "blks");
	cat_ncstring_p	(&tx_path, chash + 0, 2);
	cat_ncstring_p	(&tx_path, chash + 2, 2);
	cat_cstring_p	(&tx_path, chash);
	cat_cstring_p	(&tx_path, "tx_");
	cat_cstring		(&tx_path, cthash);

	ret = 0;

	if (get_file(tx_path.str, &tx_data, &tx_data_len) > 0)
	{
		if ((tx->zone != PTR_NULL) || (tree_manager_create_node("tx", NODE_BITCORE_TX, tx)))
		{
			init_node(tx);
			read_node(tx, tx_data);
			ret = 1;
		}
		free_c(tx_data);
	}
	free_string		(&tx_path);
	return ret;
}
OS_API_C_FUNC(int) load_tx_input(mem_zone_ref_const_ptr tx, unsigned int idx, mem_zone_ref_ptr	vin , mem_zone_ref_ptr tx_out)
{
	hash_t			prev_hash, blk_hash;
	int				ret;

	if (!get_tx_input(tx, idx, vin))return 0;

	tree_manager_get_child_value_hash(vin, NODE_HASH("tx hash"), prev_hash);
	ret = load_tx(tx_out, blk_hash, prev_hash);

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

OS_API_C_FUNC(int) add_unspent(btc_addr_t	addr, const char *tx_hash, unsigned int oidx, uint64_t amount, btc_addr_t *src_addrs, unsigned int n_addrs)
{
	struct string	out_path = { 0 };
	int ret;

	make_string(&out_path, "adrs");
	cat_ncstring_p(&out_path, addr, 34);
	cat_cstring_p(&out_path, "unspent");
	create_dir(out_path.str);
	cat_cstring_p(&out_path, tx_hash);
	cat_cstring(&out_path, "_");
	strcat_int(&out_path, oidx);

	ret = put_file(out_path.str, &amount, sizeof(uint64_t));
	if (n_addrs > 0)
	{
		append_file(out_path.str, &n_addrs , sizeof(unsigned int));
		append_file(out_path.str, src_addrs, n_addrs*sizeof(btc_addr_t));
	}
	free_string(&out_path);
	return (ret>0);
}


OS_API_C_FUNC(int) spend_tx_addr(btc_addr_t addr, const char *tx_hash, unsigned int vin,const char *ptx_hash, unsigned int oidx, btc_addr_t *addrs_to, unsigned int n_addrs_to)
{
	struct string	 unspent_path = { 0 };
	unsigned char	*sp_buf;
	unsigned int	len;

	make_string(&unspent_path, "adrs");
	cat_ncstring_p(&unspent_path, addr, 34);
	if (stat_file(unspent_path.str) != 0)
	{
		free_string(&unspent_path);
		return 0;
	}

	cat_cstring_p(&unspent_path, "unspent");
	cat_cstring_p(&unspent_path, ptx_hash);
	cat_cstring(&unspent_path, "_");
	strcat_int(&unspent_path, oidx);

	if (get_file(unspent_path.str, &sp_buf, &len)>0)	
	{
		struct string	spent_path = { 0 };
					
		make_string		(&spent_path, "adrs");
		cat_ncstring_p	(&spent_path, addr, 34);
		cat_cstring_p	(&spent_path, "spent");
		create_dir		(spent_path.str);
		cat_cstring_p	(&spent_path, ptx_hash);
		cat_cstring		(&spent_path, "_");
		strcat_int		(&spent_path, oidx);
		move_file		(unspent_path.str, spent_path.str);
		
		append_file		(spent_path.str, tx_hash, sizeof(hash_t));
		append_file		(spent_path.str, &vin	, sizeof(unsigned int));
		append_file		(spent_path.str, addrs_to, n_addrs_to*sizeof(btc_addr_t));

		free_string		(&spent_path);
		free_c			(sp_buf);
		del_file		(unspent_path.str);
	}

	free_string(&unspent_path);


	return 1;
}

int cancel_spend_tx_addr(btc_addr_t addr, const char *tx_hash, unsigned int oidx)
{
	struct string	spent_path = { 0 }; 
	int ret;
	make_string(&spent_path, "adrs");
	cat_ncstring_p(&spent_path, addr, 34);

	cat_cstring_p(&spent_path, "spent");
	cat_cstring_p(&spent_path, tx_hash);
	cat_cstring(&spent_path, "_");
	strcat_int(&spent_path, oidx);

	ret = (stat_file(spent_path.str) == 0) ? 1 : 0;
	if (ret)
	{
		struct string	 unspent_path = { 0 };
		unsigned char	 *data;
		size_t			 len;

		make_string(&unspent_path, "adrs");
		cat_ncstring_p(&unspent_path, addr, 34);
		cat_cstring_p(&unspent_path, "unspent");
		create_dir(unspent_path.str);
		cat_cstring_p(&unspent_path, tx_hash);
		cat_cstring(&unspent_path, "_");
		strcat_int(&unspent_path, oidx);
		ret = move_file(spent_path.str,unspent_path.str);

		if (get_file(unspent_path.str, &data, &len))
		{
			unsigned int n_addr;
			n_addr = *((unsigned int *)(data + sizeof(uint64_t)));
			truncate_file(unspent_path.str, sizeof(uint64_t) + sizeof(unsigned int) + n_addr*sizeof(btc_addr_t), PTR_NULL, 0);
		}

		free_string(&spent_path);
	}
	free_string(&spent_path);

	return ret;
}
int store_tx_vout(struct string *out_path, mem_zone_ref_ptr vout, btc_addr_t out_addr)
{
	unsigned char		bbuffer[64];
	struct string		script = { 0 };
	uint64_t			amount;
	int					ret_addr;

	if (!tree_manager_get_child_value_i64(vout, NODE_HASH("value"), &amount))return 0;
	if (!tree_manager_get_child_value_istr(vout, NODE_HASH("script"), &script, 16))return 0;
	if (script.len == 0){ free_string(&script); return 0; }
	ret_addr = get_out_script_address(&script, out_addr);
	free_string(&script);

	memcpy_c(bbuffer, &amount, sizeof(uint64_t));
	memcpy_c(bbuffer + sizeof(uint64_t), out_addr, sizeof(btc_addr_t));
	put_file(out_path->str, bbuffer, sizeof(uint64_t) + sizeof(btc_addr_t));

	return ret_addr;
}

OS_API_C_FUNC(int) get_tx_output(mem_zone_ref_const_ptr tx, unsigned int idx, mem_zone_ref_ptr vout)
{
	int ret;
	mem_zone_ref txout_list = { PTR_NULL };

	if (!tree_manager_find_child_node(tx, NODE_HASH("txsout"), NODE_BITCORE_VOUTLIST, &txout_list))return 0;
	ret = tree_manager_get_child_at(&txout_list, idx, vout);
	release_zone_ref(&txout_list);
	return ret;

}



OS_API_C_FUNC(int) get_tx_output_amount(const hash_t tx_hash, unsigned int idx, uint64_t *amount)
{
	hash_t			blkhash;
	mem_zone_ref	tx = { PTR_NULL }, vout = { PTR_NULL };
	int				ret;

	if (!load_tx(&tx, blkhash, tx_hash))return 0;
	ret = get_tx_output(&tx, idx, &vout);
	if (ret)
	{
		ret = tree_manager_get_child_value_i64(&vout, NODE_HASH("value"), amount);
		release_zone_ref(&vout);
	}
	release_zone_ref(&tx);
	return ret;
}

OS_API_C_FUNC(int) get_tx_output_addr(const hash_t tx_hash, unsigned int idx, btc_addr_t addr)
{
	hash_t			blkhash;
	mem_zone_ref	tx = { PTR_NULL }, vout = { PTR_NULL };
	int				ret;

	if (!load_tx(&tx, blkhash, tx_hash))return 0;
	ret = get_tx_output(&tx, idx, &vout);
	if (ret)
	{
		struct string  script;
		ret = tree_manager_get_child_value_istr(&vout, NODE_HASH("script"), &script,0);
		if (ret)
		{
			get_out_script_address(&script, addr);
			free_string(&script);
		}
		release_zone_ref(&vout);
	}
	release_zone_ref(&tx);
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

	if ((ret) && (script.str[0] != 0))
		ret = 0;

	free_string(&script);
	release_zone_ref(&vout);

	return ret;
}


OS_API_C_FUNC(int) is_tx_null(mem_zone_ref_const_ptr tx)
{
	struct string	script = { 0 };
	mem_zone_ref	vout = { PTR_NULL };
	mem_zone_ref	txout_list = { PTR_NULL };
	uint64_t		amount;
	int				ret, nc;


	if (!tree_manager_find_child_node(tx, NODE_HASH("txsout"), NODE_BITCORE_VOUTLIST, &txout_list))return -1;
	nc = tree_manager_get_node_num_children(&txout_list);
	if (nc == 0)
	{
		release_zone_ref(&txout_list);
		return -1;
	}
	ret = tree_manager_get_child_at(&txout_list, 0, &vout);
	release_zone_ref(&txout_list);
	if (!ret)return -1;
	ret = tree_manager_get_child_value_i64(&vout, NODE_HASH("value"), &amount);
	if (ret)ret = tree_manager_get_child_value_istr(&vout, NODE_HASH("script"), &script, 0);
	release_zone_ref(&vout);
	if (!ret)return -1;
	if ((nc == 1) && (amount == 0) && (script.str[0] == 0))
		ret = 1;
	else
		ret = 0;

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
		if (hash[31 - n] != uc)
			return 0;

		n++;
	}

	return 1;

}
OS_API_C_FUNC(int) get_moneysupply(uint64_t *amount)
{
	unsigned char *data;
	size_t len;
	int ret = 0;
	if (get_file("supply", &data, &len))
	{
		if (len >= sizeof(uint64_t))
		{
			ret = 1;
			*amount = *((uint64_t *)data);
		}
		free_c(data);
	}
	return ret;
}

OS_API_C_FUNC(int) add_moneysupply(uint64_t amount)
{
	unsigned char *data;
	size_t len;
	uint64_t cur = 0;

	if (get_file("supply", &data, &len))
	{
		if (len >= sizeof(uint64_t))
			cur = *((uint64_t *)data);
		free_c(data);
	}
	cur += amount;
	put_file("supply", &cur, sizeof(uint64_t));
}

OS_API_C_FUNC(int) store_tx_inputs(mem_zone_ref_ptr tx,const char *tx_hash,unsigned int wallet)
{
	struct string	 tx_path = { 0 };
	mem_zone_ref	 txin_list = { PTR_NULL }, txout_list = { PTR_NULL }, my_list = { PTR_NULL };
	mem_zone_ref_ptr input = PTR_NULL, out = PTR_NULL;
	unsigned int	 n_to_addrs,vin;
	btc_addr_t		to_addr_list[16];
	
	
	if (!tree_manager_find_child_node(tx, NODE_HASH("txsin"), NODE_BITCORE_VINLIST, &txin_list))return 0;
	
	if (wallet)
	{
		n_to_addrs = 0;
		if (tree_manager_find_child_node(tx, NODE_HASH("txsout"), NODE_BITCORE_VOUTLIST, &txout_list))
		{
			for (tree_manager_get_first_child(&txout_list, &my_list, &out); ((out != NULL) && (out->zone != NULL)); tree_manager_get_next_child(&my_list, &out))
			{
				struct string script = { 0 };
				if (!tree_manager_get_child_value_istr(out, NODE_HASH("script"), &script, 16))continue;
				if (script.len == 0){ free_string(&script); continue; }
				if (get_out_script_address(&script, to_addr_list[n_to_addrs]))
				{
					unsigned int n, f;
					f = 0;
					for (n = 0; n < n_to_addrs; n++)
					{
						if (!memcmp_c(to_addr_list[n_to_addrs], to_addr_list[n], sizeof(btc_addr_t)))
						{
							f = 1;
							break;
						}
					}
					if (f == 0)
						n_to_addrs++;
				}
				free_string(&script);
			}
			release_zone_ref(&txout_list);
		}
	}

	for (vin = 0, tree_manager_get_first_child(&txin_list, &my_list, &input); ((input != NULL) && (input->zone != NULL)); tree_manager_get_next_child(&my_list, &input), vin++)
	{
		char			chash[65], ptchash[65];
		hash_t			blk_hash,prev_hash = { 0 };
		struct string	out_path = {0};
		int				sret,n;
		unsigned int	 oidx;
		tree_manager_get_child_value_hash	(input, NODE_HASH("tx hash"), prev_hash);
		tree_manager_get_child_value_i32	(input, NODE_HASH("idx")	, &oidx);
		
		if (!memcmp_c(prev_hash, null_hash, sizeof(hash_t)))
		{
			btc_addr_t coinbase;
			memset_c(coinbase, '0', sizeof(btc_addr_t));
			tree_manager_set_child_value_btcaddr(input, "src addr", coinbase);
			continue;
		}
		if (!find_blk_hash(prev_hash, blk_hash))continue;

		n = 0;
		while (n<32)
		{
			chash[n * 2 + 0] = hex_chars[blk_hash[n] >> 4];
			chash[n * 2 + 1] = hex_chars[blk_hash[n] & 0x0F];
			n++;
		}
		chash[64] = 0;

		n = 0;
		while (n<32)
		{
			ptchash[n * 2 + 0] = hex_chars[prev_hash[n] >> 4];
			ptchash[n * 2 + 1] = hex_chars[prev_hash[n] & 0x0F];
			n++;
		}
		ptchash[64] = 0;

		make_string	  (&out_path, "blks");
		cat_ncstring_p(&out_path, chash + 0, 2);
		cat_ncstring_p(&out_path, chash + 2, 2);
		cat_cstring_p (&out_path, chash);
		cat_cstring_p (&out_path, ptchash);
		cat_cstring   (&out_path, "_out_");
		strcat_int    (&out_path, oidx);

		sret = stat_file(out_path.str);
		if (sret == 0)
		{
			char *buffer;
			size_t len;
			if (get_file(out_path.str, &buffer, &len))
			{
				if (len >= (sizeof(uint64_t) + sizeof(btc_addr_t)))
				{
					tree_manager_set_child_value_i64	(input, "amount"	, *((uint64_t *)(buffer)));
					tree_manager_set_child_value_btcaddr(input, "src addr"	, buffer + sizeof(uint64_t));
					
					if (wallet)
						spend_tx_addr(buffer + sizeof(uint64_t), tx_hash,vin, ptchash, oidx, to_addr_list, n_to_addrs);
				}
				free_c(buffer);
			}
			del_file(out_path.str);
		}
		free_string	 (&out_path);
	}
	release_zone_ref(&txin_list);
	return 1;
}



OS_API_C_FUNC(int) store_tx_outputs(const char * blk_hash,mem_zone_ref_ptr tx, const char * tx_hash,unsigned int wallet)
{
	
	struct string		script={0},tx_path={0};
	mem_zone_ref		txout_list = { PTR_NULL }, txin_list = { PTR_NULL }, my_list = { PTR_NULL };
	mem_zone_ref_ptr	out = PTR_NULL, in = PTR_NULL;
	unsigned int		oidx,n_in_addr;
	btc_addr_t			src_addr_list[16];
	
	
	if (!tree_manager_find_child_node(tx, NODE_HASH("txsout"), NODE_BITCORE_VOUTLIST, &txout_list))return 0;

	if (wallet)
	{
		n_in_addr = 0;
		if (tree_manager_find_child_node(tx, NODE_HASH("txsin"), NODE_BITCORE_VINLIST, &txin_list))
		{
			for (tree_manager_get_first_child(&txin_list, &my_list, &in); ((in != NULL) && (in->zone != NULL)); tree_manager_get_next_child(&my_list, &in))
			{
				if (tree_manager_get_child_value_btcaddr(in, NODE_HASH("src addr"), src_addr_list[n_in_addr]))
				{
					unsigned int n, f;
					f = 0;
					for (n = 0; n < n_in_addr; n++)
					{
						if (!memcmp_c(src_addr_list[n_in_addr], src_addr_list[n], sizeof(btc_addr_t)))
						{
							f = 1;
							break;
						}
					}
					if (f == 0)
						n_in_addr++;
				}
			}
			release_zone_ref(&txin_list);
		}
	}
	make_string		(&tx_path, "blks");
	cat_ncstring_p	(&tx_path, blk_hash + 0, 2);
	cat_ncstring_p	(&tx_path, blk_hash + 2, 2);
	cat_cstring_p	(&tx_path, blk_hash );

	for (oidx = 0,tree_manager_get_first_child(&txout_list, &my_list, &out); ((out != NULL) && (out->zone != NULL)); oidx++, tree_manager_get_next_child(&my_list, &out))
	{
		btc_addr_t		out_addr = { 0 };
		struct string	out_path = {0};
		uint64_t		amount	=	0;
		int				ret;
		
		clone_string		(&out_path, &tx_path);
		cat_cstring_p		(&out_path, tx_hash);
		cat_cstring			(&out_path, "_out_");
		strcat_int			(&out_path, oidx);
		ret=store_tx_vout	(&out_path, out, out_addr);
		free_string			(&out_path);
		if (ret)
		{
			if (wallet)
			{
				make_string(&out_path, "adrs");
				cat_ncstring_p(&out_path, out_addr, 34);

				if (is_coinbase(tx))
					create_dir(out_path.str);

				if (stat_file(out_path.str) == 0)
				{
					tree_manager_get_child_value_i64(out, NODE_HASH("value"), &amount);
					add_unspent(out_addr, tx_hash, oidx, amount, src_addr_list, n_in_addr);
				}
				free_string(&out_path);
			}
		}
	}
	free_string		(&tx_path);
	release_zone_ref(&txout_list);
	return 1;
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
			step = mul64(step,2);
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
	uint64_t			list_reward;
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

			hash_t				pBlock;
			char				cphash[65] = { 0 }, ctphash[65] = { 0 };
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
					total_in += get_blockreward(0);
					coinbase = 0;
					continue;
				}
				dec_zone_ref(tx);
				release_zone_ref(&my_list);
				dec_zone_ref(input);
				release_zone_ref(&my_llist);
				release_zone_ref(&txin_list);
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
				free_string	(&script);
				
				load_tx		(&prev_tx,pBlock, prev_hash);

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
						ret = tree_manager_get_child_value_i64(&prevout, NODE_HASH("value"), &amount);
					}
					release_zone_ref(&prevout);
				}
				release_zone_ref(&prev_tx);
			}

			n = 0;
			while (n<32)
			{
				ctphash[n * 2 + 0] = hex_chars[pBlock[n] >> 4];
				ctphash[n * 2 + 1] = hex_chars[pBlock[n] & 0x0F];
				n++;
			}
			ctphash[64] = 0;

			make_string		(&tx_path, "blks");
			cat_ncstring_p	(&tx_path, ctphash + 0, 2);
			cat_ncstring_p	(&tx_path, ctphash + 2, 2);
			cat_cstring_p	(&tx_path, ctphash);
			cat_cstring_p	(&tx_path, cphash);
			cat_cstring		(&tx_path, "_out_");
			strcat_int		(&tx_path, oidx);

			ret = (stat_file(tx_path.str) == 0) ? 1 : 0;
			free_string(&tx_path);
			if (!ret)
			{
				dec_zone_ref(tx);
				release_zone_ref(&my_list);
				dec_zone_ref(input);
				release_zone_ref(&my_llist);
				release_zone_ref(&txin_list);
				return 0;
			}
			total_in += amount;
		}
		release_zone_ref(&txin_list);
		
		total_out = 0;
		check_tx_outputs(tx, &total_out,coinstaking, &is_staking);
		
		if (is_staking)
		{
			if (coinstaking == 0)
			{
				dec_zone_ref(tx);
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
				dec_zone_ref(tx);
				release_zone_ref(&my_list);
				return 0;
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


OS_API_C_FUNC(int) check_block_pow(mem_zone_ref_ptr hdr,hash_t diff_hash)
{
	hash_t				blk_pow, rdiff;
	mem_zone_ref		log={PTR_NULL};
	char				rpow[32];
	hash_t				bhash;
	int					n= 32;
	
	//pow block

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
	n = 32;
	while (n--)
	{
		rdiff[n] = diff_hash[31 - n];
		rpow[n]  = blk_pow[31 - n];
	}
	//compare pow & diff
	if (cmp_hashle(blk_pow, rdiff) == 1)
	{
		tree_manager_create_node("log", NODE_LOG_PARAMS, &log);
		tree_manager_set_child_value_hash(&log, "diff", diff_hash);
		tree_manager_set_child_value_hash(&log, "pow", rpow);
		tree_manager_set_child_value_hash(&log, "hash", bhash);
		log_message("----------------\nNEW POW BLOCK\n%diff%\n%pow%\n%hash%\n", &log);
		release_zone_ref(&log);
		return 1;
	}
	else
	{
		tree_manager_create_node("log", NODE_LOG_PARAMS, &log);
		tree_manager_set_child_value_hash(&log, "diff", diff_hash);
		tree_manager_set_child_value_hash(&log, "pow" , rpow);
		tree_manager_set_child_value_hash(&log, "hash", bhash);
		log_message("----------------\nBAD POW BLOCK\n%diff%\n%pow%\n%hash%\n", &log);
		release_zone_ref(&log);
		return 0;
	}
	
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

int remove_tx_index(hash_t tx_hash)
{
	char tchash[65];
	struct string tx_path = { 0 };
	unsigned char *buffer;
	size_t size;
	unsigned int ret, n;
	n = 0;
	while (n<32)
	{
		tchash[n * 2 + 0] = hex_chars[tx_hash[n] >> 4];
		tchash[n * 2 + 1] = hex_chars[tx_hash[n] & 0x0F];
		n++;
	}
	tchash[64] = 0;


	make_string(&tx_path, "txs");
	cat_ncstring_p(&tx_path, tchash + 0, 2);
	cat_ncstring_p(&tx_path, tchash + 2, 2);

	ret = get_file(tx_path.str, &buffer, &size);
	
	if (ret<=0){
		free_string(&tx_path);
		return 0;
	}

	ret = 0;
	n = 0;
	while (n<size)
	{
		if (!memcmp_c(&buffer[n], tx_hash, sizeof(hash_t)))
		{
			truncate_file	(tx_path.str, n, &buffer[n+64],size - (n + 64));
			ret = 1;
			break;
		}
		n += 64;
	}
	if (size>0)
	free_c(buffer);
	free_string(&tx_path);

	return ret;
}
int cancel_tx_inputs(mem_zone_ref_ptr tx)
{
	mem_zone_ref	 txin_list = { PTR_NULL }, my_list = { PTR_NULL };
	mem_zone_ref_ptr input = PTR_NULL;


	if (!tree_manager_find_child_node(tx, NODE_HASH("txsin"), NODE_BITCORE_VINLIST, &txin_list))return 0;

	for (tree_manager_get_first_child(&txin_list, &my_list, &input); ((input != NULL) && (input->zone != NULL)); tree_manager_get_next_child(&my_list, &input))
	{
		mem_zone_ref	 ptx = { PTR_NULL };
		hash_t			 prev_hash, pblk_hash;
		unsigned int	 oidx;

		tree_manager_get_child_value_hash(input, NODE_HASH("tx hash"), prev_hash);
		tree_manager_get_child_value_i32(input, NODE_HASH("idx"), &oidx);

		if (load_tx(&ptx, pblk_hash, prev_hash))
		{
			btc_addr_t		 out_addr = { 0 };
			mem_zone_ref	 vout = { PTR_NULL };
			struct string	  tx_path = { 0 };
			char			 pchash[65];
			int					n;

			if (get_tx_output(&ptx, oidx, &vout))
			{
				n = 0;
				while (n < 32)
				{
					pchash[n * 2 + 0] = hex_chars[prev_hash[n] >> 4];
					pchash[n * 2 + 1] = hex_chars[prev_hash[n] & 0x0F];
					n++;
				}
				pchash[64] = 0;

				make_string(&tx_path, "blks");
				cat_ncstring_p(&tx_path, pblk_hash + 0, 2);
				cat_ncstring_p(&tx_path, pblk_hash + 2, 2);
				cat_cstring_p(&tx_path, pblk_hash);
				cat_cstring_p(&tx_path, pchash);
				cat_cstring(&tx_path, "_out_");
				strcat_int(&tx_path, oidx);
				store_tx_vout(&tx_path, &vout, out_addr);
				free_string(&tx_path);
				release_zone_ref(&vout);
				cancel_spend_tx_addr(out_addr, pchash, oidx);
			}
			release_zone_ref(&ptx);
		}
	}
	release_zone_ref(&txin_list);

	return 1;
}

OS_API_C_FUNC(int) remove_block(hash_t blk_hash)
{
	char			chash[65];
	struct string	blk_path = { 0 }, blk_data_path = { 0 };
	struct string	dir_list = { PTR_NULL };
	unsigned char	*txs;
	size_t			len, ntx;
	int				n;
	const char		*ptr, *optr;
	size_t			cur, nfiles;

	n = 0;
	while (n<32)
	{
		chash[n * 2 + 0] = hex_chars[blk_hash[n] >> 4];
		chash[n * 2 + 1] = hex_chars[blk_hash[n] & 0x0F];
		n++;
	}
	chash[64] = 0;

	make_string		(&blk_path, "blks");
	cat_ncstring_p	(&blk_path, chash + 0, 2);
	cat_ncstring_p	(&blk_path, chash + 2, 2);
	cat_cstring_p	(&blk_path, chash);

	clone_string	(&blk_data_path,&blk_path);
	cat_cstring_p	(&blk_data_path, "txs");
	if (get_file(blk_data_path.str, &txs, &len)>=32)
	{
		ntx = 0;
		while (ntx < len)
		{
			remove_tx_index(&txs[ntx]);
			ntx += 32;
		}
	}
	free_string(&blk_data_path);

	nfiles = get_sub_files(blk_path.str, &dir_list);
	if (nfiles > 0)
	{
		unsigned int dir_list_len;

		dir_list_len = dir_list.len;
		optr = dir_list.str;
		cur = 0;
		while (cur < nfiles)
		{
			size_t			sz;

			ptr = memchr_c(optr, 10, dir_list_len);
			sz = mem_sub(optr, ptr);
	
			if (!strncmp_c(optr, "tx_", 3))
			{
				int		n=32;
				hash_t	tx_hash;
				mem_zone_ref tx = { PTR_NULL };

				while (n--)
				{
					char    hex[3];
					hex[0]		= optr[3 + n * 2 + 0];
					hex[1]		= optr[3 + n * 2 + 1];
					hex[2]		= 0;
					tx_hash[n]	= strtoul_c(hex, PTR_NULL, 16);
				}

				if (load_tx(&tx, blk_hash, tx_hash))
				{
					cancel_tx_inputs(&tx);
					release_zone_ref(&tx);
				}

				remove_tx_index(tx_hash);
			}
			cur++;
			optr = ptr + 1;
			dir_list_len -= sz;

		}
		dir_list_len = dir_list.len;
		optr = dir_list.str;
		cur = 0;
		while (cur < nfiles)
		{
			size_t			sz;
			ptr = memchr_c(optr, 10, dir_list_len);
			sz = mem_sub(optr, ptr);

			clone_string(&blk_data_path, &blk_path);
			cat_ncstring_p(&blk_data_path, optr, sz);
			del_file(blk_data_path.str);
			free_string(&blk_data_path);
			cur++;
			optr = ptr + 1;
			dir_list_len -= sz;
		}
		del_dir(blk_path.str);
		free_string(&blk_path);
		free_string(&dir_list);
	}

	return 1;
}
OS_API_C_FUNC(int) get_last_block_height()
{
	return file_size("blk_indexes") / 32;
}




OS_API_C_FUNC(int) store_block(mem_zone_ref_ptr header, mem_zone_ref_ptr tx_list)
{
	char				chash[65], tchash[65];
	mem_zone_ref_ptr	tx = PTR_NULL;
	mem_zone_ref		my_list = { PTR_NULL };
	size_t				length;
	uint64_t			height;
	mem_ptr				buffer;
	hash_t				blk_hash, pow;
	
	struct string		blk_path={0},blk_data_path={0};
	unsigned int		n,n_tx, nc, block_time;
	unsigned char		*blk_txs;

	if (!tree_manager_get_child_value_hash(header, NODE_HASH("blk hash"), blk_hash))return 0;

	n = 0;
	while (n<32)
	{
		chash[n * 2 + 0] = hex_chars[blk_hash[n] >> 4];
		chash[n * 2 + 1] = hex_chars[blk_hash[n] & 0x0F];
		n++;
	}
	chash[64] = 0;

	make_string		(&blk_path, "blks");
	cat_ncstring_p	(&blk_path, chash + 0, 2);
	create_dir		(blk_path.str);
	
	cat_ncstring_p	(&blk_path, chash + 2, 2);
	create_dir		(blk_path.str);
	
	cat_cstring_p	(&blk_path, chash);
	create_dir		(blk_path.str);

	if (tree_manager_get_child_value_i32(header, NODE_HASH("time"), &block_time))
		set_ftime(blk_path.str, block_time);
		
	length = compute_payload_size(header);
	buffer = malloc_c(length);

	write_node		(header, (unsigned char *)buffer);
	
	clone_string	(&blk_data_path, &blk_path);
	cat_cstring_p	(&blk_data_path, "header");
	put_file		(blk_data_path.str, buffer, length);
	free_string		(&blk_data_path);

	free_c			(buffer);

	height		= get_last_block_height();

	clone_string		(&blk_data_path, &blk_path);
	cat_cstring_p		(&blk_data_path, "height");
	put_file			(blk_data_path.str, &height, sizeof(uint64_t));
	free_string			(&blk_data_path);


	nc		=	tree_manager_get_node_num_children(tx_list);
	if (nc > 0)
	{
		blk_txs = calloc_c(sizeof(hash_t), nc);
		n		= 0;
		for (n_tx = 0, tree_manager_get_first_child(tx_list, &my_list, &tx); ((tx != NULL) && (tx->zone != NULL)); tree_manager_get_next_child(&my_list, &tx), n_tx++)
		{
			hash_t				tx_hash, tmp_hash;
			struct string		tx_path = { 0 };
			unsigned int		tx_time;

			length = get_node_size(tx);
			buffer = malloc_c(length);
			write_node(tx, (unsigned char *)buffer);

			if (!tree_manager_get_child_value_hash(tx, NODE_HASH("tx hash"), tx_hash))
			{
				mbedtls_sha256((unsigned char *)buffer, length, tmp_hash, 0);
				mbedtls_sha256(tmp_hash, 32, tx_hash, 0);
				tree_manager_set_child_value_hash(tx, "tx hash", tx_hash);
			}

			if (!tree_manager_get_child_value_i32(tx, NODE_HASH("time"), &tx_time))
			{
				tx_time = block_time;
			}

			memcpy_c		(&blk_txs[n_tx*32], tx_hash, 32);
			n = 0;
			while (n<32)
			{
				tchash[n * 2 + 0] = hex_chars[tx_hash[n] >> 4];
				tchash[n * 2 + 1] = hex_chars[tx_hash[n] & 0x0F];
				n++;
			}
			tchash[64] = 0;


			make_string		(&tx_path, "txs");
			cat_ncstring_p	(&tx_path, tchash + 0, 2);
			create_dir		(tx_path.str);

			cat_ncstring_p	(&tx_path, tchash + 2, 2);
			append_file		(tx_path.str, tx_hash , sizeof(hash_t));
			append_file		(tx_path.str, blk_hash, sizeof(hash_t));
			free_string		(&tx_path);
			
			clone_string	(&tx_path, &blk_path);
			cat_cstring_p	(&tx_path, "tx_");
			cat_cstring		(&tx_path, tchash);
			put_file		(tx_path.str, buffer, length);

			set_ftime		(tx_path.str, tx_time);

			free_string		(&tx_path);
			free_c			(buffer);

			if (is_tx_null(tx)==1)
				continue;
			
			store_tx_inputs(tx, tchash, 1);
			store_tx_outputs(chash, tx, tchash, 1);

			
		}

		clone_string	(&blk_data_path, &blk_path);
		cat_cstring_p	(&blk_data_path, "txs");
		put_file		(blk_data_path.str, blk_txs, n_tx*sizeof(hash_t));
		free_c			(blk_txs);
	}
	free_string(&blk_data_path);

	if (tree_manager_get_child_value_hash(header, NODE_HASH("blk pow"), pow))
	{
		clone_string	(&blk_data_path, &blk_path);
		cat_cstring_p	(&blk_data_path, "pow");
		put_file		(blk_data_path.str, pow, sizeof(hash_t));
		free_string		(&blk_data_path);
	}

	append_file("./blk_indexes", blk_hash, 32);

	free_string(&blk_path);

	return 1;
}

OS_API_C_FUNC(int) is_pow_block(const char *blk_hash)
{
	struct string file_path = { 0 };
	int stat, ret;

	make_string		(&file_path, "blks");
	cat_ncstring_p	(&file_path, blk_hash + 0, 2);
	cat_ncstring_p  (&file_path, blk_hash + 2, 2);
	cat_cstring_p	(&file_path, blk_hash);
	cat_cstring_p	(&file_path, "pow");
	stat = stat_file(file_path.str);
	free_string		(&file_path);

	ret = (stat == 0) ? 1 : 0;
	return ret;
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