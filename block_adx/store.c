//copyright antoine bentue-ferrer 2016
#include <base/std_def.h>
#include <base/std_mem.h>
#include <base/mem_base.h>
#include <base/std_str.h>

#include <sha256.h>
#define FORWARD_CRYPTO
#include <crypto.h>
#include <strs.h>
#include <tree.h>
#include <fsio.h>


#define BLOCK_API C_EXPORT
#include "block_api.h"

//protocol module

C_IMPORT size_t			C_API_FUNC	compute_payload_size(mem_zone_ref_ptr payload_node);
C_IMPORT char*			C_API_FUNC	write_node(mem_zone_ref_const_ptr key, unsigned char *payload);
C_IMPORT size_t			C_API_FUNC	get_node_size(mem_zone_ref_ptr key);
C_IMPORT void			C_API_FUNC	serialize_children(mem_zone_ref_ptr node, unsigned char *payload);
C_IMPORT const unsigned char*	C_API_FUNC read_node(mem_zone_ref_ptr key, const unsigned char *payload);
C_IMPORT size_t			C_API_FUNC init_node(mem_zone_ref_ptr key);

//local module
extern hash_t null_hash;

btc_addr_t				src_addr_list[1024] = { 0xABCDEF };

static __inline void make_blk_path(const char *chash, struct string *blk_path)
{

	make_string(blk_path, "./blks/");
	cat_ncstring(blk_path, chash + 0, 2);
	cat_cstring(blk_path, "/");
	cat_ncstring(blk_path, chash + 2, 2);
	cat_cstring(blk_path, "/");
	cat_cstring(blk_path, chash);
}

OS_API_C_FUNC(int) get_last_block_height()
{
	return file_size("blk_indexes") / 32;
}

OS_API_C_FUNC(int) get_moneysupply(uint64_t *amount)
{
	unsigned char *data;
	size_t len;
	int ret = 0;
	if (get_file("supply", &data, &len)>0)
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
	if (ret <= 0)return 0;

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
	cat_ncstring(&blk_path, file_name + 0, 2);
	cat_cstring(&blk_path, "/");
	cat_ncstring(&blk_path, file_name + 2, 2);
	cat_cstring(&blk_path, "/");
	cat_cstring(&blk_path, file_name);

	ret = (stat_file(blk_path.str) == 0) ? 1 : 0;

	free_string(&blk_path);
	return ret;
}

OS_API_C_FUNC(int) load_blk_hdr(mem_zone_ref_ptr hdr, const char *blk_hash)
{
	unsigned char		*hdr_data;
	size_t				hdr_data_len;
	struct string		blk_path = { PTR_NULL };
	int    ret = 0;

	make_string(&blk_path, "blks");
	cat_ncstring_p(&blk_path, blk_hash, 2);
	cat_ncstring_p(&blk_path, blk_hash + 2, 2);
	cat_cstring_p(&blk_path, blk_hash);
	cat_cstring_p(&blk_path, "header");

	if (get_file(blk_path.str, &hdr_data, &hdr_data_len) > 0)
	{
		if ((hdr->zone != PTR_NULL) || (tree_manager_create_node("blk", NODE_BITCORE_BLK_HDR, hdr)))
		{
			hash_t hash;
			int		n = 32;

			init_node(hdr);
			read_node(hdr, hdr_data);
			while (n--)
			{
				char    hex[3];
				hex[0] = blk_hash[n * 2 + 0];
				hex[1] = blk_hash[n * 2 + 1];
				hex[2] = 0;
				hash[n] = strtoul_c(hex, PTR_NULL, 16);
			}
			tree_manager_set_child_value_bhash(hdr, "blkHash", hash);
			ret = 1;
		}
		free_c(hdr_data);
	}
	free_string(&blk_path);

	return ret;
}


OS_API_C_FUNC(int) get_block_time(const char *blkHash, ctime_t *time)
{
	struct string blk_path = { 0 };
	int ret;

	make_string(&blk_path, "blks");
	cat_ncstring_p(&blk_path, blkHash + 0, 2);
	cat_ncstring_p(&blk_path, blkHash + 2, 2);
	cat_cstring_p(&blk_path, blkHash);
	cat_cstring_p(&blk_path, "header");

	ret = get_ftime(blk_path.str, time);
	free_string(&blk_path);

	return ret;
}


OS_API_C_FUNC(int) get_pow_block(const char *blk_hash, hash_t pow)
{
	unsigned char   *data;
	size_t			len;
	struct string file_path = { 0 };
	int ret = 0;

	make_string(&file_path, "blks");
	cat_ncstring_p(&file_path, blk_hash + 0, 2);
	cat_ncstring_p(&file_path, blk_hash + 2, 2);
	cat_cstring_p(&file_path, blk_hash);
	cat_cstring_p(&file_path, "pow");
	if (get_file(file_path.str, &data, &len) > 0)
	{
		if (len >= sizeof(hash_t))
		{
			memcpy_c(pow, data, sizeof(hash_t));
			ret = 1;
		}
		free_c(data);
	}

	free_string(&file_path);
	return ret;
}

OS_API_C_FUNC(int) is_pow_block(const char *blk_hash)
{
	struct string file_path = { 0 };
	int stat, ret;

	make_string(&file_path, "blks");
	cat_ncstring_p(&file_path, blk_hash + 0, 2);
	cat_ncstring_p(&file_path, blk_hash + 2, 2);
	cat_cstring_p(&file_path, blk_hash);
	cat_cstring_p(&file_path, "pow");
	stat = stat_file(file_path.str);
	free_string(&file_path);

	ret = (stat == 0) ? 1 : 0;
	return ret;
}


OS_API_C_FUNC(int) get_blk_sign(const char *blk_hash, struct string *sign)
{
	struct string blk_path = { PTR_NULL }, tx_path = { PTR_NULL };
	unsigned char *data;
	int ret = 0;
	size_t len;
	make_string(&blk_path, "blks");
	cat_ncstring_p(&blk_path, blk_hash + 0, 2);
	cat_ncstring_p(&blk_path, blk_hash + 2, 2);
	cat_cstring_p(&blk_path, blk_hash);
	cat_cstring_p(&blk_path, "signature");
	if (get_file(blk_path.str, &data, &len)>0)
	{
		sign->len = len;
		sign->size = sign->len + 1;
		sign->str = malloc_c(sign->size);
		memcpy_c(sign->str, data, len);
		sign->str[sign->len] = 0;
		free_c(data);
	}
	free_string(&blk_path);
	return ret;
}


OS_API_C_FUNC(int) get_blk_height(const char *blk_hash, uint64_t *height)
{
	struct string blk_path = { PTR_NULL }, tx_path = { PTR_NULL };
	unsigned char *data;
	int ret = 0;
	size_t len;
	make_string(&blk_path, "blks");
	cat_ncstring_p(&blk_path, blk_hash + 0, 2);
	cat_ncstring_p(&blk_path, blk_hash + 2, 2);
	cat_cstring_p(&blk_path, blk_hash);
	cat_cstring_p(&blk_path, "height");
	if (get_file(blk_path.str, &data, &len)>0)
	{
		if (len >= sizeof(uint64_t))
		{
			ret = 1;
			(*height) = *((uint64_t *)data);
		}
		free_c(data);
	}
	free_string(&blk_path);
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

	make_string(&blk_path, "blks");
	cat_ncstring_p(&blk_path, chash + 0, 2);
	cat_ncstring_p(&blk_path, chash + 2, 2);
	cat_cstring_p(&blk_path, chash);

	clone_string(&tx_path, &blk_path);
	cat_cstring_p(&tx_path, "header");
	get_ftime(tx_path.str, &ctime);
	(*block_time) = ctime;
	free_string(&tx_path);

	clone_string(&tx_path, &blk_path);
	cat_cstring_p(&tx_path, "tx_");
	cat_cstring(&tx_path, tchash);
	get_ftime(tx_path.str, &ctime);
	(*tx_time) = ctime;
	free_string(&tx_path);

	cat_cstring_p(&blk_path, "height");
	if (get_file(blk_path.str, &data, &len)>0)
	{
		if (len >= sizeof(uint64_t))
			(*height) = *((uint64_t *)data);
		free_c(data);
	}
	free_string(&blk_path);
	return 1;
}


OS_API_C_FUNC(int) blk_load_tx_hash(const char *blk_hash, const char *tx_hash, mem_zone_ref_ptr tx)
{
	struct string		tx_path = { 0 };
	unsigned char		*tx_data;
	size_t				tx_data_len;
	int					ret;

	make_string(&tx_path, "blks");
	cat_ncstring_p(&tx_path, blk_hash + 0, 2);
	cat_ncstring_p(&tx_path, blk_hash + 2, 2);
	cat_cstring_p(&tx_path, blk_hash);
	cat_cstring_p(&tx_path, "tx_");
	cat_cstring(&tx_path, tx_hash);

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
	free_string(&tx_path);

	return ret;
}


OS_API_C_FUNC(int) load_blk_tx(mem_zone_ref_ptr tx, const char *blk_hash, unsigned int tx_idx)
{
	struct string blk_path = { 0 };
	int		n, ret = 0;
	unsigned char *tx_list;
	unsigned int  txs_len;


	make_string(&blk_path, "blks");
	cat_ncstring_p(&blk_path, blk_hash + 0, 2);
	cat_ncstring_p(&blk_path, blk_hash + 2, 2);
	cat_cstring_p(&blk_path, blk_hash);
	cat_cstring_p(&blk_path, "txs");
	if (get_file(blk_path.str, &tx_list, &txs_len) >0)
	{
		if (((tx_idx + 1) * 32) <= txs_len)
		{
			char tchash[65];
			n = 0;
			while (n<32)
			{
				tchash[n * 2 + 0] = hex_chars[tx_list[tx_idx * 32 + n] >> 4];
				tchash[n * 2 + 1] = hex_chars[tx_list[tx_idx * 32 + n] & 0x0F];
				n++;
			}
			tchash[64] = 0;
			ret = blk_load_tx_hash(blk_hash, tchash, tx);
		}
		free_c(tx_list);
	}
	free_string(&blk_path);
	return ret;
}


OS_API_C_FUNC(int) load_tx(mem_zone_ref_ptr tx, hash_t blk_hash, const hash_t tx_hash)
{
	char				chash[65], cthash[65];

	struct string		tx_path = { 0 };
	unsigned char		*buffer;
	mem_size			size;
	int					ret = 0;

	unsigned int		n = 32;

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
	if (ret <= 0)return 0;

	ret = 0;
	n = 0;
	while (n<size)
	{
		if (!memcmp_c(&buffer[n], tx_hash, sizeof(hash_t)))
		{
			int nn;
			nn = 0;
			while (nn<32)
			{
				blk_hash[nn] = buffer[n + 32 + nn];
				chash[nn * 2 + 0] = hex_chars[blk_hash[nn] >> 4];
				chash[nn * 2 + 1] = hex_chars[blk_hash[nn] & 0x0F];
				nn++;
			}
			chash[64] = 0;
			ret = 1;
			break;
		}
		n += 64;
	}
	free_c(buffer);
	if (!ret)
		return 0;

	ret = blk_load_tx_hash(chash, cthash, tx);
	return ret;
}

OS_API_C_FUNC(int) load_tx_addresses(btc_addr_t addr, mem_zone_ref_ptr tx_hashes)
{
	btc_addr_t null_addr = { 0 };
	unsigned char *data;
	size_t len;
	struct string tx_file = { 0 };

	memset_c(null_addr, '0', sizeof(btc_addr_t));

	make_string(&tx_file, "adrs");
	cat_ncstring_p(&tx_file, &addr[31], 2);
	if (get_file(tx_file.str, &data, &len) > 0)
	{
		size_t idx_sz, n = 0, idx = 0;
		uint64_t ftx, ttx, ntx = 0, aidx;
		unsigned char *first_tx;

		ttx = 0;
		while (n < len)
		{
			if (!memcmp_c(&data[n], null_addr, sizeof(btc_addr_t)))
				break;


			if (!memcmp_c(&data[n], addr, sizeof(btc_addr_t)))
			{
				ftx = ttx;
				ntx = *((uint64_t *)(data + n + sizeof(btc_addr_t)));
				aidx = idx;
			}

			ttx += *((uint64_t *)(data + n + sizeof(btc_addr_t)));
			n += sizeof(btc_addr_t) + sizeof(uint64_t);
			idx++;
		}

		if (ntx>0)
		{
			int nn;
			idx_sz = idx*(sizeof(btc_addr_t) + sizeof(uint64_t)) + sizeof(btc_addr_t);
			first_tx = data + idx_sz + ftx*sizeof(hash_t);
			nn = 0;
			while (nn < ntx)
			{
				mem_zone_ref new_hash = { PTR_NULL };
				uint64_t  height,time, tx_time;

				if (get_tx_blk_height(first_tx + nn*sizeof(hash_t), &height, &time, &tx_time))
				{
					if (tree_manager_add_child_node(tx_hashes, "tx", NODE_BITCORE_HASH, &new_hash))
					{
						tree_manager_write_node_hash(&new_hash, 0, first_tx + nn*sizeof(hash_t));
						release_zone_ref(&new_hash);
					}
				}
				nn++;
			}
		}
		free_c(data);
	}

	free_string(&tx_file);
	return 0;
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
	ret_addr = get_out_script_address(&script, PTR_NULL, out_addr);
	free_string(&script);

	memcpy_c(bbuffer, &amount, sizeof(uint64_t));
	memcpy_c(bbuffer + sizeof(uint64_t), out_addr, sizeof(btc_addr_t));
	put_file(out_path->str, bbuffer, sizeof(uint64_t) + sizeof(btc_addr_t));

	return ret_addr;
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


	//open index file for the hash
	make_string(&tx_path, "txs");
	cat_ncstring_p(&tx_path, tchash + 0, 2);
	cat_ncstring_p(&tx_path, tchash + 2, 2);

	if (get_file(tx_path.str, &buffer, &size) <= 0)
	{
		//not in the index
		free_string(&tx_path);
		return 0;
	}

	ret = 0;
	n = 0;
	while (n<size)
	{
		if (!memcmp_c(&buffer[n], tx_hash, sizeof(hash_t)))
		{
			truncate_file(tx_path.str, n, &buffer[n + 64], size - (n + 64));
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


OS_API_C_FUNC(int) remove_tx_addresses(const btc_addr_t addr, const hash_t tx_hash)
{
	btc_addr_t		null_addr;
	struct string   tx_file = { 0 };
	size_t			len;
	unsigned char  *data;

	memset_c(null_addr, '0', sizeof(btc_addr_t));

	/*open the address index file*/
	make_string(&tx_file, "adrs");
	cat_ncstring_p(&tx_file, &addr[31], 2);
	if (get_file(tx_file.str, &data, &len)>0)
	{
		size_t		idx_sz, tx_list_ofs, ftidx;
		size_t		n = 0, idx = 0;
		uint64_t	ftx, ttx, cntx = 0, ntx = 0, aidx;
		unsigned char *first_tx;

		ttx = 0;
		while ((n + sizeof(btc_addr_t)) <= len)
		{

			/*address is not in the index*/
			if (!memcmp_c(&data[n], null_addr, sizeof(btc_addr_t)))
				break;

			cntx = *((uint64_t *)(data + n + sizeof(btc_addr_t)));

			/*address is in the index at current position*/
			if (!memcmp_c(&data[n], addr, sizeof(btc_addr_t)))
			{
				/*position of the first transaction for this address*/
				ftx = ttx;

				/*number of transactions for this address*/
				ntx = cntx;

				/*index of the address*/
				aidx = idx;
			}

			//index of the first transaction of the next address
			ttx += cntx;

			//next address in the index
			n += sizeof(btc_addr_t) + sizeof(uint64_t);
			idx++;
		}



		//check transaction from the address
		if (ntx > 0)
		{
			//position of the end of address list
			idx_sz = idx*(sizeof(btc_addr_t) + sizeof(uint64_t));


			//position of the first_transaction
			tx_list_ofs = idx_sz + sizeof(btc_addr_t);

			//position of the first tx for the address
			first_tx = data + tx_list_ofs + ftx * sizeof(hash_t);

			//find the transaction in the address index
			n = 0;
			while (n < ntx)
			{
				if (!memcmp_c(first_tx + n*sizeof(hash_t), tx_hash, sizeof(hash_t)))
				{
					uint64_t	*addr_ntx_ptr;
					size_t		next_tx_pos;

					addr_ntx_ptr = (uint64_t	*)(data + aidx*(sizeof(btc_addr_t) + sizeof(uint64_t)) + sizeof(btc_addr_t));
					*addr_ntx_ptr = ntx - 1;

					//position of the transaction to remove in the index
					ftidx = (ftx + n)*sizeof(hash_t);
					next_tx_pos = tx_list_ofs + ftidx + sizeof(hash_t);
					//write the new address index and transaction up to the one to remove
					put_file("newfile", data, tx_list_ofs + ftidx);

					//write transactions in the index after the one to remove
					append_file("newfile", data + next_tx_pos, len - next_tx_pos);


					//write the new index in the file
					del_file(tx_file.str);
					move_file("newfile", tx_file.str);
					break;
				}
				n++;
			}
		}
		free_c(data);
	}
	free_string(&tx_file);
	return 1;
}


int cancel_tx_outputs(mem_zone_ref_ptr tx, hash_t tx_hash, hash_t blk_hash)
{
	mem_zone_ref	    txout_list = { PTR_NULL }, my_list = { PTR_NULL };
	mem_zone_ref_ptr    output = PTR_NULL;
	unsigned int		oidx;

	if (!tree_manager_find_child_node(tx, NODE_HASH("txsout"), NODE_BITCORE_VOUTLIST, &txout_list))return 0;

	for (oidx = 0, tree_manager_get_first_child(&txout_list, &my_list, &output); ((output != NULL) && (output->zone != NULL)); tree_manager_get_next_child(&my_list, &output), oidx++)
	{

		char			 chash[65], tchash[65];
		struct string	 tx_path = { PTR_NULL };
		int				 n;
		/*
		btc_addr_t		 out_addr;
		struct string	 pubk = { PTR_NULL }, script = { PTR_NULL };
		uint64_t		 amount;

		tree_manager_get_child_value_i64(output, NODE_HASH("value"), &amount);
		tree_manager_get_child_value_istr(output, NODE_HASH("script"), &script, 0);
		if (get_out_script_address(&script, &pubk, out_addr))
		{
			cancel_unspend_tx_addr(out_addr, tx_hash, oidx);
			remove_tx_staking(out_addr, tx_hash);
			remove_tx_addresses(out_addr, tx_hash);
			if (pubk.str != PTR_NULL)
				free_string(&pubk);
		}
		free_string(&script);
		*/
		n = 0;
		while (n<32)
		{
			chash[n * 2 + 0] = hex_chars[blk_hash[n] >> 4];
			chash[n * 2 + 1] = hex_chars[blk_hash[n] & 0x0F];

			tchash[n * 2 + 0] = hex_chars[tx_hash[n] >> 4];
			tchash[n * 2 + 1] = hex_chars[tx_hash[n] & 0x0F];
			n++;
		}
		chash[64] = 0;
		tchash[64] = 0;

		make_string(&tx_path, "blks");
		cat_ncstring_p(&tx_path, chash + 0, 2);
		cat_ncstring_p(&tx_path, chash + 2, 2);
		cat_cstring_p(&tx_path, chash);
		cat_cstring_p(&tx_path, tchash);
		cat_cstring(&tx_path, "_out_");
		strcat_int(&tx_path, oidx);
		del_file(tx_path.str);
		free_string(&tx_path);
	}
	release_zone_ref(&txout_list);
	return 1;
}

OS_API_C_FUNC(int) cancel_tx_inputs(mem_zone_ref_ptr tx, hash_t tx_hash)
{
	mem_zone_ref	 txin_list = { PTR_NULL }, my_list = { PTR_NULL };
	mem_zone_ref_ptr input = PTR_NULL;


	if (!tree_manager_find_child_node(tx, NODE_HASH("txsin"), NODE_BITCORE_VINLIST, &txin_list))return 0;

	//process tx inputs
	for (tree_manager_get_first_child(&txin_list, &my_list, &input); ((input != NULL) && (input->zone != NULL)); tree_manager_get_next_child(&my_list, &input))
	{
		mem_zone_ref	 ptx = { PTR_NULL };
		hash_t			 prev_hash, pblk_hash;
		unsigned int	 oidx;

		tree_manager_get_child_value_hash(input, NODE_HASH("txid"), prev_hash);
		tree_manager_get_child_value_i32(input, NODE_HASH("idx"), &oidx);


		/*load the transaction with the spent output*/
		if (load_tx(&ptx, pblk_hash, prev_hash))
		{
			char			 pchash[65];
			char			 pblk_chash[65];
			btc_addr_t		 out_addr;
			struct string	 script = { PTR_NULL }, pubk = { PTR_NULL };
			mem_zone_ref	 vout = { PTR_NULL };
			struct string	 tx_path = { 0 };
			int			  	 n;

			memset_c(out_addr, '0', sizeof(btc_addr_t));

			/*load the spent output from the parent transaction*/
			if (get_tx_output(&ptx, oidx, &vout))
			{
				n = 0;
				while (n < 32)
				{
					pchash[n * 2 + 0] = hex_chars[prev_hash[n] >> 4];
					pchash[n * 2 + 1] = hex_chars[prev_hash[n] & 0x0F];

					pblk_chash[n * 2 + 0] = hex_chars[pblk_hash[n] >> 4];
					pblk_chash[n * 2 + 1] = hex_chars[pblk_hash[n] & 0x0F];

					n++;
				}
				pchash[64] = 0;
				pblk_chash[64] = 0;


				/*rewrite the original tx out from the parent transaction*/
				make_string(&tx_path, "blks");
				cat_ncstring_p(&tx_path, pblk_chash + 0, 2);
				cat_ncstring_p(&tx_path, pblk_chash + 2, 2);
				cat_cstring_p(&tx_path, pblk_chash);
				cat_cstring_p(&tx_path, pchash);
				cat_cstring(&tx_path, "_out_");
				strcat_int(&tx_path, oidx);
				store_tx_vout(&tx_path, &vout, out_addr);
				free_string(&tx_path);
				release_zone_ref(&vout);

				/*
				//cancel the spent in the wallet
				cancel_spend_tx_addr(out_addr, pchash, oidx);

				//remove tx from the address index
				remove_tx_addresses(out_addr, tx_hash);
				*/
			}
			release_zone_ref(&ptx);
		}
	}
	release_zone_ref(&txin_list);
	return 1;
}

OS_API_C_FUNC(int) get_block_size(const char *blk_hash, size_t *size)
{

	struct string	blk_path = { 0 }, blk_data_path = { 0 };
	struct string	dir_list = { PTR_NULL };
	unsigned char	*txs;
	size_t			len;


	make_string(&blk_path, "blks");
	cat_ncstring_p(&blk_path, blk_hash + 0, 2);
	cat_ncstring_p(&blk_path, blk_hash + 2, 2);
	cat_cstring_p(&blk_path, blk_hash);
	clone_string(&blk_data_path, &blk_path);
	cat_cstring_p(&blk_data_path, "header");
	*size = file_size(blk_data_path.str) - 24;
	free_string(&blk_data_path);

	if (size == 0)
	{
		free_string(&blk_path);
		return 0;
	}

	clone_string(&blk_data_path, &blk_path);
	cat_cstring_p(&blk_data_path, "txs");
	if (get_file(blk_data_path.str, &txs, &len) >0)
	{
		unsigned int cur = 0;
		free_string(&blk_data_path);
		while (cur < len)
		{
			char			chash[65];
			int				n;
			n = 0;
			while (n<32)
			{
				chash[n * 2 + 0] = hex_chars[txs[cur + n] >> 4];
				chash[n * 2 + 1] = hex_chars[txs[cur + n] & 0x0F];
				n++;
			}
			chash[64] = 0;

			clone_string(&blk_data_path, &blk_path);
			cat_cstring_p(&blk_data_path, "tx_");
			cat_cstring(&blk_data_path, chash);
			*size += file_size(blk_data_path.str);
			cur += 32;
			free_string(&blk_data_path);
		}
		free_c(txs);
	}
	free_string(&blk_data_path);
	free_string(&blk_path);

	return 1;
}

OS_API_C_FUNC(unsigned int) get_blk_ntxs(const char* blk_hash)
{
	struct string	blk_path = { 0 };
	size_t			ntx;

	make_string(&blk_path, "blks");
	cat_ncstring_p(&blk_path, blk_hash + 0, 2);
	cat_ncstring_p(&blk_path, blk_hash + 2, 2);
	cat_cstring_p(&blk_path, blk_hash);
	cat_cstring_p(&blk_path, "txs");
	ntx = file_size(blk_path.str) / sizeof(hash_t);
	free_string(&blk_path);
	return ntx;
}

OS_API_C_FUNC(int) get_blk_tx_hash(const char* blk_hash, unsigned int idx, hash_t tx_hash)
{
	struct string	blk_path = { 0 };
	unsigned char	*ptxs;
	size_t			len;
	int				ret = 0;
	make_string(&blk_path, "blks");
	cat_ncstring_p(&blk_path, blk_hash + 0, 2);
	cat_ncstring_p(&blk_path, blk_hash + 2, 2);
	cat_cstring_p(&blk_path, blk_hash);
	cat_cstring_p(&blk_path, "txs");
	if (get_file(blk_path.str, &ptxs, &len) >0)
	{
		if (((idx + 1) * 32) <= len)
		{
			memcpy_c(tx_hash, &ptxs[idx * 32], sizeof(hash_t));
			ret = 1;
		}

		free_c(ptxs);
	}
	free_string(&blk_path);
	return ret;
}

OS_API_C_FUNC(int) get_blk_txs(const char* blk_hash, mem_zone_ref_ptr txs, size_t max)
{
	struct string	blk_path = { 0 };
	unsigned char	*ptxs;
	size_t			len, ntx;

	make_string(&blk_path, "blks");
	cat_ncstring_p(&blk_path, blk_hash + 0, 2);
	cat_ncstring_p(&blk_path, blk_hash + 2, 2);
	cat_cstring_p(&blk_path, blk_hash);
	cat_cstring_p(&blk_path, "txs");
	if (get_file(blk_path.str, &ptxs, &len) >0)
	{
		ntx = 0;
		while (ntx < len)
		{
			mem_zone_ref tx = { PTR_NULL };
			tree_manager_add_child_node(txs, "tx", NODE_BITCORE_HASH, &tx);
			tree_manager_write_node_hash(&tx, 0, &ptxs[ntx]);
			release_zone_ref(&tx);
			ntx += 32;
		}
		free_c(ptxs);
	}
	free_string(&blk_path);

	return 1;
}


OS_API_C_FUNC(int) load_blk_txs(const char* blk_hash, mem_zone_ref_ptr txs)
{
	struct string	blk_path = { 0 };
	unsigned char	*ptxs;
	size_t			len, ntx;



	make_string(&blk_path, "blks");
	cat_ncstring_p(&blk_path, blk_hash + 0, 2);
	cat_ncstring_p(&blk_path, blk_hash + 2, 2);
	cat_cstring_p(&blk_path, blk_hash);
	cat_cstring_p(&blk_path, "txs");
	if (get_file(blk_path.str, &ptxs, &len) >0)
	{
		ntx = 0;
		while (ntx < len)
		{
			hash_t bh;
			mem_zone_ref tx = { PTR_NULL };

			load_tx(&tx, bh, &ptxs[ntx]);
			tree_manager_node_add_child(txs, &tx);
			release_zone_ref(&tx);
			ntx += 32;
		}
		free_c(ptxs);
	}
	free_string(&blk_path);

	return 1;
}



OS_API_C_FUNC(int) remove_tx(hash_t tx_hash)
{
	hash_t			blk_hash;
	int				n = 32;
	mem_zone_ref	tx = { PTR_NULL };

	/*load transaction data from the block*/
	if (load_tx(&tx, blk_hash, tx_hash))
	{
		/*cancel transaction on wallet*/
		cancel_tx_outputs(&tx, tx_hash, blk_hash);

		cancel_tx_inputs(&tx, tx_hash);

		release_zone_ref(&tx);
	}
	/*remove transaction from global index*/
	remove_tx_index(tx_hash);

	return 1;
}




OS_API_C_FUNC(int) store_block_height(const char *hash, uint64_t height)
{
	struct string		blk_path = { 0 };
	int ret;

	make_string(&blk_path, "blks");
	cat_ncstring_p(&blk_path, hash + 0, 2);
	cat_ncstring_p(&blk_path, hash + 2, 2);
	cat_cstring_p(&blk_path, hash);
	cat_cstring_p(&blk_path, "height");
	ret = put_file(blk_path.str, &height, sizeof(uint64_t));
	free_string(&blk_path);

	return ret;
}



OS_API_C_FUNC(int) clear_tx_index()
{
	struct string	dir_list = { PTR_NULL }, tx_path = { PTR_NULL };
	size_t			cur, nfiles;

	nfiles = get_sub_dirs("txs", &dir_list);
	if (nfiles > 0)
	{
		const char		*ptr, *optr;
		unsigned int	dir_list_len;

		dir_list_len = dir_list.len;
		optr = dir_list.str;
		cur = 0;
		while (cur < nfiles)
		{
			struct string	txp = { PTR_NULL };
			size_t			sz;

			ptr = memchr_c(optr, 10, dir_list_len);
			sz = mem_sub(optr, ptr);

			make_string(&txp, "txs");
			cat_ncstring_p(&txp, optr, sz);
			rm_dir(txp.str);
			free_string(&txp);

			cur++;
			optr = ptr + 1;
			dir_list_len -= sz;
		}
	}
	free_string(&dir_list);
	return 1;
}



OS_API_C_FUNC(int) store_tx_blk_index(const hash_t tx_hash, const hash_t blk_hash)
{
	char			tchash[65];
	struct string	tx_path = { 0 };
	int n;
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
	create_dir(tx_path.str);
	cat_ncstring_p(&tx_path, tchash + 2, 2);

	append_file(tx_path.str, tx_hash, sizeof(hash_t));
	append_file(tx_path.str, blk_hash, sizeof(hash_t));
	free_string(&tx_path);

	return 1;
}



OS_API_C_FUNC(int) store_tx_inputs(mem_zone_ref_ptr tx)
{
	hash_t			 thash;
	char			 tx_hash[65];
	struct string	 tx_path = { 0 };
	mem_zone_ref	 txin_list = { PTR_NULL }, my_list = { PTR_NULL };
	mem_zone_ref_ptr input = PTR_NULL;
	unsigned int	 vin;
	int				 n;

	if (!tree_manager_find_child_node(tx, NODE_HASH("txsin"), NODE_BITCORE_VINLIST, &txin_list))return 0;
	
	if (!tree_manager_get_child_value_hash(tx, NODE_HASH("txid"), thash))
	{
		compute_tx_hash						(tx, thash);
		tree_manager_set_child_value_hash	(tx, "txid", thash);
	}

	n = 0;
	while (n<32)
	{
		tx_hash[n * 2 + 0] = hex_chars[thash[n] >> 4];
		tx_hash[n * 2 + 1] = hex_chars[thash[n] & 0x0F];

		n++;
	}
	tx_hash[64] = 0;
	
	for (vin = 0, tree_manager_get_first_child(&txin_list, &my_list, &input); ((input != NULL) && (input->zone != NULL)); tree_manager_get_next_child(&my_list, &input), vin++)
	{
		char			chash[65], ptchash[65];
		hash_t			blk_hash, prev_hash = { 0 };
		struct string	out_path = { 0 };
		int				sret, n;
		unsigned int	 oidx;
		tree_manager_get_child_value_hash(input, NODE_HASH("txid"), prev_hash);
		tree_manager_get_child_value_i32(input, NODE_HASH("idx"), &oidx);

		if (!memcmp_c(prev_hash, null_hash, sizeof(hash_t)))
		{
			btc_addr_t coinbase;
			memset_c(coinbase, '0', sizeof(btc_addr_t));
			tree_manager_set_child_value_btcaddr(input, "srcaddr", coinbase);
			continue;
		}
		if (!find_blk_hash(prev_hash, blk_hash))continue;

		n = 0;
		while (n<32)
		{
			chash[n * 2 + 0] = hex_chars[blk_hash[n] >> 4];
			chash[n * 2 + 1] = hex_chars[blk_hash[n] & 0x0F];

			ptchash[n * 2 + 0] = hex_chars[prev_hash[n] >> 4];
			ptchash[n * 2 + 1] = hex_chars[prev_hash[n] & 0x0F];
			n++;
		}
		chash[64] = 0;
		ptchash[64] = 0;

		make_string(&out_path, "blks");
		cat_ncstring_p(&out_path, chash + 0, 2);
		cat_ncstring_p(&out_path, chash + 2, 2);
		cat_cstring_p(&out_path, chash);
		cat_cstring_p(&out_path, ptchash);
		cat_cstring(&out_path, "_out_");
		strcat_int(&out_path, oidx);

		sret = stat_file(out_path.str);
		if (sret == 0)
		{
			char *buffer;
			size_t len;
			if (get_file(out_path.str, &buffer, &len))
			{
				if (len >= (sizeof(uint64_t) + sizeof(btc_addr_t)))
				{
					tree_manager_set_child_value_i64		(input, "amount", *((uint64_t *)(buffer)));
					tree_manager_set_child_value_btcaddr	(input, "srcaddr", buffer + sizeof(uint64_t));
					store_tx_addresses						(buffer + sizeof(uint64_t), thash);
				}
				free_c(buffer);
			}
			del_file(out_path.str);
		}
		free_string(&out_path);
	}
	release_zone_ref(&txin_list);
	return 1;
}



OS_API_C_FUNC(int) store_tx_addresses(btc_addr_t addr, hash_t tx_hash)
{
	btc_addr_t null_addr = { 0 };
	unsigned char *data;
	size_t len;
	struct string tx_file = { 0 };

	memset_c(null_addr, '0', sizeof(btc_addr_t));
	make_string(&tx_file, "adrs");
	cat_ncstring_p(&tx_file, &addr[31], 2);
	if (get_file(tx_file.str, &data, &len)>0)
	{
		size_t idx_sz, ftidx;
		size_t n = 0, idx = 0;
		uint64_t ftx, ttx, ntx = 0, aidx;
		unsigned char *first_tx;

		ttx = 0;
		while (n < len)
		{
			if (!memcmp_c(&data[n], null_addr, sizeof(btc_addr_t)))
				break;

			if (!memcmp_c(&data[n], addr, sizeof(btc_addr_t)))
			{
				ftx = ttx;
				ntx = *((uint64_t *)(data + n + sizeof(btc_addr_t)));
				aidx = idx;
			}
			ttx += *((uint64_t *)(data + n + sizeof(btc_addr_t)));
			n += sizeof(btc_addr_t) + sizeof(uint64_t);
			idx++;
		}
		idx_sz = idx*(sizeof(btc_addr_t) + sizeof(uint64_t));
		if (ntx > 0)
		{
			int fnd = 0;

			first_tx = data + idx_sz + sizeof(btc_addr_t) + ftx*sizeof(hash_t);
			n = 0;
			while (n < ntx)
			{
				if (!memcmp_c(first_tx + n*sizeof(hash_t), tx_hash, sizeof(hash_t)))
				{
					fnd = 1;
					break;
				}
				n++;
			}
			if (!fnd)
			{
				*((uint64_t *)(data + aidx*(sizeof(btc_addr_t) + sizeof(uint64_t)) + sizeof(btc_addr_t))) = ntx + 1;
				ftidx = (ftx + ntx)*sizeof(hash_t);
				put_file("newfile", data, idx_sz + sizeof(btc_addr_t) + ftidx);
				append_file("newfile", tx_hash, sizeof(hash_t));
				append_file("newfile", data + idx_sz + sizeof(btc_addr_t) + ftidx, len - (idx_sz + ftidx + sizeof(btc_addr_t)));
				del_file(tx_file.str);
				move_file("newfile", tx_file.str);
			}
		}
		else
		{
			uint64_t one = 1;

			put_file("newfile", data, idx_sz);
			append_file("newfile", addr, sizeof(btc_addr_t));
			append_file("newfile", &one, sizeof(uint64_t));
			append_file("newfile", data + idx_sz, len - (idx_sz));
			append_file("newfile", tx_hash, sizeof(hash_t));
			del_file(tx_file.str);
			move_file("newfile", tx_file.str);
		}

	}
	else
	{
		size_t s = sizeof(btc_addr_t) * 2 + sizeof(uint64_t);
		data = malloc_c(s);

		memcpy_c(data, addr, sizeof(btc_addr_t));
		*((uint64_t *)(data + sizeof(btc_addr_t))) = 1;
		memset_c(data + sizeof(btc_addr_t) + sizeof(uint64_t), '0', sizeof(btc_addr_t));
		put_file(tx_file.str, data, s);
		free_c(data);

		append_file(tx_file.str, tx_hash, sizeof(hash_t));
	}

	free_c(data);
	free_string(&tx_file);
	return 1;

}

OS_API_C_FUNC(int) store_tx_index(const char * blk_hash, mem_zone_ref_ptr tx, hash_t thash)
{

	char				tx_hash[65];
	mem_zone_ref		txout_list = { PTR_NULL }, txin_list = { PTR_NULL }, my_list = { PTR_NULL };
	mem_zone_ref_ptr	out = PTR_NULL, input = PTR_NULL;
	unsigned int		oidx, n_in_addr, vin;
	btc_addr_t			nulladdr;
	int					n;


	if (!tree_manager_find_child_node(tx, NODE_HASH("txsout"), NODE_BITCORE_VOUTLIST, &txout_list))return 0;
	if (!tree_manager_find_child_node(tx, NODE_HASH("txsin"), NODE_BITCORE_VINLIST, &txin_list)){ release_zone_ref(&txout_list); return 0; }

	memset_c(nulladdr, '0', sizeof(btc_addr_t));
	n = 0;
	while (n<32)
	{
		tx_hash[n * 2 + 0] = hex_chars[thash[n] >> 4];
		tx_hash[n * 2 + 1] = hex_chars[thash[n] & 0x0F];
		n++;
	}
	tx_hash[64] = 0;
	n_in_addr = 0;

	for (vin = 0, tree_manager_get_first_child(&txin_list, &my_list, &input); ((input != NULL) && (input->zone != NULL)); tree_manager_get_next_child(&my_list, &input), vin++)
	{
		hash_t			blk_hash, prev_hash = { 0 };
		btc_addr_t		prev_addr;
		mem_zone_ref	prev_tx = { PTR_NULL }, vout = { PTR_NULL };
		unsigned int	oidx;
		tree_manager_get_child_value_hash(input, NODE_HASH("txid"), prev_hash);
		if (!memcmp_c(prev_hash, null_hash, sizeof(hash_t)))
		{
			tree_manager_set_child_value_btcaddr(input, "srcaddr", nulladdr);
			continue;
		}
		if (!load_tx(&prev_tx, blk_hash, prev_hash))continue;

		tree_manager_get_child_value_i32(input, NODE_HASH("idx"), &oidx);
		if (get_tx_output(&prev_tx, oidx, &vout))
		{
			struct string   oscript;
			init_string(&oscript);
			tree_manager_get_child_value_istr(&vout, NODE_HASH("script"), &oscript, 0);

			if (get_out_script_address(&oscript, PTR_NULL, prev_addr)>0)
				store_tx_addresses(prev_addr, thash);

			release_zone_ref(&vout);
			free_string(&oscript);
		}
		release_zone_ref(&prev_tx);
	}

	for (oidx = 0, tree_manager_get_first_child(&txout_list, &my_list, &out); ((out != NULL) && (out->zone != NULL)); oidx++, tree_manager_get_next_child(&my_list, &out))
	{
		btc_addr_t		out_addr;
		struct string   oscript;

		init_string(&oscript);

		tree_manager_get_child_value_istr(out, NODE_HASH("script"), &oscript, 0);

		if (get_out_script_address(&oscript, PTR_NULL, out_addr)>0)
			store_tx_addresses(out_addr, thash);

		free_string(&oscript);

	}

	release_zone_ref(&txout_list);
	release_zone_ref(&txin_list);
	return 1;
}

OS_API_C_FUNC(int) store_tx_outputs(mem_zone_ref_ptr tx,const char * blk_hash)
{
	hash_t				thash;
	char				tx_hash[65];
	
	mem_zone_ref		txout_list = { PTR_NULL }, txin_list = { PTR_NULL }, my_list = { PTR_NULL };
	mem_zone_ref_ptr	out = PTR_NULL, in = PTR_NULL;
	unsigned int		oidx;
	btc_addr_t			nulladdr;
	int					n;
	
	memset_c(nulladdr, '0', sizeof(btc_addr_t));

	if (!tree_manager_get_child_value_hash(tx, NODE_HASH("txid"), thash))
	{
		compute_tx_hash						(tx, thash);
		tree_manager_set_child_value_hash	(tx, "txid", thash);
	}


	n = 0;
	while (n<32)
	{
		tx_hash[n * 2 + 0] = hex_chars[thash[n] >> 4];
		tx_hash[n * 2 + 1] = hex_chars[thash[n] & 0x0F];
		n++;
	}
	tx_hash[64] = 0;

	if (tree_manager_find_child_node(tx, NODE_HASH("txsout"), NODE_BITCORE_VOUTLIST, &txout_list))
	{
		struct string tx_path = { 0 };


		make_string		(&tx_path, "blks");
		cat_ncstring_p	(&tx_path, blk_hash + 0, 2);
		cat_ncstring_p	(&tx_path, blk_hash + 2, 2);
		cat_cstring_p	(&tx_path, blk_hash);

		for (oidx = 0, tree_manager_get_first_child(&txout_list, &my_list, &out); ((out != NULL) && (out->zone != NULL)); oidx++, tree_manager_get_next_child(&my_list, &out))
		{
			btc_addr_t		out_addr = { 0 };
			struct string	out_path = { 0 };
			uint64_t		amount = 0;
			int				ret;

			clone_string		(&out_path, &tx_path);
			cat_cstring_p		(&out_path, tx_hash);
			cat_cstring			(&out_path, "_out_");
			strcat_int			(&out_path, oidx);

			ret = store_tx_vout	(&out_path, out, out_addr);
			free_string			(&out_path);
			if (ret)ret = store_tx_addresses(out_addr, thash);
		}
		free_string(&tx_path);
	}
	
	release_zone_ref(&txout_list);
	return 1;
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

	struct string		signature = { 0 }, blk_path = { 0 }, blk_data_path = { 0 };
	unsigned int		n, n_tx, nc, block_time;
	unsigned char		*blk_txs;

	if (!tree_manager_get_child_value_hash(header, NODE_HASH("blkHash"), blk_hash))return 0;

	n = 0;
	while (n<32)
	{
		chash[n * 2 + 0] = hex_chars[blk_hash[n] >> 4];
		chash[n * 2 + 1] = hex_chars[blk_hash[n] & 0x0F];
		n++;
	}
	chash[64] = 0;

	make_string(&blk_path, "blks");
	cat_ncstring_p(&blk_path, chash + 0, 2);
	create_dir(blk_path.str);

	cat_ncstring_p(&blk_path, chash + 2, 2);
	create_dir(blk_path.str);

	cat_cstring_p(&blk_path, chash);
	create_dir(blk_path.str);



	length = compute_payload_size(header);
	buffer = malloc_c(length);

	write_node(header, (unsigned char *)buffer);

	clone_string(&blk_data_path, &blk_path);
	cat_cstring_p(&blk_data_path, "header");
	put_file(blk_data_path.str, buffer, length);

	if (tree_manager_get_child_value_i32(header, NODE_HASH("time"), &block_time))
		set_ftime(blk_data_path.str, block_time);

	free_string(&blk_data_path);
	free_c(buffer);

	height = get_last_block_height() + 1;

	clone_string(&blk_data_path, &blk_path);
	cat_cstring_p(&blk_data_path, "height");
	put_file(blk_data_path.str, &height, sizeof(uint64_t));
	free_string(&blk_data_path);


	nc = tree_manager_get_node_num_children(tx_list);
	if (nc > 0)
	{
		blk_txs = calloc_c(sizeof(hash_t), nc);
		n = 0;
		for (n_tx = 0, tree_manager_get_first_child(tx_list, &my_list, &tx); ((tx != NULL) && (tx->zone != NULL)); tree_manager_get_next_child(&my_list, &tx), n_tx++)
		{
			hash_t				tx_hash, tmp_hash;
			struct string		tx_path = { 0 };
			unsigned int		tx_time;

			length = get_node_size(tx);
			buffer = malloc_c(length);
			write_node(tx, (unsigned char *)buffer);

			if (!tree_manager_get_child_value_hash(tx, NODE_HASH("txid"), tx_hash))
			{
				mbedtls_sha256((unsigned char *)buffer, length, tmp_hash, 0);
				mbedtls_sha256(tmp_hash, 32, tx_hash, 0);
				tree_manager_set_child_value_hash(tx, "txid", tx_hash);
			}

			if (!tree_manager_get_child_value_i32(tx, NODE_HASH("time"), &tx_time))
			{
				tx_time = block_time;
			}

			memcpy_c(&blk_txs[n_tx * 32], tx_hash, 32);
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
			create_dir(tx_path.str);

			cat_ncstring_p(&tx_path, tchash + 2, 2);
			append_file(tx_path.str, tx_hash, sizeof(hash_t));
			append_file(tx_path.str, blk_hash, sizeof(hash_t));
			free_string(&tx_path);

			clone_string(&tx_path, &blk_path);
			cat_cstring_p(&tx_path, "tx_");
			cat_cstring(&tx_path, tchash);
			put_file(tx_path.str, buffer, length);

			set_ftime(tx_path.str, tx_time);

			free_string(&tx_path);
			free_c(buffer);

			if (is_tx_null(tx) == 1)
				continue;

			store_tx_inputs		(tx);
			store_tx_outputs	(tx,chash);
		}

		clone_string	(&blk_data_path, &blk_path);
		cat_cstring_p	(&blk_data_path, "txs");
		put_file		(blk_data_path.str, blk_txs, n_tx*sizeof(hash_t));
		free_c			(blk_txs);
	}
	free_string(&blk_data_path);

	if (tree_manager_get_child_value_hash(header, NODE_HASH("blk pow"), pow))
	{
		clone_string(&blk_data_path, &blk_path);
		cat_cstring_p(&blk_data_path, "pow");
		put_file(blk_data_path.str, pow, sizeof(hash_t));
		free_string(&blk_data_path);
	}
	if (tree_manager_get_child_value_istr(header, NODE_HASH("signature"), &signature, 0))
	{
		if (signature.len > 0)
		{
			clone_string(&blk_data_path, &blk_path);
			cat_cstring_p(&blk_data_path, "signature");
			put_file(blk_data_path.str, signature.str, signature.len);
			free_string(&blk_data_path);
		}
		free_string(&signature);
	}
	free_string(&blk_path);

	return 1;
}


