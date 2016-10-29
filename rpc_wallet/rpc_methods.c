//copyright iadix 2016
#include <base/std_def.h>
#include <base/std_mem.h>
#include <base/mem_base.h>
#include <base/std_str.h>

#include <strs.h>
#include <tree.h>
#include <fsio.h>
#include <mem_stream.h>
#include <tpo_mod.h>



typedef int  C_API_FUNC get_blk_staking_infos_func(mem_zone_ref_ptr blk, const char *blk_hash, mem_zone_ref_ptr infos);
typedef get_blk_staking_infos_func *get_blk_staking_infos_func_ptr;


#ifdef _DEBUG
C_IMPORT int					C_API_FUNC get_blk_staking_infos(mem_zone_ref_ptr blk, const char *blk_hash, mem_zone_ref_ptr infos);
get_blk_staking_infos_func_ptr  _get_blk_staking_infos = PTR_INVALID;
#else
get_blk_staking_infos_func_ptr  get_blk_staking_infos = PTR_INVALID;
#endif

//get_blk_staking_infos_func_ptr  get_blk_staking_infos = PTR_INVALID;

C_IMPORT int			C_API_FUNC	is_pow_block(const char *blk_hash);
C_IMPORT int			C_API_FUNC	 get_blk_height(const char *blk_hash, uint64_t *height);
C_IMPORT int			C_API_FUNC	  get_blk_txs(const char* blk_hash, mem_zone_ref_ptr txs);
C_IMPORT int			C_API_FUNC load_blk_hdr(mem_zone_ref_ptr hdr, const char *blk_hash);
C_IMPORT int			C_API_FUNC	get_block_size(const char *blk_hash, size_t *size);
C_IMPORT int			C_API_FUNC	 get_pow_block(const char *blk_hash, hash_t pos);
C_IMPORT int			C_API_FUNC	SetCompact(unsigned int bits, hash_t out);
C_IMPORT int			C_API_FUNC get_last_block_height();
C_IMPORT int			C_API_FUNC get_moneysupply(uint64_t *amount);
C_IMPORT int			C_API_FUNC  load_tx_addresses(btc_addr_t addr, mem_zone_ref_ptr tx_hashes);
C_IMPORT int			C_API_FUNC   load_tx(mem_zone_ref_ptr tx, hash_t blk_hash, const hash_t tx_hash);
C_IMPORT int			C_API_FUNC get_tx_blk_height(const hash_t tx_hash, uint64_t *height, uint64_t *block_time, uint64_t *tx_time);
C_IMPORT int			C_API_FUNC compute_block_hash(mem_zone_ref_ptr block, hash_t hash);
C_IMPORT int			C_API_FUNC  get_in_script_address(struct string *script, btc_addr_t addr);
C_IMPORT int			C_API_FUNC   get_out_script_address(struct string *script, struct string *pubk, btc_addr_t addr);
C_IMPORT int			C_API_FUNC    load_tx_input(mem_zone_ref_const_ptr tx, unsigned int idx, mem_zone_ref_ptr	vin, mem_zone_ref_ptr tx_out);
C_IMPORT int			C_API_FUNC     get_tx_output(mem_zone_ref_const_ptr tx, unsigned int idx, mem_zone_ref_ptr vout);
C_IMPORT int			C_API_FUNC      get_tx_input(mem_zone_ref_const_ptr tx, unsigned int idx, mem_zone_ref_ptr vout);
unsigned int			WALLET_VERSION = 60000;
mem_zone_ref			my_node = { PTR_INVALID };


OS_API_C_FUNC(int) set_node(mem_zone_ref_ptr node,tpo_mod_file *pos_mod)
{
	my_node.zone = PTR_NULL;
	copy_zone_ref(&my_node, node);

	
#ifdef _DEBUG
	_get_blk_staking_infos = get_tpo_mod_exp_addr_name(pos_mod, "get_blk_staking_infos", 0);
#else
	get_blk_staking_infos = get_tpo_mod_exp_addr_name(pos_mod, "get_blk_staking_infos", 0);
#endif
	
	//get_blk_staking_infos = get_tpo_mod_exp_addr_name(pos_mod, "get_blk_staking_infos", 0);
	return 1;
}


int list_unspent(btc_addr_t addr, mem_zone_ref_ptr unspents,unsigned int max)
{
	struct string		unspent_path = { 0 };
	unsigned int		n;
	unsigned int		dir_list_len;
	struct string		dir_list = { PTR_NULL };
	const char			*ptr, *optr;
	size_t				cur, nfiles;
	uint64_t			sheight;

	make_string(&unspent_path, "adrs");
	cat_ncstring_p(&unspent_path, addr, 34);
	cat_cstring_p(&unspent_path, "unspent");

	if (stat_file(unspent_path.str) != 0)
	{
		free_string(&unspent_path);
		return 0;
	}

	sheight = get_last_block_height();

	nfiles = get_sub_files(unspent_path.str, &dir_list);

	dir_list_len = dir_list.len;
	optr = dir_list.str;
	cur = 0;
	while (cur < nfiles)
	{
		struct string	tx_path = { 0 };
		unsigned int	output = 0xFFFFFFFF;
		size_t			sz, len;
		unsigned char	*data;

		if (cur >= max)
			break;

		ptr = memchr_c(optr, 10, dir_list_len);
		sz = mem_sub(optr, ptr);


		clone_string(&tx_path, &unspent_path);
		cat_ncstring_p(&tx_path, optr, sz);

		if (get_file(tx_path.str, &data, &len)>0)
		{
			if (optr[64] == '_')
				output = strtoul_c(&optr[65], PTR_NULL, 10);
			else
				output = 0xFFFFFFFF;

			if (len >= sizeof(uint64_t))
			{
				mem_zone_ref unspent = { PTR_NULL };
				if (tree_manager_add_child_node(unspents, "unspent", NODE_GFX_OBJECT, &unspent))
				{
					hash_t		hash;
					uint64_t	height, block_time, tx_time, nconf;
					unsigned int n_addrs;
					n = 0;
					while (n<32)
					{
						char    hex[3];
						hex[0] = optr[n * 2 + 0];
						hex[1] = optr[n * 2 + 1];
						hex[2] = 0;
						hash[n] = strtoul_c(hex, PTR_NULL, 16);
						n++;
					}

					if (get_tx_blk_height(hash, &height, &block_time, &tx_time))
						nconf = sheight - height;
					else
					{
						block_time = 0;
						tx_time = 0;
						nconf = 0;
					}

					tree_manager_set_child_value_hash(&unspent, "txid", hash);
					tree_manager_set_child_value_i32(&unspent, "vout", output);
					tree_manager_set_child_value_i64(&unspent, "amount", *((uint64_t*)data));

					tree_manager_set_child_value_i32(&unspent, "time", tx_time);
					tree_manager_set_child_value_i64(&unspent, "confirmations", nconf);

					len -= sizeof(uint64_t);
					if (len > 4)
					{
						n_addrs = *((unsigned int *)(data + sizeof(uint64_t)));
						if (n_addrs > 0)
						{
							mem_zone_ref addr_list = { PTR_NULL };

							if (tree_manager_add_child_node(&unspent, "addresses", NODE_JSON_ARRAY, &addr_list))
							{
								mem_ptr addrs;
								addrs = data + sizeof(uint64_t) + sizeof(unsigned int);
								for (n = 0; n < n_addrs; n++)
								{
									mem_zone_ref new_addr = { PTR_NULL };
									if (tree_manager_add_child_node(&addr_list, "address", NODE_BITCORE_WALLET_ADDR, &new_addr))
									{
										tree_manager_write_node_btcaddr(&new_addr, 0, addrs);
										release_zone_ref(&new_addr);
									}
									addrs = mem_add(addrs, sizeof(btc_addr_t));
								}
								release_zone_ref(&addr_list);
							}
						}
					}
					release_zone_ref(&unspent);
				}
			}
			free_c(data);
		}
		free_string(&tx_path);

		cur++;
		optr = ptr + 1;
		dir_list_len -= sz;
	}
	free_string(&dir_list);

	return 1;
}


int find_mem_hash(hash_t hash, unsigned char *mem_hash, unsigned int num)
{
	unsigned int n = 0;
	if (num == 0)return 0;
	if (mem_hash == PTR_NULL)return 0;
	while (n<(num * 32))
	{
		if (!memcmp_c(&mem_hash[n], hash, sizeof(hash_t)))
			return 1;
		n += 32;
	}
	return 0;
}

int find_stake_hash(hash_t hash, unsigned char *stakes, unsigned int len)
{
	unsigned int n = 0;
	if (len == 0)return 0;
	if (stakes == PTR_NULL)return 0;
	while (n<len)
	{
		if (!memcmp_c(&stakes[n + 8], hash, sizeof(hash_t)))
			return 1;
		n += 40;
	}
	return 0;
}
int list_spent(btc_addr_t addr, mem_zone_ref_ptr spents)
{
	struct string		spent_path = { 0 };
	unsigned int		dir_list_len;
	struct string		dir_list = { PTR_NULL };
	const char			*ptr, *optr;
	size_t				len_stakes;
	unsigned char		*stakes;
	size_t				cur, nfiles;
	uint64_t			sheight;
	struct string		stake_path = { 0 };

	make_string(&spent_path, "adrs");
	cat_ncstring_p(&spent_path, addr, 34);
	cat_cstring_p(&spent_path, "spent");

	if (stat_file(spent_path.str) != 0)
	{
		free_string(&spent_path);
		return 0;
	}

	sheight = get_last_block_height();


	make_string(&stake_path, "adrs");
	cat_ncstring_p(&stake_path, addr, 34);
	cat_cstring_p(&stake_path, "stakes");
	get_file(stake_path.str, &stakes, &len_stakes);
	free_string(&stake_path);

	/*
	make_string		(&stake_path, "adrs");
	cat_ncstring_p	(&stake_path, addr, 34);
	cat_cstring_p	(&stake_path, "stake");
	*/

	nfiles = get_sub_files(spent_path.str, &dir_list);

	dir_list_len = dir_list.len;
	optr = dir_list.str;
	cur = 0;
	while (cur < nfiles)
	{
		struct string	tx_path = { 0 };
		unsigned int	vin = 0xFFFFFFFF;
		unsigned int	prev_out = 0xFFFFFFFF;
		size_t			sz, len;
		unsigned char	*data;

		ptr = memchr_c(optr, 10, dir_list_len);
		sz = mem_sub(optr, ptr);

		clone_string(&tx_path, &spent_path);
		cat_ncstring_p(&tx_path, optr, sz);
		if (get_file(tx_path.str, &data, &len) > 0)
		{
			if (optr[64] == '_')
				prev_out = strtoul_c(&optr[65], PTR_NULL, 10);
			else
				prev_out = 0xFFFFFFFF;

			if (len >= sizeof(uint64_t))
			{
				hash_t		  hash;
				unsigned int  n_in_addr;
				unsigned char *cdata;
				mem_zone_ref spent = { PTR_NULL };

				cdata = data + sizeof(uint64_t);
				n_in_addr = *((unsigned int *)(cdata));
				cdata += sizeof(unsigned int) + n_in_addr*sizeof(btc_addr_t);
				memcpy_c(hash, cdata, sizeof(hash_t));
				cdata += sizeof(hash_t);
				vin = *((unsigned int *)(cdata));
				cdata += sizeof(unsigned int);

				/*
				char chash[65];
				n = 0;
				while (n<32)
				{
				chash[n * 2 + 0] = hex_chars[hash[n] >> 4];
				chash[n * 2 + 1] = hex_chars[hash[n] & 0x0F];
				n++;
				}
				chash[64] = 0;
				free_string(&tx_path);
				clone_string(&tx_path, &stake_path);
				cat_cstring_p(&tx_path, chash);
				sRet = stat_file(tx_path.str) == 0 ? 1 : 0;
				free_string(&tx_path);
				if (!sRet)
				*/
				if (!find_stake_hash(hash, stakes, len_stakes))
				{
					if (tree_manager_add_child_node(spents, "spent", NODE_GFX_OBJECT, &spent))
					{
						mem_zone_ref  addr_list = { PTR_NULL };
						uint64_t	  height, tx_time, block_time, nconf;

						if (get_tx_blk_height(hash, &height, &block_time, &tx_time))
							nconf = sheight - height;
						else
						{
							block_time = 0;
							tx_time = 0;
							nconf = 0;
						}

						tree_manager_set_child_value_hash(&spent, "txid", hash);
						tree_manager_set_child_value_i32(&spent, "vin", vin);
						tree_manager_set_child_value_i64(&spent, "amount", *((uint64_t*)data));
						tree_manager_set_child_value_i32(&spent, "time", tx_time);
						tree_manager_set_child_value_i64(&spent, "confirmations", nconf);


						if (tree_manager_add_child_node(&spent, "addresses", NODE_JSON_ARRAY, &addr_list))
						{
							while (cdata < (data + len))
							{
								mem_zone_ref new_addr = { PTR_NULL };
								if (tree_manager_add_child_node(&addr_list, "address", NODE_BITCORE_WALLET_ADDR, &new_addr))
								{
									tree_manager_write_node_btcaddr(&new_addr, 0, cdata);
									release_zone_ref(&new_addr);
								}
								cdata = mem_add(cdata, sizeof(btc_addr_t));
							}
							release_zone_ref(&addr_list);
						}
						release_zone_ref(&spent);
					}
				}
			}
			free_c(data);
		}
		free_string(&tx_path);
		cur++;
		optr = ptr + 1;
		dir_list_len -= sz;
	}

	free_c(stakes);
	free_string(&dir_list);
	free_string(&spent_path);
	return 1;
}


int list_received(btc_addr_t addr, uint64_t *amount, mem_zone_ref_ptr received)
{
	btc_addr_t			null_addr;
	mem_zone_ref		my_list = { PTR_NULL };
	mem_zone_ref_ptr	ptx = PTR_NULL;
	struct string		unspent_path = { 0 };
	struct string		spent_path = { 0 };
	struct string		stake_path = { 0 };
	unsigned int		dir_list_len;
	struct string		dir_list = { PTR_NULL };
	uint64_t			sheight;
	const char			*ptr, *optr;
	size_t				cur, nfiles,nStakes;
	size_t				len_stakes;
	unsigned char		*stakes = PTR_NULL;
	//unsigned char		*mem_trans = PTR_NULL;


	memset_c(null_addr, '0', sizeof(btc_addr_t));

	sheight = get_last_block_height();

	make_string		(&unspent_path, "adrs");
	cat_ncstring_p	(&unspent_path, addr, 34);

	clone_string	(&spent_path, &unspent_path);
	clone_string	(&stake_path, &unspent_path);
	cat_cstring_p	(&spent_path, "spent");
	cat_cstring_p	(&stake_path, "stakes");
	cat_cstring_p	(&unspent_path, "unspent");

	*amount = 0;

	if (get_file(stake_path.str, &stakes, &len_stakes))
	{
		nStakes = len_stakes / 40;
		cur = 0;
		while (cur < len_stakes)
		{
			*amount += *((uint64_t*)(stakes + cur));

			if (received != PTR_NULL)
			{
				mem_zone_ref recv = { PTR_NULL };
				if (tree_manager_add_child_node(received, "recv", NODE_GFX_OBJECT, &recv))
				{
					mem_zone_ref addr_list = { PTR_NULL };
					uint64_t	height, block_time, tx_time, nconf;

					if (get_tx_blk_height(&stakes[cur + 8], &height, &block_time, &tx_time))
						nconf = sheight - height;
					else
					{
						tx_time = 0;
						block_time = 0;
						nconf = 0;
					}

					tree_manager_set_child_value_hash(&recv, "txid", &stakes[cur + 8]);
					tree_manager_set_child_value_i64(&recv, "amount", *((uint64_t*)(stakes + cur)));
					tree_manager_set_child_value_i32(&recv, "time", tx_time);
					tree_manager_set_child_value_i64(&recv, "confirmations", nconf);
					if (tree_manager_add_child_node(&recv, "addresses", NODE_JSON_ARRAY, &addr_list))
					{
						mem_zone_ref new_addr = { PTR_NULL };
						if (tree_manager_add_child_node(&addr_list, "address", NODE_BITCORE_WALLET_ADDR, &new_addr))
						{
							tree_manager_write_node_btcaddr(&new_addr, 0, addr);
							release_zone_ref(&new_addr);
						}
						release_zone_ref(&addr_list);
					}
					release_zone_ref(&recv);
				}
			}
			cur += 40;
		}
	}
	else
	{
		len_stakes = 0;
		nStakes = 0;
	}
	free_string(&stake_path);

	nfiles = get_sub_files(unspent_path.str, &dir_list);

	dir_list_len = dir_list.len;
	optr = dir_list.str;
	cur = 0;
	while (cur < nfiles)
	{
		hash_t			hash;
		struct string	tx_path = { 0 };
		unsigned int	output = 0xFFFFFFFF;
		int				n;
		size_t			sz, len;
		unsigned char	*data;

		ptr = memchr_c(optr, 10, dir_list_len);
		sz = mem_sub(optr, ptr);

		n = 0;
		while (n < 32)
		{
			char    hex[3];
			hex[0] = optr[n * 2 + 0];
			hex[1] = optr[n * 2 + 1];
			hex[2] = 0;
			hash[n] = strtoul_c(hex, PTR_NULL, 16);
			n++;
		}

		if (!find_stake_hash(hash, stakes, len_stakes))
		{
			if (optr[64] == '_')
				output = strtoul_c(&optr[65], PTR_NULL, 10);

			clone_string(&tx_path, &unspent_path);
			cat_ncstring_p(&tx_path, optr, sz);

			if (get_file(tx_path.str, &data, &len)>0)
			{
				if (len >= sizeof(uint64_t))
					*amount += *((uint64_t*)data);

				if (received != PTR_NULL)
				{
					mem_zone_ref recv = { PTR_NULL };
					if (tree_manager_add_child_node(received, "recv", NODE_GFX_OBJECT, &recv))
					{
						hash_t		 hash;
						uint64_t	 height, block_time, tx_time, nconf;
						unsigned int n;
						unsigned int n_addrs;
						n = 0;
						while (n < 32)
						{
							char    hex[3];
							hex[0] = optr[n * 2 + 0];
							hex[1] = optr[n * 2 + 1];
							hex[2] = 0;
							hash[n] = strtoul_c(hex, PTR_NULL, 16);
							n++;
						}


						if (get_tx_blk_height(hash, &height, &block_time, &tx_time))
							nconf = sheight - height;
						else
						{
							block_time = 0;
							tx_time = 0;
							nconf = 0;
						}

						tree_manager_set_child_value_hash(&recv, "txid", hash);
						tree_manager_set_child_value_i64(&recv, "amount", *((uint64_t*)data));
						tree_manager_set_child_value_i32(&recv, "time", tx_time);
						tree_manager_set_child_value_i64(&recv, "confirmations", nconf);


						n_addrs = *((unsigned int *)(data + sizeof(uint64_t)));
						if (n_addrs > 0)
						{
							mem_zone_ref addr_list = { PTR_NULL };

							if (tree_manager_add_child_node(&recv, "addresses", NODE_JSON_ARRAY, &addr_list))
							{
								mem_ptr addrs;
								addrs = data + sizeof(uint64_t) + sizeof(unsigned int);
								for (n = 0; n < n_addrs; n++)
								{
									mem_zone_ref new_addr = { PTR_NULL };
									if (tree_manager_add_child_node(&addr_list, "address", NODE_BITCORE_WALLET_ADDR, &new_addr))
									{
										tree_manager_write_node_btcaddr(&new_addr, 0, addrs);
										release_zone_ref(&new_addr);
									}
									addrs = mem_add(addrs, sizeof(btc_addr_t));
								}
								release_zone_ref(&addr_list);
							}
						}

						release_zone_ref(&recv);
					}
				}
				free_c(data);
			}
			free_string(&tx_path);
		}
		cur++;
		optr = ptr + 1;
		dir_list_len -= sz;
	}
	free_string(&dir_list);
	nfiles = get_sub_files(spent_path.str, &dir_list);

	dir_list_len = dir_list.len;
	optr = dir_list.str;
	cur = 0;
	while (cur < nfiles)
	{
		hash_t			hash;
		struct string	tx_path = { 0 };
		int				n;
		size_t			sz, len;
		unsigned char	*data;

		ptr = memchr_c(optr, 10, dir_list_len);
		sz = mem_sub(optr, ptr);

		n = 0;
		while (n < 32)
		{
			char    hex[3];
			hex[0] = optr[n * 2 + 0];
			hex[1] = optr[n * 2 + 1];
			hex[2] = 0;
			hash[n] = strtoul_c(hex, PTR_NULL, 16);
			n++;
		}
		if (!find_stake_hash(hash, stakes, len_stakes))
		{
			unsigned int prev_output;

			clone_string(&tx_path, &spent_path);
			cat_ncstring_p(&tx_path, optr, sz);

			if (optr[64] == '_')
				prev_output = strtoul_c(&optr[65], PTR_NULL, 10);

			if (get_file(tx_path.str, &data, &len)>0)
			{
				if (len >= sizeof(uint64_t))
					*amount += *((uint64_t*)data);

				if (received != PTR_NULL)
				{
					mem_zone_ref recv = { PTR_NULL };
					if (tree_manager_add_child_node(received, "recv", NODE_GFX_OBJECT, &recv))
					{
						mem_zone_ref addr_list = { PTR_NULL };
						unsigned int n_in_addr, vin;
						hash_t		 hash;
						uint64_t	 height, block_time, tx_time, nconf;
						unsigned int  n;
						unsigned char *cdata;

						cdata = data + sizeof(uint64_t);
						n_in_addr = *((unsigned int *)(cdata));
						cdata += sizeof(unsigned int);
						if (tree_manager_add_child_node(&recv, "addresses", NODE_JSON_ARRAY, &addr_list))
						{
							for (n = 0; n < n_in_addr; n++)
							{
								mem_zone_ref new_addr = { PTR_NULL };
								if (tree_manager_add_child_node(&addr_list, "address", NODE_BITCORE_WALLET_ADDR, &new_addr))
								{
									tree_manager_write_node_btcaddr(&new_addr, 0, cdata);
									release_zone_ref(&new_addr);
								}
								cdata = mem_add(cdata, sizeof(btc_addr_t));
							}
							release_zone_ref(&addr_list);
						}
						memcpy_c(hash, cdata, sizeof(hash_t));
						cdata += sizeof(hash_t);
						vin = *((unsigned int *)(cdata));
						cdata += sizeof(unsigned int);

						if (get_tx_blk_height(hash, &height, &block_time, &tx_time))
							nconf = sheight - height;
						else
						{
							block_time = 0;
							tx_time = 0;
							nconf = 0;
						}

						tree_manager_set_child_value_hash(&recv, "txid", hash);
						tree_manager_set_child_value_i64(&recv, "amount", *((uint64_t*)data));
						tree_manager_set_child_value_i32(&recv, "time", tx_time);
						tree_manager_set_child_value_i64(&recv, "confirmations", nconf);

						release_zone_ref(&recv);
					}
				}
				free_c(data);
			}
		}
		free_string(&tx_path);
		cur++;
		optr = ptr + 1;
		dir_list_len -= sz;
	}
	free_string(&unspent_path);
	free_string(&dir_list);
	free_string(&stake_path);

	if (stakes!=PTR_NULL)
		free_c(stakes);
	return 1;

}



OS_API_C_FUNC(int) getaddressscanstatus(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{
	btc_addr_t			new_addr;
	mem_zone_ref		addr = { PTR_NULL };
	struct string		adr_path = { 0 };
	unsigned char		*data;
	size_t				len;
	unsigned int		scanning, block;

	if (!tree_manager_get_child_at(params, 0, &addr))return 0;
	if (!tree_manager_get_node_btcaddr(&addr, 0, new_addr))
	{
		release_zone_ref(&addr);
		return 0;
	}
	release_zone_ref(&addr);

	make_string   (&adr_path, "adrs");
	cat_ncstring_p(&adr_path, new_addr, 34);
	cat_cstring_p  (&adr_path, "scanning");
	scanning = (stat_file(adr_path.str) == 0) ? 1 : 0;
	tree_manager_set_child_value_i32(result, "scanning", scanning);

	if (get_file(adr_path.str, &data, &len) > 0)
	{
		block = *((unsigned int *)(data));
		free_c(data);
	}
	else
		block = 0;
	tree_manager_set_child_value_i32(result, "block", block);

	free_string(&adr_path);
	
	return 1;
}
double GetDifficulty(unsigned int nBits)
{
	int nShift   = (nBits >> 24) & 0xff;
	double dDiff = (double)0x0000ffff / (double)(nBits & 0x00ffffff);

	while (nShift < 29)
	{
		dDiff *= 256.0;
		nShift++;
	}
	while (nShift > 29)
	{
		dDiff /= 256.0;
		nShift--;
	}

	return dDiff;
}

OS_API_C_FUNC(int) getlastblock(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{
	mem_zone_ref last_blk = { PTR_NULL };


	if (tree_manager_find_child_node(&my_node, NODE_HASH("last block"), NODE_BITCORE_BLK_HDR, &last_blk))
	{
		mem_zone_ref txs = { PTR_NULL };
		char   chash[65];
		hash_t hash, merkle, proof, nullhash, rdiff,hdiff,prev;
		size_t size;
		unsigned int version, time, bits, nonce;
		uint64_t height;

		memset_c(nullhash, 0, sizeof(hash_t));

		if (!tree_manager_get_child_value_hash(&last_blk, NODE_HASH("blk_hash"), hash))
		{
			compute_block_hash(&last_blk, hash);
			tree_manager_set_child_value_hash(&last_blk, "blk_hash", hash);
		}

		tree_manager_get_child_value_str(&last_blk, NODE_HASH("blk_hash"), chash, 65, 16);
		tree_manager_get_child_value_hash(&last_blk, NODE_HASH("merkle_root"), merkle);
		tree_manager_get_child_value_hash(&last_blk, NODE_HASH("prev"), prev);
		tree_manager_get_child_value_i32(&last_blk, NODE_HASH("version"), &version);
		tree_manager_get_child_value_i32(&last_blk, NODE_HASH("time"), &time);
		tree_manager_get_child_value_i32(&last_blk, NODE_HASH("bits"), &bits);
		tree_manager_get_child_value_i32(&last_blk, NODE_HASH("nonce"), &nonce);
		
		if (!get_block_size(chash, &size))
			size = 0;

		get_blk_height(chash, &height);

		if (is_pow_block(chash))
		{
			SetCompact							(bits, hdiff);
			get_pow_block						(chash, proof);
			tree_manager_set_child_value_hash	(result, "proofhash", proof);
			tree_manager_set_child_value_hash	(result, "hbits", rdiff);
		}
		else if (get_blk_staking_infos)
			get_blk_staking_infos(&last_blk, chash, result);

		tree_manager_set_child_value_hash(result, "hash", hash);
		tree_manager_set_child_value_i32(result , "confirmations", 0);
		tree_manager_set_child_value_i32(result , "size", size);
		tree_manager_set_child_value_i64(result , "height", height);
		tree_manager_set_child_value_i32(result, "time", time);
		tree_manager_set_child_value_i32(result, "version", version);
		tree_manager_set_child_value_i32(result, "bits", bits);
		tree_manager_set_child_value_i32(result, "nonce", nonce);
		tree_manager_set_child_value_hash(result, "merkleroot", merkle);
		tree_manager_set_child_value_hash(result, "previousblockhash", prev);
		tree_manager_set_child_value_hash(result, "nextblockhash", nullhash);
		tree_manager_set_child_value_float(result, "difficulty", GetDifficulty(bits));
		tree_manager_add_child_node(result, "txs", NODE_JSON_ARRAY,&txs);
		get_blk_txs(chash, &txs);
		release_zone_ref(&txs);
			/*
			"mint" : 0.00000000,
			"blocktrust" : "100001",
			"chaintrust" : "100001",
			"nextblockhash" : "af49672bafd39e39f8058967a2cce926a9b21db14c452a7883fba63a78a611a6",
			"flags" : "proof-of-work stake-modifier",
			"entropybit" : 0,
			*/
		return 1;
	}

	return 0;
}

OS_API_C_FUNC(int) getinfo(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{
	char	ip[32];
	mem_zone_ref addr_node = { PTR_NULL }, difficulty = { PTR_NULL };
	uint64_t balance = 0, paytxfee = 0, services = 0, last_blk = 0, supply = 0;
	hash_t posd, powd;
	unsigned int PROTOCOL_VERSION, p2p_status;
	unsigned int pow_diff=0, pos_diff=0;
	short int port;

	last_blk = get_last_block_height();

	if (tree_manager_find_child_node(&my_node, NODE_HASH("p2p_addr"), NODE_BITCORE_ADDR, &addr_node))
	{
		tree_manager_get_child_value_str(&addr_node, NODE_HASH("addr"), ip,32,0);
		tree_manager_get_child_value_i16(&addr_node, NODE_HASH("port"), &port);
		tree_manager_get_child_value_i64(&addr_node, NODE_HASH("services"), &services);
		release_zone_ref(&addr_node);
	}
	
	get_moneysupply(&supply);
	tree_manager_get_child_value_i32(&my_node, NODE_HASH("version"), &PROTOCOL_VERSION);
	tree_manager_get_child_value_i32(&my_node, NODE_HASH("p2p_status"), &p2p_status);
	tree_manager_get_child_value_i64(&my_node, NODE_HASH("paytxfee"), &paytxfee);

	if (tree_manager_get_child_value_i32(&my_node, NODE_HASH("current pos diff"), &pos_diff))
		SetCompact(pos_diff, posd);
	
	if(tree_manager_get_child_value_i32(&my_node, NODE_HASH("current pow diff"), &pow_diff))
		SetCompact(pow_diff, powd);


	tree_manager_add_child_node(result, "difficulty", NODE_GFX_OBJECT,&difficulty);
	tree_manager_set_child_value_float(&difficulty, "pow", GetDifficulty(pow_diff));
	tree_manager_set_child_value_hash(&difficulty, "hpow", powd);
	tree_manager_set_child_value_float(&difficulty, "pos", GetDifficulty(pos_diff));
	tree_manager_set_child_value_hash(&difficulty, "hpos", posd);

	release_zone_ref(&difficulty);

	tree_manager_set_child_value_str(result, "version", "purenode v0.1");
	tree_manager_set_child_value_i32(result, "protocolversion", PROTOCOL_VERSION);
	tree_manager_set_child_value_i32(result, "walletversion", WALLET_VERSION);
	tree_manager_set_child_value_i64(result, "paytxfee", paytxfee);
	tree_manager_set_child_value_i64(result, "mininput", 0);
	tree_manager_set_child_value_i64(result, "moneysupply", supply);
	tree_manager_set_child_value_i64(result, "testnet", 0);
	tree_manager_set_child_value_str(result, "error","");
	tree_manager_set_child_value_str(result, "ip", ip);
	tree_manager_set_child_value_i32(result, "p2pport", port);
	tree_manager_set_child_value_i32(result, "p2p_status", p2p_status);
	tree_manager_set_child_value_i64(result, "balance", balance);
	tree_manager_set_child_value_i64(result, "blocks", last_blk);
	tree_manager_set_child_value_i64(result, "timeoffset", 0);
	/*
	"newmint" : 0.00000000,
	"stake" : 0.00000000,
	"connections" : 2,
	"proxy" : "",
	"unlocked_until" : 0,
	*/
	return 1;

}

OS_API_C_FUNC(int) getblockcount(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{

	tree_manager_set_child_value_i32(result, "count", get_last_block_height());

	return 1;
}


OS_API_C_FUNC(int) importaddress(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{
	btc_addr_t			new_addr;
	mem_zone_ref		addr = { PTR_NULL }, rescan = { PTR_NULL };
	struct string		adr_path = { 0 };
	unsigned int		scan;
	
	tree_manager_get_child_at		(params, 0, &addr);
	if (!tree_manager_get_node_btcaddr(&addr, 0, new_addr))
	{
		release_zone_ref(&addr);
		return 0;
	}

	if (tree_manager_get_child_at(params, 1, &rescan))
		tree_mamanger_get_node_dword(&rescan, 0, &scan);
	else
		scan = 1;


	make_string						(&adr_path, "adrs");
	cat_ncstring_p					(&adr_path, new_addr, 34);
	create_dir						(adr_path.str);
	
	if (scan)
	{
		mem_zone_ref scan_list = { PTR_NULL };
		if (tree_manager_find_child_node(&my_node, NODE_HASH("addr scan list"), NODE_BITCORE_WALLET_ADDR_LIST, &scan_list))
		{
			mem_zone_ref addr_scan = { PTR_NULL };
			if (tree_manager_create_node("scan", NODE_BITCORE_WALLET_ADDR, &addr_scan))
			{
				tree_manager_set_child_value_btcaddr(&addr_scan, "addr", new_addr);
				tree_manager_set_child_value_i32	(&addr_scan, "done", 0);
				tree_manager_node_add_child			(&scan_list, &addr_scan);
				release_zone_ref					(&addr_scan);
			}
			release_zone_ref						(&scan_list);
		}
	}
		

	release_zone_ref				(&addr);
	release_zone_ref				(&rescan);
	free_string						(&adr_path);
		
	return 1;
}
OS_API_C_FUNC(int) listtransactions(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{
	hash_t		null_hash;
	mem_zone_ref  tx_out_list = { PTR_NULL }, addrs = { PTR_NULL };
	mem_zone_ref  my_list = { PTR_NULL };
	mem_zone_ref_ptr addr;

	tree_manager_add_child_node(result, "txs", NODE_JSON_ARRAY, &tx_out_list);



	tree_manager_get_child_at(params, 0, &addrs);
	memset_c(null_hash, 0, sizeof(hash_t));

	for (tree_manager_get_first_child(&addrs, &my_list, &addr); ((addr != NULL) && (addr->zone != NULL)); tree_manager_get_next_child(&my_list, &addr))
	{
		btc_addr_t			my_addr;
		mem_zone_ref		tx_list = { PTR_NULL };
		mem_zone_ref		my_tlist = { PTR_NULL }, my_tx = { PTR_NULL };
		mem_zone_ref_ptr	tx = PTR_NULL;

		if (!tree_manager_create_node("txs", NODE_BITCORE_HASH_LIST, &tx_list))
			break;
				
		tree_manager_get_node_btcaddr(addr, 0, my_addr);
		load_tx_addresses(my_addr, &tx_list);

		for (tree_manager_get_first_child(&tx_list, &my_tlist, &tx); ((tx != NULL) && (tx->zone != NULL)); tree_manager_get_next_child(&my_tlist, &tx))
		{
			hash_t tx_hash,blk_hash;
			btc_addr_t maddr;
			tree_manager_get_node_hash	(tx, 0, tx_hash);
			if (load_tx(&my_tx, blk_hash,tx_hash))
			{
				mem_zone_ref txout_list = { PTR_NULL }, txin_list = { PTR_NULL };
				if (tree_manager_find_child_node(&my_tx, NODE_HASH("txsin"), NODE_BITCORE_VINLIST, &txin_list))
				{
					unsigned int vin_idx, nin;
					nin = tree_manager_get_node_num_children(&txin_list);
					for (vin_idx = 0; vin_idx < nin; vin_idx++)
					{
						struct string script = { 0 };
						mem_zone_ref vin = { PTR_NULL }, pvout = { PTR_NULL };

						if (get_tx_input(&my_tx, vin_idx, &vin))
						{ 
							hash_t prevOutHash;
							unsigned int prevOutIdx;

							tree_manager_get_child_value_hash(&vin, NODE_HASH("tx hash"), prevOutHash);
							tree_manager_get_child_value_i32(&vin, NODE_HASH("idx"), &prevOutIdx);

							if (memcmp_c(prevOutHash, null_hash, sizeof(hash_t)))
							{
								mem_zone_ref prev_tx = { PTR_NULL };
								load_tx(&prev_tx, blk_hash, prevOutHash);

								if (get_tx_output(&prev_tx, prevOutIdx, &pvout))
								{
									if (tree_manager_get_child_value_istr(&pvout, NODE_HASH("script"), &script, 0))
									{
										if (get_out_script_address(&script, PTR_NULL,maddr))
										{
											if (!memcmp_c(my_addr, maddr, sizeof(btc_addr_t)))
											{
												mem_zone_ref out = { PTR_NULL };
												if (tree_manager_create_node("tx", NODE_GFX_OBJECT, &out))
												{
													uint64_t		amount=0;
													unsigned int	time=0;

													tree_manager_get_child_value_i32(&my_tx, NODE_HASH("time"), &time);
													tree_manager_get_child_value_i64(&pvout, NODE_HASH("value"), &amount);

													tree_manager_set_child_value_hash(&out, "txid", tx_hash);
													tree_manager_set_child_value_hash(&out, "blockhash", blk_hash);
													tree_manager_set_child_value_i32(&out, "time", time);
													tree_manager_set_child_value_i64(&out, "amount", amount);
													tree_manager_set_child_value_btcaddr(&out, "address", maddr);
													tree_manager_set_child_value_str(&out, "category", "send");
													tree_manager_node_add_child(&tx_out_list, &out);
													release_zone_ref(&out);
												}
											}
										}
										free_string(&script);
									}
									release_zone_ref(&pvout);
								}
								release_zone_ref(&prev_tx);
							}
							release_zone_ref(&vin);
						}
					}
					release_zone_ref(&txin_list);
				}

				if (tree_manager_find_child_node(&my_tx, NODE_HASH("txsout"), NODE_BITCORE_VOUTLIST, &txout_list))
				{
					mem_zone_ref my_outlist = { PTR_NULL };
					mem_zone_ref_ptr out = PTR_NULL;

					for (tree_manager_get_first_child(&txout_list, &my_outlist, &out); ((out != NULL) && (out->zone != NULL)); tree_manager_get_next_child(&my_outlist, &out))
					{
						struct string script = { 0 };
						if (tree_manager_get_child_value_istr(out, NODE_HASH("script"), &script, 0))
						{
							if (get_out_script_address(&script, PTR_NULL,maddr))
							{
								if (!memcmp_c(my_addr, maddr, sizeof(btc_addr_t)))
								{
									mem_zone_ref tout = { PTR_NULL };
									if (tree_manager_create_node("tx", NODE_GFX_OBJECT, &tout))
									{
										uint64_t		amount;
										unsigned int	time;

										tree_manager_get_child_value_i32(&my_tx, NODE_HASH("time"), &time);
										tree_manager_get_child_value_i64(out, NODE_HASH("value"), &amount);

										tree_manager_set_child_value_hash	(&tout, "txid", tx_hash);
										tree_manager_set_child_value_hash	(&tout, "blockhash", blk_hash);
										tree_manager_set_child_value_i32	(&tout, "time", time);
										tree_manager_set_child_value_btcaddr (&tout, "address", maddr);
										tree_manager_set_child_value_i64	(&tout, "amount", amount);
										tree_manager_set_child_value_str	(&tout, "category", "receive");
										tree_manager_node_add_child			(&tx_out_list, &tout);
										release_zone_ref(&tout);
									}
								}
							}
							free_string(&script);
						}
					}
					release_zone_ref(&txout_list);
				}
				release_zone_ref(&my_tx);
			}
		}
		release_zone_ref(&tx_list);
	}
	
	release_zone_ref(&tx_out_list);
	release_zone_ref(&addrs);

	return 1;
}

OS_API_C_FUNC(int) listreceived(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{
	mem_zone_ref minconf = { PTR_NULL }, maxconf = { PTR_NULL }, received = { PTR_NULL }, addrs = { PTR_NULL };
	mem_zone_ref  my_list = { PTR_NULL };
	mem_zone_ref_ptr addr;
	uint64_t		amount;

	if (!tree_manager_create_node("received", NODE_JSON_ARRAY, &received))
		return 0;

	tree_manager_get_child_at(params, 0, &minconf);
	tree_manager_get_child_at(params, 1, &maxconf);
	tree_manager_get_child_at(params, 2, &addrs);


	for (tree_manager_get_first_child(&addrs, &my_list, &addr); ((addr != NULL) && (addr->zone != NULL)); tree_manager_get_next_child(&my_list, &addr))
	{
		btc_addr_t my_addr;
		tree_manager_get_node_btcaddr	(addr, 0, my_addr);
		list_received					(my_addr,&amount, &received);
	}
	tree_manager_node_add_child(result, &received);
	release_zone_ref(&received);

	release_zone_ref(&addrs);
	release_zone_ref(&maxconf);
	release_zone_ref(&minconf);

	return 1;
}
OS_API_C_FUNC(int) listspent(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{
	mem_zone_ref minconf = { PTR_NULL }, maxconf = { PTR_NULL }, spents = { PTR_NULL }, addrs = { PTR_NULL };
	mem_zone_ref  my_list = { PTR_NULL };
	mem_zone_ref_ptr addr;

	if (!tree_manager_create_node("spents", NODE_JSON_ARRAY, &spents))
		return 0;

	tree_manager_get_child_at(params, 0, &minconf);
	tree_manager_get_child_at(params, 1, &maxconf);
	tree_manager_get_child_at(params, 2, &addrs);


	for (tree_manager_get_first_child(&addrs, &my_list, &addr); ((addr != NULL) && (addr->zone != NULL)); tree_manager_get_next_child(&my_list, &addr))
	{
		btc_addr_t my_addr;

		tree_manager_get_node_btcaddr(addr, 0, my_addr);
		list_spent(my_addr, &spents);
	}

	tree_manager_node_add_child(result, &spents);
	release_zone_ref(&spents);

	release_zone_ref(&addrs);
	release_zone_ref(&maxconf);
	release_zone_ref(&minconf);

	return 1;
}
OS_API_C_FUNC(int) listunspent(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{
	mem_zone_ref minconf = { PTR_NULL }, maxconf = { PTR_NULL }, unspents = { PTR_NULL }, addrs = { PTR_NULL };
	mem_zone_ref  my_list = { PTR_NULL };
	mem_zone_ref_ptr addr;
	
	if (!tree_manager_create_node("unspents", NODE_JSON_ARRAY, &unspents))
		return 0;

	tree_manager_get_child_at(params, 0, &minconf);
	tree_manager_get_child_at(params, 1, &maxconf);
	tree_manager_get_child_at(params, 2, &addrs);


	for (tree_manager_get_first_child(&addrs, &my_list, &addr); ((addr != NULL) && (addr->zone != NULL)); tree_manager_get_next_child(&my_list, &addr))
	{
		btc_addr_t my_addr;

		tree_manager_get_node_btcaddr	(addr, 0, my_addr);
		list_unspent					(my_addr, &unspents,500);
	}

	tree_manager_node_add_child	(result, &unspents);
	release_zone_ref			(&unspents);

	release_zone_ref			(&addrs);
	release_zone_ref			(&maxconf);
	release_zone_ref			(&minconf);

	return 1;
}

OS_API_C_FUNC(int) listreceivedbyaddress(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{
	mem_zone_ref	addr_list = { PTR_NULL };
	struct string	dir_list = { PTR_NULL };
	size_t			cur, nfiles;


	if (!tree_manager_create_node("addrs", NODE_JSON_ARRAY, &addr_list))
		return 0;

	nfiles = get_sub_dirs("adrs", &dir_list);
	if (nfiles > 0)
	{
		const char		*ptr, *optr;
		unsigned int	dir_list_len;

		dir_list_len = dir_list.len;
		optr = dir_list.str;
		cur = 0;
		while (cur < nfiles)
		{
			mem_zone_ref	new_addr = { PTR_NULL };
			size_t			sz;

			ptr = memchr_c(optr, 10, dir_list_len);
			sz = mem_sub(optr, ptr);

			if (tree_manager_add_child_node(&addr_list, "address", NODE_GFX_OBJECT, &new_addr))
			{
				char addr[35];
				uint64_t amount;
				memcpy_c(addr, optr, sz); addr[34] = 0;
				
				list_received					(addr, &amount,PTR_NULL);
				tree_manager_set_child_value_str(&new_addr, "addr", addr);
				tree_manager_set_child_value_i64(&new_addr, "amount", amount);
				release_zone_ref				(&new_addr);
			}
			cur++;
			optr = ptr + 1;
			dir_list_len -= sz;
		}
		free_string(&dir_list);
	}
	tree_manager_node_add_child(result, &addr_list);
	release_zone_ref(&addr_list);
	return 1;
}