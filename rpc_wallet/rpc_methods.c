//copyright iadix 2016
#include <base/std_def.h>
#include <base/std_mem.h>
#include <base/mem_base.h>
#include <base/std_str.h>

#include <strs.h>
#include <tree.h>
#include <fsio.h>
#include <sha256.h>
#include <crypto.h>
#include <mem_stream.h>
#include <tpo_mod.h>



typedef int  C_API_FUNC				get_blk_staking_infos_func(mem_zone_ref_ptr blk, const char *blk_hash, mem_zone_ref_ptr infos);
typedef get_blk_staking_infos_func *get_blk_staking_infos_func_ptr;

typedef int	C_API_FUNC	store_tx_staking_func(mem_zone_ref_ptr tx, hash_t tx_hash, btc_addr_t stake_addr, uint64_t	stake_in);
typedef store_tx_staking_func		*store_tx_staking_func_ptr;

typedef int	C_API_FUNC	get_tx_pos_hash_data_func(mem_zone_ref_ptr hdr, const hash_t txHash, unsigned int OutIdx, struct string *hash_data,uint64_t *amount, hash_t out_diff);
typedef  get_tx_pos_hash_data_func *get_tx_pos_hash_data_func_ptr;

typedef int	C_API_FUNC get_target_spacing_func(unsigned int *target);
typedef  get_target_spacing_func   *get_target_spacing_func_ptr;

typedef int	C_API_FUNC get_stake_reward_func(uint64_t *reward);
typedef get_stake_reward_func   *get_stake_reward_func_ptr;

typedef int	C_API_FUNC  get_last_stake_modifier_func(mem_zone_ref_ptr pindex, hash_t nStakeModifier, unsigned int *nModifierTime);
typedef get_last_stake_modifier_func   *get_last_stake_modifier_func_ptr;

typedef int	C_API_FUNC compute_tx_pos_func(mem_zone_ref_ptr tx, hash_t StakeModifier, unsigned int txTime, hash_t pos_hash, hash_t prevOutHash, unsigned int *prevOutIdx);
typedef compute_tx_pos_func   *compute_tx_pos_func_ptr;

typedef unsigned int	C_API_FUNC	get_current_pos_difficulty_func();
typedef get_current_pos_difficulty_func		*get_current_pos_difficulty_func_ptr;

typedef int	 C_API_FUNC	create_pos_block_func(hash_t pHash, mem_zone_ref_ptr tx, mem_zone_ref_ptr newBlock);
typedef create_pos_block_func *create_pos_block_func_ptr;

#ifdef _DEBUG
C_IMPORT int			C_API_FUNC		get_last_stake_modifier(mem_zone_ref_ptr pindex, hash_t nStakeModifier, unsigned int *nModifierTime);
C_IMPORT int			C_API_FUNC		get_tx_pos_hash_data(mem_zone_ref_ptr hdr, const hash_t txHash, unsigned int OutIdx, struct string *hash_data,uint64_t *amount, hash_t out_diff);
C_IMPORT int			C_API_FUNC		get_blk_staking_infos(mem_zone_ref_ptr blk, const char *blk_hash, mem_zone_ref_ptr infos);
C_IMPORT int			C_API_FUNC		store_tx_staking(mem_zone_ref_ptr tx, hash_t tx_hash, btc_addr_t stake_addr, uint64_t	stake_in);
C_IMPORT int			C_API_FUNC		get_target_spacing(unsigned int *target);
C_IMPORT unsigned int	C_API_FUNC		get_current_pos_difficulty();
C_IMPORT int			C_API_FUNC		get_stake_reward(uint64_t *reward);
C_IMPORT int			C_API_FUNC		compute_tx_pos(mem_zone_ref_ptr tx, hash_t StakeModifier, unsigned int txTime, hash_t pos_hash, hash_t prevOutHash, unsigned int *prevOutIdx);
C_IMPORT int			C_API_FUNC		create_pos_block(hash_t pHash, mem_zone_ref_ptr tx, mem_zone_ref_ptr newBlock);

get_blk_staking_infos_func_ptr			_get_blk_staking_infos = PTR_INVALID;
get_tx_pos_hash_data_func_ptr			_get_tx_pos_hash_data = PTR_INVALID;
store_tx_staking_func_ptr				_store_tx_staking = PTR_INVALID;
get_target_spacing_func_ptr				_get_target_spacing = PTR_INVALID;
get_stake_reward_func_ptr				_get_stake_reward = PTR_INVALID;
get_last_stake_modifier_func_ptr		_get_last_stake_modifier = PTR_INVALID;
get_current_pos_difficulty_func_ptr	    _get_current_pos_difficulty = PTR_INVALID;
compute_tx_pos_func_ptr					_compute_tx_pos = PTR_INVALID;
create_pos_block_func_ptr				_create_pos_block = PTR_INVALID;
#else
get_blk_staking_infos_func_ptr		get_blk_staking_infos = PTR_INVALID;
store_tx_staking_func_ptr			store_tx_staking = PTR_INVALID;
get_tx_pos_hash_data_func_ptr		get_tx_pos_hash_data = PTR_INVALID;
get_target_spacing_func_ptr			get_target_spacing = PTR_INVALID;
get_stake_reward_func_ptr			get_stake_reward = PTR_INVALID;
get_last_stake_modifier_func_ptr	 get_last_stake_modifier = PTR_INVALID;
get_current_pos_difficulty_func_ptr	 get_current_pos_difficulty = PTR_INVALID;
compute_tx_pos_func_ptr				compute_tx_pos = PTR_INVALID;
create_pos_block_func_ptr			create_pos_block = PTR_INVALID;
#endif

//get_blk_staking_infos_func_ptr  get_blk_staking_infos = PTR_INVALID;

C_IMPORT int			C_API_FUNC is_pow_block(const char *blk_hash);
C_IMPORT int			C_API_FUNC get_blk_height(const char *blk_hash, uint64_t *height);
C_IMPORT int			C_API_FUNC get_blk_txs(const char* blk_hash, mem_zone_ref_ptr txs, size_t max);
C_IMPORT int			C_API_FUNC load_blk_hdr(mem_zone_ref_ptr hdr, const char *blk_hash);
C_IMPORT int			C_API_FUNC get_block_size(const char *blk_hash, size_t *size);
C_IMPORT int			C_API_FUNC get_pow_block(const char *blk_hash, hash_t pos);
C_IMPORT int			C_API_FUNC SetCompact(unsigned int bits, hash_t out);
C_IMPORT int			C_API_FUNC get_last_block_height();
C_IMPORT int			C_API_FUNC get_moneysupply(uint64_t *amount);
C_IMPORT int			C_API_FUNC load_tx_addresses(btc_addr_t addr, mem_zone_ref_ptr tx_hashes);
C_IMPORT int			C_API_FUNC load_tx(mem_zone_ref_ptr tx, hash_t blk_hash, const hash_t tx_hash);
C_IMPORT int			C_API_FUNC get_tx_blk_height(const hash_t tx_hash, uint64_t *height, uint64_t *block_time, uint64_t *tx_time);
C_IMPORT int			C_API_FUNC compute_block_hash(mem_zone_ref_ptr block, hash_t hash);
C_IMPORT int			C_API_FUNC get_out_script_address(struct string *script, struct string *pubk, btc_addr_t addr);
C_IMPORT int			C_API_FUNC load_tx_input(mem_zone_ref_const_ptr tx, unsigned int idx, mem_zone_ref_ptr	vin, mem_zone_ref_ptr tx_out);
C_IMPORT int			C_API_FUNC get_tx_output(mem_zone_ref_const_ptr tx, unsigned int idx, mem_zone_ref_ptr vout);
C_IMPORT int			C_API_FUNC get_tx_input(mem_zone_ref_const_ptr tx, unsigned int idx, mem_zone_ref_ptr vout);
C_IMPORT void			C_API_FUNC key_to_addr(unsigned char *pkey, btc_addr_t addr);
C_IMPORT int			C_API_FUNC paddr_to_key(btc_paddr_t addr, dh_key_t key);
C_IMPORT int			C_API_FUNC get_tx_output_addr(const hash_t tx_hash, unsigned int idx, btc_addr_t addr);
C_IMPORT int			C_API_FUNC add_unspent(btc_addr_t	addr, const char *tx_hash, unsigned int oidx, uint64_t amount, btc_addr_t *src_addrs, unsigned int n_addrs);
C_IMPORT int			C_API_FUNC spend_tx_addr(btc_addr_t addr, const char *tx_hash, unsigned int vin, const char *ptx_hash, unsigned int oidx, btc_addr_t *addrs_to, unsigned int n_addrs_to);
C_IMPORT int			C_API_FUNC is_tx_null(mem_zone_ref_const_ptr tx);
C_IMPORT int			C_API_FUNC is_vout_null(mem_zone_ref_const_ptr tx, unsigned int idx);
C_IMPORT int			C_API_FUNC get_tx_output_amount(const hash_t tx_hash, unsigned int idx, uint64_t *amount);
C_IMPORT int			C_API_FUNC compute_tx_hash(mem_zone_ref_ptr tx, hash_t hash);
C_IMPORT int			C_API_FUNC tx_add_output(mem_zone_ref_ptr tx, uint64_t value, const struct string *script);
C_IMPORT int			C_API_FUNC tx_add_input(mem_zone_ref_ptr tx, const hash_t tx_hash, unsigned int index, struct string *script);
C_IMPORT int			C_API_FUNC new_transaction(mem_zone_ref_ptr tx, ctime_t time);
C_IMPORT int			C_API_FUNC compute_tx_sign_hash(mem_zone_ref_const_ptr tx, unsigned int nIn, const struct string *script, unsigned int hash_type, hash_t txh);
C_IMPORT void			C_API_FUNC mul_compact(unsigned int nBits, uint64_t op, hash_t hash);
C_IMPORT int			C_API_FUNC cmp_hashle(hash_t hash1, hash_t hash2);
C_IMPORT int			C_API_FUNC tx_sign(mem_zone_ref_const_ptr tx, unsigned int nIn, unsigned int hashType, const struct string *sign);
C_IMPORT int	C_API_FUNC  parse_sig_seq(const struct string *sign_seq, struct string *sign, unsigned char *hashtype, int rev);
C_IMPORT char*			C_API_FUNC	write_node(mem_zone_ref_const_ptr key, unsigned char *payload);
C_IMPORT size_t			C_API_FUNC	get_node_size(mem_zone_ref_ptr key);
C_IMPORT int			C_API_FUNC	blk_check_sign(const struct string *sign, const struct string *pubk, const hash_t hash);
C_IMPORT int			C_API_FUNC	build_merkel_tree(mem_zone_ref_ptr txs, hash_t merkleRoot);

unsigned int			WALLET_VERSION = 60000;
unsigned int			min_staking_depth = 2;
mem_zone_ref			my_node = { PTR_INVALID };
btc_addr_t				src_addr_list[1024] = { 0xCDFF };

OS_API_C_FUNC(int) set_node(mem_zone_ref_ptr node,tpo_mod_file *pos_mod)
{
	my_node.zone = PTR_NULL;
	copy_zone_ref(&my_node, node);

	

#ifndef _DEBUG
	get_blk_staking_infos		= (get_blk_staking_infos_func_ptr)		get_tpo_mod_exp_addr_name(pos_mod, "get_blk_staking_infos", 0);
	store_tx_staking			= (store_tx_staking_func_ptr)			get_tpo_mod_exp_addr_name(pos_mod, "store_tx_staking", 0);
	get_tx_pos_hash_data		= (get_tx_pos_hash_data_func_ptr)		get_tpo_mod_exp_addr_name(pos_mod, "get_tx_pos_hash_data", 0);
	get_target_spacing			= (get_target_spacing_func_ptr)			get_tpo_mod_exp_addr_name(pos_mod, "get_target_spacing", 0);
	get_stake_reward			= (get_stake_reward_func_ptr)			get_tpo_mod_exp_addr_name(pos_mod, "get_stake_reward", 0);
	get_last_stake_modifier		= (get_last_stake_modifier_func_ptr)	get_tpo_mod_exp_addr_name(pos_mod, "get_last_stake_modifier", 0);
	get_current_pos_difficulty  = (get_current_pos_difficulty_func_ptr)	get_tpo_mod_exp_addr_name(pos_mod, "get_current_pos_difficulty", 0);
	compute_tx_pos				= (compute_tx_pos_func_ptr)				get_tpo_mod_exp_addr_name(pos_mod, "compute_tx_pos", 0);
	create_pos_block			= (create_pos_block_func_ptr)			get_tpo_mod_exp_addr_name(pos_mod, "create_pos_block", 0);
#endif
	
	//get_blk_staking_infos = get_tpo_mod_exp_addr_name(pos_mod, "get_blk_staking_infos", 0);
	return 1;
}


int list_unspent(btc_addr_t addr, mem_zone_ref_ptr unspents,int *max)
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

		if (((*max)--)<=0)
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

int get_balance(btc_addr_t addr, uint64_t *conf_amount, uint64_t *amount, unsigned int minconf)
{
	struct string		unspent_path;
	unsigned int		n;
	unsigned int		dir_list_len;
	struct string		dir_list = { PTR_NULL };
	const char			*ptr, *optr;
	size_t				cur, nfiles;
	uint64_t			sheight;

	init_string		(&unspent_path);
	make_string		(&unspent_path, "adrs");
	cat_ncstring_p	(&unspent_path, addr, 34);
	cat_cstring_p	(&unspent_path, "unspent");

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
	while ((cur < nfiles) && (dir_list_len>0))
	{
		struct string	tx_path;
		unsigned int	output = 0xFFFFFFFF;
		size_t			sz, len;
		unsigned char	*data;

		ptr = memchr_c(optr, 10, dir_list_len);
		if (ptr == PTR_NULL)break;
		sz	= mem_sub(optr, ptr);

		init_string		(&tx_path);
		clone_string	(&tx_path, &unspent_path);
		cat_ncstring_p	(&tx_path, optr, sz);

		if (get_file(tx_path.str, &data, &len)>0)
		{
			unsigned int nconf;
			if (len >= sizeof(uint64_t))
			{
				hash_t			hash;
				mem_zone_ref	unspent = { PTR_NULL };
				uint64_t		height, block_time, tx_time;

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

				if (optr[64] == '_')
					output = strtoul_c(&optr[65], PTR_NULL, 10);
				else
					output = 0xFFFFFFFF;

				if (get_tx_blk_height(hash, &height, &block_time, &tx_time))
					nconf = sheight - height;
				else
				{
					block_time = 0;
					tx_time = 0;
					nconf = 0;
				}
				if (nconf < minconf)
					(*amount)		+= *((uint64_t*)data); 
				else
					(*conf_amount)	+= *((uint64_t*)data);
			}
			free_c(data);
		}
		free_string(&tx_path);
		cur++;
		optr = ptr + 1;
		dir_list_len -= (sz+1);
	}
	free_string(&dir_list);

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
		get_blk_txs(chash, &txs,10);
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
	int max = 50;
	
	if (!tree_manager_add_child_node(result,"unspents", NODE_JSON_ARRAY, &unspents))
		return 0;

	tree_manager_get_child_at(params, 0, &minconf);
	tree_manager_get_child_at(params, 1, &maxconf);
	tree_manager_get_child_at(params, 2, &addrs);


	for (tree_manager_get_first_child(&addrs, &my_list, &addr); ((addr != NULL) && (addr->zone != NULL)); tree_manager_get_next_child(&my_list, &addr))
	{
		if (max > 0)
		{
			btc_addr_t my_addr;
			tree_manager_get_node_btcaddr(addr, 0, my_addr);
			list_unspent(my_addr, &unspents, &max);
		}
	}
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

OS_API_C_FUNC(int) pubkeytoaddr(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{
	dh_key_t		pub;
	btc_addr_t		pubaddr;
	mem_zone_ref	pubkey_n = { PTR_NULL };
	struct string   xpubkey = { PTR_NULL };
	size_t keys_data_len = 0;
	unsigned char *keys_data = PTR_NULL;

	tree_manager_get_child_at(params, 0, &pubkey_n);
	tree_manager_get_node_istr(&pubkey_n, 0, &xpubkey, 0);
	release_zone_ref(&pubkey_n);
	if (xpubkey.len == 130)
	{
		unsigned char cpub[65];
		int n = 65;
		while (n--)
		{
			char    hex[3];
			hex[0] = xpubkey.str[n * 2 + 0];
			hex[1] = xpubkey.str[n * 2 + 1];
			hex[2] = 0;
			cpub[n] = strtoul_c(hex, PTR_NULL, 16);
		}
		key_to_addr(pub, pubaddr);
	}
	if (xpubkey.len == 66)
	{
		char    hex[3];
		int n = 32;

		hex[0] = xpubkey.str[0];
		hex[1] = xpubkey.str[1];
		hex[2] = 0;
		pub[0] = strtoul_c(hex, PTR_NULL, 16);
		while (n--)
		{
			hex[0] = xpubkey.str[(n + 1) * 2 + 0];
			hex[1] = xpubkey.str[(n + 1) * 2 + 1];
			hex[2] = 0;
			pub[(n)+1] = strtoul_c(hex, PTR_NULL, 16);
		}
		key_to_addr(pub, pubaddr);
	}
	free_string								(&xpubkey);
	tree_manager_set_child_value_btcaddr	(result,"addr",pubaddr);
	return 1;
}

int store_tx_wallet(btc_addr_t addr, hash_t tx_hash)
{
	char			 tchash[65];
	hash_t			 blk_hash, null_hash;
	btc_addr_t	 	 to_addr_list[16];
	
	struct string	 tx_path = { 0 };
	mem_zone_ref	 txin_list = { PTR_NULL }, txout_list = { PTR_NULL }, my_list = { PTR_NULL }, tx = { PTR_NULL };
	mem_zone_ref_ptr input = PTR_NULL, out = PTR_NULL;
	unsigned int	 n, oidx, iidx;
	unsigned int	 n_to_addrs;
	unsigned int	 n_in_addr;

	memset_c(null_hash, 0, 32);

	if (!load_tx(&tx, blk_hash, tx_hash))return 0;
	if (is_tx_null(&tx))
	{
		release_zone_ref(&tx);
		return 0;
	}
	if (!tree_manager_find_child_node(&tx, NODE_HASH("txsin"), NODE_BITCORE_VINLIST, &txin_list))return 0;
	if (!tree_manager_find_child_node(&tx, NODE_HASH("txsout"), NODE_BITCORE_VOUTLIST, &txout_list)){ release_zone_ref(&txin_list); return 0; }

	n = 0;
	while (n < 32)
	{
		tchash[n * 2 + 0] = hex_chars[tx_hash[n] >> 4];
		tchash[n * 2 + 1] = hex_chars[tx_hash[n] & 0x0F];
		n++;
	}
	tchash[64] = 0;
	n_to_addrs = 0;
	for (tree_manager_get_first_child(&txout_list, &my_list, &out); ((out != NULL) && (out->zone != NULL)); tree_manager_get_next_child(&my_list, &out))
	{
		struct string script = { 0 };
		if (!tree_manager_get_child_value_istr(out, NODE_HASH("script"), &script, 16))continue;
		if (script.len == 0){ free_string(&script); continue; }
		if (get_out_script_address(&script, PTR_NULL, to_addr_list[n_to_addrs]))
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


	n_in_addr = 0;
	for (iidx = 0, tree_manager_get_first_child(&txin_list, &my_list, &input); ((input != NULL) && (input->zone != NULL)); tree_manager_get_next_child(&my_list, &input), iidx++)
	{
		char			ptchash[65];
		hash_t			prev_hash = { 0xFF };
		struct string	out_path = { 0 };
		int				n, my_addr;
		uint64_t		amount;

		tree_manager_get_child_value_hash(input, NODE_HASH("tx hash"), prev_hash);
		tree_manager_get_child_value_i32(input, NODE_HASH("idx"), &oidx);

		my_addr = 0;

		//coin base
		if (!memcmp_c(prev_hash, null_hash, sizeof(hash_t)))
		{
			memset_c(src_addr_list[0], '0', sizeof(btc_addr_t));
			n_in_addr = 1;
			continue;
		}


		if (get_tx_output_addr(prev_hash, oidx, src_addr_list[n_in_addr]))
		{
			unsigned int nn, f;
			f = 0;
			for (nn = 0; nn < n_in_addr; nn++)
			{
				if (!memcmp_c(src_addr_list[n_in_addr], src_addr_list[nn], sizeof(btc_addr_t)))
				{
					f = 1;
					break;
				}
			}

			if (!memcmp_c(addr, src_addr_list[n_in_addr], sizeof(btc_addr_t)))
				my_addr = 1;

			if (f == 0)
				n_in_addr++;

		}

		if (my_addr)
		{
			n = 0;
			while (n < 32)
			{
				ptchash[n * 2 + 0] = hex_chars[prev_hash[n] >> 4];
				ptchash[n * 2 + 1] = hex_chars[prev_hash[n] & 0x0F];
				n++;
			}
			ptchash[64] = 0;
			spend_tx_addr(addr, tchash, iidx, ptchash, oidx, to_addr_list, n_to_addrs);

			if (get_tx_output_amount(prev_hash, oidx, &amount))
				tree_manager_set_child_value_i64(input, "amount", amount);
			tree_manager_set_child_value_btcaddr(input, "src addr", addr);
		}
	}


	out = PTR_NULL;
	release_zone_ref(&my_list);

	for (oidx = 0, tree_manager_get_first_child(&txout_list, &my_list, &out); ((out != NULL) && (out->zone != NULL)); oidx++, tree_manager_get_next_child(&my_list, &out))
	{
		btc_addr_t		out_addr = { 0 };
		struct string	out_path = { 0 }, script = { 0 };
		uint64_t		amount = 0;
		int				ret;

		tree_manager_get_child_value_istr(out, NODE_HASH("script"), &script, 0);
		ret = get_out_script_address(&script, PTR_NULL, out_addr);
		free_string(&script);

		if (ret)
		{
			make_string(&out_path, "adrs");
			cat_ncstring_p(&out_path, out_addr, 34);

			/*
			if (is_coinbase(&tx))
			create_dir(out_path.str);
			*/
			if ((stat_file(out_path.str) == 0) && (!memcmp_c(addr, out_addr, sizeof(btc_addr_t))))
			{
				tree_manager_get_child_value_i64(out, NODE_HASH("value"), &amount);
				add_unspent(out_addr, tchash, oidx, amount, src_addr_list, n_in_addr);
			}
			free_string(&out_path);
		}
	}
	if (is_vout_null(&tx, 0))
	{
		mem_zone_ref	vin = { PTR_NULL };
		btc_addr_t		stake_addr = { 0 };
		uint64_t		stake_in = 0;

		if (tree_manager_get_child_at(&txin_list, 0, &vin))
		{
			tree_manager_get_child_value_btcaddr(&vin, NODE_HASH("src addr"), stake_addr);
			tree_manager_get_child_value_i64(&vin, NODE_HASH("amount"), &stake_in);
			release_zone_ref(&vin);
		}
		release_zone_ref(&txin_list);

		if (!memcmp_c(stake_addr, addr, sizeof(btc_addr_t)))
			store_tx_staking(&tx, tx_hash, stake_addr, stake_in);
	}

	release_zone_ref(&txin_list);
	release_zone_ref(&txout_list);
	release_zone_ref(&tx);

	return 1;

}



int list_staking_unspent(mem_zone_ref_ptr last_blk, btc_addr_t addr, mem_zone_ref_ptr unspents, unsigned int min_depth,int *max)
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
		hash_t			hash, rhash;
		mem_zone_ref	unspent = { PTR_NULL };
		unsigned int	output = 0xFFFFFFFF;
		uint64_t		height, blk_time, tx_time, nconf;
		size_t			sz;

		if (((*max)--) <= 0)
			break;

		ptr = memchr_c(optr, 10, dir_list_len);
		sz = mem_sub(optr, ptr);

		if (optr[64] == '_')
			output = strtoul_c(&optr[65], PTR_NULL, 10);
		else
			output = 0xFFFFFFFF;
		
		n = 0;
		while (n<32)
		{
			char    hex[3];
			hex[0] = optr[n * 2 + 0];
			hex[1] = optr[n * 2 + 1];
			hex[2] = 0;
			hash[n] = strtoul_c(hex, PTR_NULL, 16);
			rhash[31 - n] = hash[n];
			n++;
		}
		if (get_tx_blk_height(hash, &height, &blk_time, &tx_time))
		{
			nconf = sheight - height;
			if (nconf >min_depth)
			{
				if (tree_manager_add_child_node(unspents, "unspent", NODE_GFX_OBJECT, &unspent))
				{
					hash_t			out_diff;
					struct string	pos_hash_data = { PTR_NULL };
					uint64_t		amount;

					memset_c(out_diff, 0, sizeof(hash_t));
					if (get_tx_pos_hash_data(last_blk, hash, output, &pos_hash_data, &amount, out_diff))
					{
						hash_t rout_diff;
						n = 32;
						while (n--)rout_diff[n] = out_diff[31 - n];
						tree_manager_set_child_value_hash(&unspent, "txid", hash);
						tree_manager_set_child_value_i32(&unspent, "vout", output);
						tree_manager_set_child_value_i32(&unspent, "nconf", nconf);
						tree_manager_set_child_value_i64(&unspent, "weight", amount);
						tree_manager_set_child_value_str(&unspent, "hash_data", pos_hash_data.str);
						tree_manager_set_child_value_hash(&unspent, "difficulty", rout_diff);
						free_string(&pos_hash_data);
					}
					release_zone_ref(&unspent);
				}
			}
		}
		cur++;
		optr = ptr + 1;
		dir_list_len -= sz;
	}
	free_string(&dir_list);
	free_string(&unspent_path);

	return 1;
}
OS_API_C_FUNC(int) liststaking(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{
	mem_zone_ref_ptr addr;
	mem_zone_ref	minconf = { PTR_NULL }, maxconf = { PTR_NULL }, unspents = { PTR_NULL }, addrs = { PTR_NULL };
	mem_zone_ref	my_list = { PTR_NULL };
	mem_zone_ref	last_blk = { PTR_NULL };
	struct string	pos_hash_data = { PTR_NULL };
	int				max = 2000;
	int				ret = 0;
	unsigned int 	block_time;
	unsigned int	target,iminconf=0;
	if (!tree_manager_find_child_node(&my_node, NODE_HASH("last block"), NODE_BITCORE_BLK_HDR, &last_blk))return 0;

	if (!tree_manager_add_child_node(result, "unspents", NODE_JSON_ARRAY, &unspents))
		return 0;

	if (tree_manager_get_child_at(params, 0, &minconf))
	{
		tree_mamanger_get_node_dword(&minconf, 0, &iminconf);
		release_zone_ref			(&minconf);
	}

	if (iminconf < min_staking_depth)
		iminconf = min_staking_depth;

	tree_manager_get_child_at		(params, 1, &maxconf);
	tree_manager_get_child_at		(params, 2, &addrs);

	get_target_spacing				(&target);
	tree_manager_get_child_value_i32(&last_blk, NODE_HASH("time"), &block_time);

	tree_manager_set_child_value_i32(result, "block_target", target);
	tree_manager_set_child_value_i32(result, "now", get_time_c());
	tree_manager_set_child_value_i32(result, "last_block_time", block_time);

	for (tree_manager_get_first_child(&addrs, &my_list, &addr); ((addr != NULL) && (addr->zone != NULL)); tree_manager_get_next_child(&my_list, &addr))
	{
		if (max > 0)
		{
			btc_addr_t my_addr;
			tree_manager_get_node_btcaddr(addr, 0, my_addr);
			list_staking_unspent(&last_blk, my_addr, &unspents, iminconf, &max);
		}
	}
	release_zone_ref(&last_blk);
	release_zone_ref(&unspents);
	release_zone_ref(&addrs);
	release_zone_ref(&maxconf);
	

	return 1;
	
}
OS_API_C_FUNC(int) signstakeblock(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{
	hash_t			rblkHash, blkHash;
	unsigned char	chash[65];
	struct string   signature = { 0 }, vpubk = { 0 }, pubk = { 0 }, sign = { 0 };
	mem_zone_ref	pn = { PTR_NULL }, blk = { PTR_NULL }, node_blks = { PTR_NULL };
	unsigned int	n;
	int				ret=0;
	tree_manager_get_child_at(params, 0, &pn);
	tree_manager_get_node_str(&pn, 0, chash, 65, 0);
	release_zone_ref(&pn);

	tree_manager_get_child_at(params, 1, &pn);
	tree_manager_get_node_istr(&pn, 0, &signature, 0);
	release_zone_ref(&pn);

	tree_manager_get_child_at(params, 2, &pn);
	tree_manager_get_node_istr(&pn, 0, &vpubk, 0);
	release_zone_ref(&pn);

	n = 0;
	while (n < 32)
	{
		char	hex[3];
		hex[0] = chash[n * 2 + 0];
		hex[1] = chash[n * 2 + 1];
		hex[2] = 0;
		blkHash[n] = strtoul_c(hex, PTR_NULL, 16);
		rblkHash[31 - n] = blkHash[n];
		n++;
	}

	sign.len = signature.len / 2;
	sign.size = sign.len + 1;
	sign.str = malloc_c(sign.size);
	n		 = 0;
	while (n < sign.len)
	{
		char	hex[3];
		hex[0] = signature.str[n * 2 + 0];
		hex[1] = signature.str[n * 2 + 1];
		hex[2] = 0;
		sign.str[n] = strtoul_c(hex, PTR_NULL, 16);
		n++;
	}
	sign.str[sign.len] = 0;
	free_string(&signature);


	if (vpubk.len == 66)
	{
		pubk.len  = 33;
		pubk.size = pubk.len + 1;
		pubk.str  = malloc_c(pubk.size);
		n = 0;
		while (n < pubk.len)
		{
			char	hex[3];
			hex[0] = vpubk.str[n * 2 + 0];
			hex[1] = vpubk.str[n * 2 + 1];
			hex[2] = 0;
			pubk.str[n] = strtoul_c(hex, PTR_NULL, 16);
			n++;
		}
		pubk.str[pubk.len] = 0;
	}
	free_string(&vpubk);

	if (tree_manager_find_child_node(&my_node, NODE_HASH("submitted blocks"), NODE_BITCORE_BLK_HDR_LIST, &node_blks))
	{
		if (tree_find_child_node_by_member_name_hash(&node_blks, NODE_BITCORE_BLK_HDR, "blk hash", blkHash, &blk))
		{
			mem_zone_ref	txs = { PTR_NULL };
			mem_zone_ref	sig = { PTR_NULL };

			if (pubk.len==0)
				ret = 1; 
			else
			{
				unsigned char	type;
				struct string	bsig = { 0 };

				ret = parse_sig_seq(&sign, &bsig, &type, 1);
				if (ret)
					ret = blk_check_sign(&bsig, &pubk, blkHash);
			}
			if (ret)
			{
				tree_manager_add_child_node(&blk, "signature", NODE_BITCORE_ECDSA_SIG, &sig);
				tree_manager_write_node_sig(&sig, 0, sign.str, sign.len);
				release_zone_ref(&sig);

			}
			release_zone_ref			(&blk);
		}
		release_zone_ref(&node_blks);
	}
	
	free_string(&sign);
	free_string(&pubk);


	return ret;
}


OS_API_C_FUNC(int) signstaketx(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{
	hash_t			txHash;
	unsigned char	chash[65];
	btc_addr_t		pubAddr;
	int				ret = 0;
	unsigned int	n;
	unsigned char   hash_type = 1;
	struct	string  bsign = { PTR_NULL }, sign = { PTR_NULL };
	mem_zone_ref	pn = { PTR_NULL }, node_txs = { PTR_NULL }, tx = { PTR_NULL };
	
	tree_manager_get_child_at	(params, 0, &pn);
	tree_manager_get_node_str	(&pn, 0, chash, 65, 0);
	release_zone_ref			(&pn);

	n = 0;
	while (n < 32)
	{
		char	hex[3];
		hex[0] = chash[n * 2 + 0];
		hex[1] = chash[n * 2 + 1];
		hex[2] = 0;
		txHash[n]			= strtoul_c(hex, PTR_NULL, 16);
		n++;
	}
	tree_manager_get_child_at	(params, 1, &pn);
	tree_manager_get_node_istr	(&pn, 0, &sign, 0);
	release_zone_ref			(&pn);

	bsign.len	= (sign.len / 2)+1;
	bsign.size  = bsign.len + 1;
	bsign.str	= malloc_c(bsign.size);

	n = 0;
	while (n < bsign.len)
	{
		char	hex[3];
		hex[0]   = sign.str[n * 2 + 0];
		hex[1]   = sign.str[n * 2 + 1];
		hex[2]   = 0;
		bsign.str[n] = strtoul_c(hex, PTR_NULL, 16);
		n++;
	}
	free_string(&sign);

	bsign.str[bsign.len-1] = hash_type;

	tree_manager_get_child_at		(params, 2, &pn);
	tree_manager_get_node_btcaddr	(&pn, 0, pubAddr);
	release_zone_ref				(&pn);

	if (tree_manager_find_child_node(&my_node, NODE_HASH("tx mem pool"), NODE_BITCORE_TX_LIST, &node_txs))
	{
		if (tree_find_child_node_by_member_name_hash(&node_txs, NODE_BITCORE_TX, "tx hash", txHash, &tx))
		{
			mem_zone_ref last_blk = { PTR_NULL }, newBlock = { PTR_NULL };
			ret = tx_sign(&tx, 0, hash_type, &bsign);
			if (ret)
			{
				if (tree_manager_find_child_node(&my_node, NODE_HASH("last block"), NODE_BITCORE_BLK_HDR, &last_blk))
				{
					hash_t block_hash;
					tree_manager_get_child_value_hash(&last_blk, NODE_HASH("blk hash"), block_hash);
					if (create_pos_block(block_hash, &tx, &newBlock))
					{
						mem_zone_ref txs = { PTR_NULL }, blk_list = { PTR_NULL };

						if (tree_manager_find_child_node(&my_node, NODE_HASH("submitted blocks"), NODE_BITCORE_BLK_HDR_LIST, &blk_list))
						{
							hash_t h,rblkh;
							
							tree_manager_get_child_value_hash(&newBlock, NODE_HASH("blk hash"), h);
							n = 32;
							while (n--)rblkh[n] = h[31 - n];

							tree_manager_set_child_value_hash	(result		, "newblockhash", rblkh);
							tree_manager_node_add_child			(&blk_list	, &newBlock);
							release_zone_ref					(&blk_list);
						}
						release_zone_ref(&newBlock);
					}
					release_zone_ref(&last_blk);
				}
			}
			release_zone_ref(&tx);
		}
		release_zone_ref(&node_txs);
	}
	free_string(&bsign);
	return ret;

}
OS_API_C_FUNC(int) getstaketx(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{
	unsigned char	chash[65];
	hash_t			txHash, blkhash;
	btc_addr_t		pubaddr;
	char			toto = 0;
	mem_zone_ref	vout = { PTR_NULL }, prevtx = { PTR_NULL }, newtx = { PTR_NULL }, pn = { PTR_NULL };
	struct string   sPubk = { PTR_NULL }, script = { PTR_NULL }, null_str = { PTR_NULL };
	uint64_t		amount;
	unsigned int	OutIdx, newTxTime,n;
	int				ret;

	null_str.str  = &toto;
	null_str.len  = 0;
	null_str.size = 1;
	
	tree_manager_get_child_at	(params, 0, &pn);
	tree_manager_get_node_str	(&pn, 0, chash, 65, 0);
	release_zone_ref			(&pn);

	n = 0;
	while (n < 32)
	{
		char	hex[3];
		hex[0] = chash[n * 2 + 0];
		hex[1] = chash[n * 2 + 1];
		hex[2] = 0;
		txHash[31 - n] = strtoul_c(hex, PTR_NULL, 16); 
		n++;
	}

	tree_manager_get_child_at		(params, 1, &pn);
	tree_mamanger_get_node_dword	(&pn, 0, &OutIdx);
	release_zone_ref				(&pn);

	tree_manager_get_child_at		(params, 2, &pn);
	tree_mamanger_get_node_dword	(&pn, 0, &newTxTime);
	release_zone_ref				(&pn);

	ret = load_tx(&prevtx, blkhash, txHash);
	
	if (ret)
		ret = get_tx_output(&prevtx, OutIdx, &vout);
	
	if (ret)
		ret = tree_manager_get_child_value_istr(&vout, NODE_HASH("script"), &script, 0);
	
	if (ret)
		ret = tree_manager_get_child_value_i64(&vout, NODE_HASH("value"), &amount);

	get_out_script_address(&script, &sPubk, pubaddr);

	if (ret)
	{
		uint64_t			half_am,rew;

		ret = 0;

		get_stake_reward	(&rew);
		half_am = muldiv64	(amount+rew, 1, 2);

		if (tree_manager_add_child_node(result, "transaction", NODE_BITCORE_TX, &newtx))
		{
			hash_t			txh;
			unsigned int	hash_type = 1;

			if (new_transaction(&newtx, newTxTime))
			{
				mem_zone_ref last_blk = { PTR_NULL };

				tx_add_input (&newtx, txHash, OutIdx, &script);
				tx_add_output(&newtx, 0, &null_str);
				tx_add_output(&newtx, half_am, &script);
				tx_add_output(&newtx, half_am, &script);

				if (tree_manager_find_child_node(&my_node, NODE_HASH("last block"), NODE_BITCORE_BLK_HDR, &last_blk))
				{
					hash_t		 StakeMod, pos_hash, out_diff;
					hash_t		 prevOutHash;
					uint64_t	 weight;
					unsigned int prevOutIdx,last_diff;
					unsigned int ModTime;


					get_last_stake_modifier	(&last_blk, StakeMod, &ModTime);
					compute_tx_pos			(&newtx, StakeMod, newTxTime, pos_hash, prevOutHash, &prevOutIdx);
					memset_c				(out_diff, 0, sizeof(hash_t));
					get_tx_output_amount	(prevOutHash, prevOutIdx, &weight);
					
					last_diff = get_current_pos_difficulty();

					if (last_diff == 0xFFFFFFFF)
					{
						unsigned int					nBits;
						tree_manager_get_child_value_i32(&last_blk, NODE_HASH("bits"), &nBits);
						mul_compact(nBits, weight, out_diff);
					}
					else
						mul_compact(last_diff, weight, out_diff);

					//check proof of stake
					if (cmp_hashle(pos_hash, out_diff) >= 0)
					{
						hash_t					rtxhash;
						mem_zone_ref			node_txs = { PTR_NULL };

						compute_tx_sign_hash	(&newtx, 0, &script, hash_type, txh);
						/*
						size_t				length;
						unsigned char		*buffer;
						hash_t			tx_hash
						length = get_node_size(&newtx);
						buffer = (unsigned char *)malloc_c(length + 4);
						*((unsigned int *)(buffer + length)) = hash_type;
						write_node			(&newtx, buffer);
						mbedtls_sha256		(buffer, length + 4, tx_hash, 0);
						mbedtls_sha256		(tx_hash, 32, txh, 0);
						free_c				(buffer);
						*/
						n = 32;
						while (n--)rtxhash[n] = txh[31 - n];
						tree_manager_set_child_value_hash	(result, "txhash"	, rtxhash);
						tree_manager_set_child_value_btcaddr(result, "addr"		, pubaddr);
						if (tree_manager_find_child_node(&my_node, NODE_HASH("tx mem pool"), NODE_BITCORE_TX_LIST, &node_txs))
						{
							tree_manager_set_child_value_bhash	(&newtx, "tx hash", txh);
							tree_manager_node_add_child			(&node_txs, &newtx);
							release_zone_ref					(&node_txs);
						}
						ret = 1;
					}
				}
				release_zone_ref					(&newtx);
			}
		}
	}

	release_zone_ref(&vout);
	release_zone_ref(&prevtx);
	free_string(&script);
	return ret;
}


OS_API_C_FUNC(int) getstaking(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{
	mem_zone_ref	last_blk		= { PTR_NULL };
	struct string	pos_hash_data	= { PTR_NULL };
	int ret = 0;

	if (tree_manager_find_child_node(&my_node, NODE_HASH("last block"), NODE_BITCORE_BLK_HDR, &last_blk))
	{
		unsigned char chash[65];
		hash_t txHash, out_diff;
		mem_zone_ref pn = { PTR_NULL };
		unsigned int OutIdx, target, block_time,n;
		uint64_t	amount;

		tree_manager_get_child_at		(params, 0, &pn);
		tree_manager_get_node_str		(&pn, 0, chash,65, 0);
		release_zone_ref				(&pn);

		n = 0;
		while (n < 32)
		{
			char	hex[3];
			hex[0]		= chash[n * 2 + 0];
			hex[1]		= chash[n * 2 + 1];
			hex[2]		= 0;
			txHash[31-n]= strtoul_c(hex, PTR_NULL, 16);
			n++;
		}
			
		tree_manager_get_child_at(params, 1, &pn);
		tree_mamanger_get_node_dword(&pn, 0, &OutIdx);
		release_zone_ref(&pn);

		get_target_spacing				(&target);
		tree_manager_get_child_value_i32(&last_blk, NODE_HASH("time"), &block_time);

		memset_c(out_diff, 0, sizeof(hash_t));

		if (get_tx_pos_hash_data(&last_blk, txHash, OutIdx, &pos_hash_data, &amount, out_diff))
		{
			hash_t rout_diff;

			n = 32;
			while (n--)rout_diff[n]=out_diff[31 - n];

			tree_manager_set_child_value_str (result , "hash_data"		, pos_hash_data.str);
			tree_manager_set_child_value_hash(result , "difficulty"		, rout_diff);
			tree_manager_set_child_value_i64(result  , "weight"			, amount);
			tree_manager_set_child_value_i32 (result , "block_target"	, target);
			tree_manager_set_child_value_i32 (result , "now"			, get_time_c());
			tree_manager_set_child_value_i32 (result , "last_block_time", block_time);
			ret = 1;
		}
		free_string		(&pos_hash_data);
		release_zone_ref(&last_blk);
	}

	return ret;
}

OS_API_C_FUNC(int) importkeypair(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{
	btc_addr_t pubaddr;
	dh_key_t pub, priv;
	mem_zone_ref username_n = { PTR_NULL }, pubkey_n = { PTR_NULL }, privkey_n = { PTR_NULL };
	struct string username = { PTR_NULL }, xpubkey = { PTR_NULL }, xprivkey = { PTR_NULL };
	struct string user_key_file = { PTR_NULL };
	size_t keys_data_len = 0;
	unsigned char *keys_data = PTR_NULL;
	int found;

	tree_manager_get_child_at(params, 0, &username_n);
	tree_manager_get_child_at(params, 1, &pubkey_n);
	tree_manager_get_child_at(params, 2, &privkey_n);
	tree_manager_get_node_istr(&username_n, 0, &username, 0);
	tree_manager_get_node_istr(&pubkey_n, 0, &xpubkey, 0);
	tree_manager_get_node_istr(&privkey_n, 0, &xprivkey, 0);
	release_zone_ref(&privkey_n);
	release_zone_ref(&pubkey_n);
	release_zone_ref(&username_n);

	if (xpubkey.len == 66)
	{
		int n = 33;
		while (n--)
		{
			char    hex[3];
			hex[0] = xpubkey.str[n * 2 + 0];
			hex[1] = xpubkey.str[n * 2 + 1];
			hex[2] = 0;
			pub[n] = strtoul_c(hex, PTR_NULL, 16);
		}
		key_to_addr(pub, pubaddr);
	}

	memset_c(priv, 0, sizeof(dh_key_t));
	if ((xprivkey.len > 0) && (xprivkey.len <= sizeof(dh_key_t)))
	{
		int n = xprivkey.len;
		while (n--)
		{
			char    hex[3];
			hex[0] = xprivkey.str[n * 2 + 0];
			hex[1] = xprivkey.str[n * 2 + 1];
			hex[2] = 0;
			priv[n] = strtoul_c(hex, PTR_NULL, 16);
		}
	}

	create_dir("keypairs");
	make_string(&user_key_file, "keypairs");
	cat_cstring_p(&user_key_file, username.str);

	found = 0;

	if (get_file(user_key_file.str, &keys_data, &keys_data_len))
	{
		mem_ptr keys_ptr = keys_data;
		while (keys_data_len > 0)
		{
			if (!memcmp_c(keys_ptr, pubaddr, sizeof(btc_addr_t)))
			{
				found = 1;
				break;
			}
			keys_ptr = mem_add(keys_ptr, (sizeof(btc_addr_t) + sizeof(dh_key_t)));
			keys_data_len -= (sizeof(btc_addr_t) + sizeof(dh_key_t));
		}
		free_c(keys_data);
	}

	if (!found)
	{
		mem_zone_ref tx_list = { PTR_NULL }, my_list = { PTR_NULL };
		mem_zone_ref_ptr tx = PTR_NULL;

		append_file(user_key_file.str, pubaddr, sizeof(btc_addr_t));
		append_file(user_key_file.str, priv, sizeof(dh_key_t));
		if (tree_manager_create_node("txs", NODE_BITCORE_HASH_LIST, &tx_list))
		{
			struct string	 adr_path = { 0 };
			make_string(&adr_path, "adrs");
			cat_ncstring_p(&adr_path, pubaddr, 34);
			if (stat_file(adr_path.str) == 0)
			{
				struct string path = { 0 };
				clone_string(&path, &adr_path);
				cat_cstring_p(&path, "spent");
				rm_dir(path.str);
				free_string(&path);

				clone_string(&path, &adr_path);
				cat_cstring_p(&path, "unspent");
				rm_dir(path.str);
				free_string(&path);

				clone_string(&path, &adr_path);
				cat_cstring_p(&path, "stakes");
				del_file(path.str);
				free_string(&path);
			}

			create_dir(adr_path.str);

			free_string(&adr_path);

			load_tx_addresses(pubaddr, &tx_list);
			for (tree_manager_get_first_child(&tx_list, &my_list, &tx); ((tx != NULL) && (tx->zone != NULL)); tree_manager_get_next_child(&my_list, &tx))
			{
				hash_t tx_hash;

				tree_manager_get_node_hash(tx, 0, tx_hash);
				store_tx_wallet(pubaddr, tx_hash);
			}
			release_zone_ref(&tx_list);
		}

	}
	free_string(&user_key_file);
	free_string(&username);
	free_string(&xpubkey);
	free_string(&xprivkey);
	return 1;
}

OS_API_C_FUNC(int) getprivaddr(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{
	mem_zone_ref	pn					= { PTR_NULL }, addr_list	= { PTR_NULL };
	struct string	pubaddr				= { PTR_NULL },	username	= { PTR_NULL };
	struct string	user_key_file		= { PTR_NULL };
	unsigned char	*keys_data			= PTR_NULL;
	size_t			keys_data_len		= 0;
	int				ret					= 0;

	tree_manager_get_child_at	(params, 0, &pn);
	tree_manager_get_node_istr	(&pn, 0, &username, 0);
	release_zone_ref			(&pn);

	tree_manager_get_child_at	(params, 1, &pn);
	tree_manager_get_node_istr	(&pn, 0, &pubaddr, 0);
	release_zone_ref			(&pn);
	
	make_string		(&user_key_file, "keypairs");
	cat_cstring_p	(&user_key_file, username.str);
	if (get_file(user_key_file.str, &keys_data, &keys_data_len))
	{
		unsigned char *keys_ptr = keys_data;
		while (keys_data_len > 0)
		{
			if (!strncmp_c(keys_ptr, pubaddr.str , sizeof(btc_addr_t)))
			{
				char hexk[129];
				int  n=0;
				while (n < 64)
				{
					hexk[n * 2 + 0] = hex_chars[keys_ptr[sizeof(btc_addr_t) + n] >> 4];
					hexk[n * 2 + 1] = hex_chars[keys_ptr[sizeof(btc_addr_t) + n] & 0x0F];
					n++;
				}
				hexk[64]	= 0;
				ret			= 1;
				tree_manager_set_child_value_str(result, "privkey", hexk);
				break;
			}
			keys_ptr		 = mem_add(keys_ptr, (sizeof(btc_addr_t) + sizeof(dh_key_t)));
			keys_data_len	-= (sizeof(btc_addr_t) + sizeof(dh_key_t));
		
		}
		free_c(keys_data);
	}
	free_string(&pubaddr);
	free_string(&username);
	free_string(&user_key_file);
	return ret;
}

OS_API_C_FUNC(int) getpubaddrs(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{
	mem_zone_ref username_n = { PTR_NULL }, addr_list = { PTR_NULL };
	struct string username = { PTR_NULL };
	struct string user_key_file = { PTR_NULL };
	size_t			keys_data_len = 0;
	uint64_t		conf_amount, unconf_amount;
	unsigned int	minconf;
	unsigned char	*keys_data = PTR_NULL;

	if (!tree_manager_get_child_at(params, 0, &username_n))
		return 0;

	tree_manager_get_node_istr	(&username_n, 0, &username, 0);
	release_zone_ref			(&username_n);

	if (!tree_manager_add_child_node(result, "addrs", NODE_JSON_ARRAY, &addr_list))
		return 0;
	
	make_string		(&user_key_file, "keypairs");
	cat_cstring_p	(&user_key_file, username.str);

	minconf = 1;

	if (get_file(user_key_file.str, &keys_data, &keys_data_len))
	{
		mem_ptr keys_ptr=keys_data;
		while (keys_data_len >= (sizeof(btc_addr_t) + sizeof(dh_key_t)))
		{
			mem_zone_ref new_addr = { PTR_NULL };
			conf_amount = 0;
			unconf_amount = 0;

			get_balance	(keys_ptr, &conf_amount, &unconf_amount, minconf);
			if(tree_manager_add_child_node			(&addr_list	, "addr"		 , NODE_GFX_OBJECT, &new_addr))
			{
				tree_manager_set_child_value_btcaddr(&new_addr	, "address"		 , keys_ptr);
				tree_manager_set_child_value_i64	(&new_addr	, "amount"		 , conf_amount);
				tree_manager_set_child_value_i64	(&new_addr	, "unconf_amount", unconf_amount);
				release_zone_ref					(&new_addr);
			}			
			keys_ptr		 =	mem_add(keys_ptr ,(sizeof(btc_addr_t) + sizeof(dh_key_t)));
			keys_data_len   -= (sizeof(btc_addr_t) + sizeof(dh_key_t));
		}
		free_c(keys_data);
	}
	
	release_zone_ref			(&addr_list);
	free_string					(&user_key_file);
	free_string					(&username);
	return 1;
}