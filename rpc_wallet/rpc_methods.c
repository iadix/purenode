//copyright antoine bentue-ferrer 2016
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

#include "../node_adx/node_api.h"
#include "../block_adx/block_api.h"
#include "../wallet/wallet_api.h"

#ifdef _DEBUG
C_IMPORT int			C_API_FUNC		get_last_stake_modifier(mem_zone_ref_ptr pindex, hash_t nStakeModifier, unsigned int *nModifierTime);
C_IMPORT int			C_API_FUNC		get_tx_pos_hash_data(mem_zone_ref_ptr hdr, const hash_t txHash, unsigned int OutIdx, struct string *hash_data,uint64_t *amount, hash_t out_diff);
C_IMPORT int			C_API_FUNC		get_blk_staking_infos(mem_zone_ref_ptr blk, const char *blk_hash, mem_zone_ref_ptr infos);
C_IMPORT int			C_API_FUNC		store_tx_staking(mem_zone_ref_ptr tx, hash_t tx_hash, btc_addr_t stake_addr, uint64_t	stake_in);
C_IMPORT int			C_API_FUNC		get_target_spacing(unsigned int *target);
C_IMPORT unsigned int	C_API_FUNC		get_current_pos_difficulty();
C_IMPORT int			C_API_FUNC		get_stake_reward(uint64_t height,uint64_t *reward);
C_IMPORT int			C_API_FUNC		compute_tx_pos(mem_zone_ref_ptr tx, hash_t StakeModifier, unsigned int txTime, hash_t pos_hash, uint64_t *weight);
C_IMPORT int			C_API_FUNC		create_pos_block(hash_t pHash, mem_zone_ref_ptr tx, mem_zone_ref_ptr newBlock);
C_IMPORT int			C_API_FUNC		check_tx_pos(mem_zone_ref_ptr hdr, mem_zone_ref_ptr tx);
C_IMPORT int			C_API_FUNC		get_min_stake_depth(unsigned int *depth);

#else
get_blk_staking_infos_func_ptr		 get_blk_staking_infos = PTR_INVALID;
store_tx_staking_func_ptr			 store_tx_staking = PTR_INVALID;
get_tx_pos_hash_data_func_ptr		 get_tx_pos_hash_data = PTR_INVALID;
get_target_spacing_func_ptr			 get_target_spacing = PTR_INVALID;
get_stake_reward_func_ptr			 get_stake_reward = PTR_INVALID;
get_last_stake_modifier_func_ptr	 get_last_stake_modifier = PTR_INVALID;
get_current_pos_difficulty_func_ptr	 get_current_pos_difficulty = PTR_INVALID;
compute_tx_pos_func_ptr				 compute_tx_pos = PTR_INVALID;
create_pos_block_func_ptr			 create_pos_block = PTR_INVALID;
check_tx_pos_func_ptr				 check_tx_pos = PTR_INVALID;
get_min_stake_depth_func_ptr		 get_min_stake_depth = PTR_INVALID;
#endif






unsigned int			WALLET_VERSION = 60000;
unsigned int			min_staking_depth = 2;
mem_zone_ref			my_node = { PTR_INVALID };
btc_addr_t				src_addr_list[1024] = { 0xCDFF };

OS_API_C_FUNC(int) set_node_rpc_wallet(mem_zone_ref_ptr node,tpo_mod_file *pos_mod)
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
	compute_tx_pos				= (get_current_pos_difficulty_func_ptr)	get_tpo_mod_exp_addr_name(pos_mod, "compute_tx_pos", 0);
	check_tx_pos				= (check_tx_pos_func_ptr)				get_tpo_mod_exp_addr_name(pos_mod, "check_tx_pos", 0);
	create_pos_block			= (create_pos_block_func_ptr)			get_tpo_mod_exp_addr_name(pos_mod, "create_pos_block", 0);
	get_min_stake_depth			= (get_min_stake_depth_func_ptr)		get_tpo_mod_exp_addr_name(pos_mod, "get_min_stake_depth", 0);
#endif
	if (get_min_stake_depth != PTR_NULL)
		get_min_stake_depth(&min_staking_depth);

	create_dir("acpw");
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


	if (tree_manager_find_child_node(&my_node, NODE_HASH("last_block"), NODE_BITCORE_BLK_HDR, &last_blk))
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

	if (tree_manager_get_child_value_i32(&my_node, NODE_HASH("current_pos_diff"), &pos_diff))
		SetCompact(pos_diff, posd);
	
	if(tree_manager_get_child_value_i32(&my_node, NODE_HASH("current_pow_diff"), &pow_diff))
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

	if (!tree_manager_get_child_at(params, 0, &addrs))return 0;
	tree_manager_add_child_node(result, "txs", NODE_JSON_ARRAY, &tx_out_list);

	memset_c(null_hash, 0, sizeof(hash_t));

	for (tree_manager_get_first_child(&addrs, &my_list, &addr); ((addr != NULL) && (addr->zone != NULL)); tree_manager_get_next_child(&my_list, &addr))
	{
		btc_addr_t			my_addr;
		mem_zone_ref		tx_list = { PTR_NULL };
		mem_zone_ref		my_tlist = { PTR_NULL }, my_tx = { PTR_NULL };
		mem_zone_ref_ptr	tx = PTR_NULL;

		if (!tree_manager_create_node("txs", NODE_BITCORE_HASH_LIST, &tx_list))
			break;
				
		tree_manager_get_node_btcaddr	(addr, 0, my_addr);
		load_tx_addresses				(my_addr, &tx_list);

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

							tree_manager_get_child_value_hash(&vin, NODE_HASH("txid"), prevOutHash);
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
	mem_zone_ref		minconf = { PTR_NULL }, maxconf = { PTR_NULL }, received = { PTR_NULL }, addrs = { PTR_NULL };
	mem_zone_ref		my_list = { PTR_NULL };
	mem_zone_ref_ptr	addr;
	uint64_t			amount;
	size_t				min_conf=0, max_conf=9999;
	size_t				max = 200, ntx = 0;

	if (tree_manager_get_child_at(params, 0, &minconf))
	{
		tree_mamanger_get_node_dword(&minconf, 0, &min_conf);
		release_zone_ref(&minconf);
	}
	if (tree_manager_get_child_at(params, 1, &maxconf))
	{
		tree_mamanger_get_node_dword(&maxconf, 0, &max_conf);
		release_zone_ref(&maxconf);
	}
	if (!tree_manager_get_child_at(params, 2, &addrs))return 0;
	
	if (!tree_manager_add_child_node(result, "received", NODE_JSON_ARRAY, &received))
		return 0;

	amount = 0;
	
	for (tree_manager_get_first_child(&addrs, &my_list, &addr); ((addr != NULL) && (addr->zone != NULL)); tree_manager_get_next_child(&my_list, &addr))
	{
		btc_addr_t my_addr;
		tree_manager_get_node_btcaddr	(addr, 0, my_addr);
		list_received					(my_addr, &received,min_conf,max_conf, &amount,&ntx,&max);
	}

	tree_manager_set_child_value_i64(result, "ntx", ntx);
	tree_manager_set_child_value_i64(result, "total", amount);

	release_zone_ref(&received);
	release_zone_ref(&addrs);
	

	return 1;
}
OS_API_C_FUNC(int) listspent(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{
	mem_zone_ref minconf = { PTR_NULL }, maxconf = { PTR_NULL }, spents = { PTR_NULL }, addrs = { PTR_NULL };
	mem_zone_ref  my_list = { PTR_NULL };
	mem_zone_ref_ptr addr;
	uint64_t			total = 0;
	size_t				min_conf = 0, max_conf = 9999;
	size_t				max = 200, ntx = 0;



	if (tree_manager_get_child_at(params, 0, &minconf))
	{
		tree_mamanger_get_node_dword(&minconf, 0, &min_conf);
		release_zone_ref(&minconf);
	}
	if (tree_manager_get_child_at(params, 1, &maxconf))
	{
		tree_mamanger_get_node_dword(&maxconf, 0, &max_conf);
		release_zone_ref(&maxconf);
	}
	if (!tree_manager_get_child_at(params, 2, &addrs))return 0;

	if (!tree_manager_add_child_node(result, "spents", NODE_JSON_ARRAY, &spents))
		return 0;
	
	for (tree_manager_get_first_child(&addrs, &my_list, &addr); ((addr != NULL) && (addr->zone != NULL)); tree_manager_get_next_child(&my_list, &addr))
	{
		btc_addr_t my_addr;

		tree_manager_get_node_btcaddr(addr, 0, my_addr);
		list_spent(my_addr, &spents, min_conf, max_conf, &total, &ntx, &max);
	}

	tree_manager_set_child_value_i64(result, "ntx", ntx);
	tree_manager_set_child_value_i64(result, "total", total);

	release_zone_ref(&spents);
	release_zone_ref(&addrs);


	return 1;
}

OS_API_C_FUNC(int) submittx(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{
	hash_t			txHash;
	unsigned char	chash[65];
	mem_zone_ref	pn = { PTR_NULL }, node_txs = { PTR_NULL };
	int				n,ret;

	if (!tree_manager_get_child_at(params, 0, &pn))return 0;
	tree_manager_get_node_str(&pn, 0, chash, 65, 0);
	release_zone_ref(&pn);

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

	ret = tree_manager_find_child_node(&my_node, NODE_HASH("tmp tx pool"), NODE_BITCORE_TX_LIST, &node_txs);
	if (ret)
	{
		mem_zone_ref tx = { PTR_NULL }, etx = { PTR_NULL };

		ret = tree_find_child_node_by_member_name_hash(&node_txs, NODE_BITCORE_TX, "txid", txHash, &tx);
		if (ret)
		{
			ret = tree_manager_find_child_node(&my_node, NODE_HASH("submitted txs"), NODE_BITCORE_TX_LIST, &etx);
			if (ret)
			{
				tree_manager_node_add_child				(&etx, &tx);
				release_zone_ref						(&etx);

				tree_remove_child_by_member_value_hash	(&node_txs, NODE_BITCORE_TX, "txid", txHash);
				tree_manager_set_child_value_hash		(result, "txid", txHash);
			}
		}
	}

	release_zone_ref(&node_txs);

	return ret;

}

OS_API_C_FUNC(int) signtxinput(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{
	hash_t			txHash;
	unsigned char	chash[65];
	struct	string  bsign = { PTR_NULL }, bpubkey = { PTR_NULL }, sign = { PTR_NULL }, inPubKey = { PTR_NULL };
	mem_zone_ref	pn = { PTR_NULL }, node_txs = { PTR_NULL }, tx = { PTR_NULL };
	int				ret = 0;
	unsigned int	n, inIdx;
	unsigned char   hash_type = 1;

	if (!tree_manager_get_child_at(params, 0, &pn))return 0;
	tree_manager_get_node_str(&pn, 0, chash, 65, 0);
	release_zone_ref(&pn);

	n = 0;
	while (n < 32)
	{
		char	hex[3];
		hex[0] = chash[n * 2 + 0];
		hex[1] = chash[n * 2 + 1];
		hex[2] = 0;
		txHash[31-n] = strtoul_c(hex, PTR_NULL, 16);
		n++;
	}


	if (!tree_manager_get_child_at(params, 1, &pn))return 0;
	tree_mamanger_get_node_dword(&pn, 0, &inIdx);
	release_zone_ref(&pn);

	
	if (!tree_manager_get_child_at(params, 2, &pn))return 0;
	tree_manager_get_node_istr(&pn, 0, &sign, 0);
	release_zone_ref(&pn);

	bsign.len = (sign.len / 2) + 1;
	bsign.size = bsign.len + 1;
	bsign.str = malloc_c(bsign.size);
	n = 0;
	while (n < bsign.len)
	{
		char	hex[3];
		hex[0] = sign.str[n * 2 + 0];
		hex[1] = sign.str[n * 2 + 1];
		hex[2] = 0;
		bsign.str[n] = strtoul_c(hex, PTR_NULL, 16);
		n++;
	}
	free_string(&sign);

	bsign.str[bsign.len - 1] = hash_type;

	if (tree_manager_get_child_at(params, 3, &pn))
	{
		struct string inPubKey = { PTR_NULL };

		tree_manager_get_node_istr(&pn, 0, &inPubKey, 16);
		release_zone_ref(&pn);
		if (inPubKey.len == 66)
		{
			bpubkey.len  = 33;
			bpubkey.size = bpubkey.len + 1;
			bpubkey.str  = malloc_c(bpubkey.size);

			n = 0;
			while (n < bpubkey.len)
			{
				char	hex[3];
				hex[0] = inPubKey.str[n * 2 + 0];
				hex[1] = inPubKey.str[n * 2 + 1];
				hex[2] = 0;
				bpubkey.str[n] = strtoul_c(hex, PTR_NULL, 16);
				n++;
			}
		}
		free_string(&inPubKey);
	}

	if (tree_manager_find_child_node(&my_node, NODE_HASH("tmp tx pool"), NODE_BITCORE_TX_LIST, &node_txs))
	{
		if (tree_find_child_node_by_member_name_hash(&node_txs, NODE_BITCORE_TX, "txid", txHash, &tx))
		{
			ret = tx_sign(&tx, inIdx, hash_type, &bsign, &bpubkey);
			if (ret)
			{
				hash_t		 txh;
				mem_zone_ref etx = { PTR_NULL };

				compute_tx_hash						(&tx, txh);
				tree_manager_set_child_value_bhash	(&tx, "txid", txh);
				tree_manager_set_child_value_hash	(result, "txid", txh);
			}
			release_zone_ref(&tx);
		}
		release_zone_ref(&node_txs);
	}
	free_string(&bpubkey);
	free_string(&bsign);
	return ret;

}
OS_API_C_FUNC(int) maketxfrom(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{
	btc_addr_t			dstAddr,changeAddr;
	mem_zone_ref		pn = { PTR_NULL }, addrs = { PTR_NULL };
	mem_zone_ref		script_node = { PTR_NULL }, inList = { PTR_NULL }, node_txs = { PTR_NULL }, my_list = { PTR_NULL }, new_tx = { PTR_NULL };
	struct	string		oScript = { PTR_NULL };
	mem_zone_ref_ptr	addr;
	uint64_t			nAmount, total_unspent, paytxfee, inFees;
	size_t				min_conf = 0, max_conf = 9999;
	size_t				max = 200, ntx = 0;
	size_t nin;
	if (!tree_manager_get_child_at(params, 1, &pn))
		return 0;

	tree_mamanger_get_node_qword(&pn, 0, &nAmount);
	release_zone_ref(&pn);

	if (!tree_manager_get_child_at(params, 2, &pn))
		return 0;
	
	tree_manager_get_node_btcaddr(&pn, 0, dstAddr);
	release_zone_ref(&pn);
	

	if (!tree_manager_get_child_at(params, 0, &addrs))
		return 0;

	if (tree_manager_get_child_at(params, 3, &pn))
	{
		tree_mamanger_get_node_qword(&pn, 0, &inFees);
		release_zone_ref(&pn);
	}
	else
		inFees = 0;

	
	if (tree_manager_get_child_at(params, 4, &pn))
	{
		tree_mamanger_get_node_dword(&pn, 0, &min_conf);
		release_zone_ref(&pn);
	}
	else
		min_conf = 10;

	if (tree_manager_get_child_at(params, 5, &pn))
	{
		tree_mamanger_get_node_dword(&pn, 0, &max_conf);
		release_zone_ref(&pn);
	}
	else
		max_conf = 9999;


	
	
	if (tree_manager_get_child_value_i64(&my_node, NODE_HASH("paytxfee"), &paytxfee))
	{
		if (inFees > paytxfee)
			inFees = paytxfee;
	}
	else if (inFees > 0)
		paytxfee = inFees;
	else
		paytxfee = 0;
	

	new_transaction(&new_tx, get_time_c());


	memset_c(changeAddr, 0, sizeof(btc_addr_t));
	total_unspent = 0;
	for (tree_manager_get_first_child(&addrs, &my_list, &addr); ((addr != NULL) && (addr->zone != NULL)); tree_manager_get_next_child(&my_list, &addr))
	{
		btc_addr_t						my_addr;
		tree_manager_get_node_btcaddr	(addr, 0, my_addr);
		get_tx_inputs_from_addr			(my_addr, &total_unspent, nAmount+paytxfee, min_conf, max_conf, &new_tx);

		if (changeAddr[0] == 0)memcpy_c	(changeAddr, my_addr,sizeof(btc_addr_t));
	}
	tree_manager_set_child_value_i64(result, "total", total_unspent);
	

	if (tree_manager_create_node("script", NODE_BITCORE_SCRIPT, &script_node))
	{
		create_p2sh_script(dstAddr, &script_node);
		serialize_script(&script_node, &oScript);
		release_zone_ref(&script_node);
	}

	tx_add_output		(&new_tx, nAmount, &oScript);
	free_string			(&oScript);

	if (total_unspent > nAmount)
	{
		if (tree_manager_create_node("script", NODE_BITCORE_SCRIPT, &script_node))
		{
			create_p2sh_script(changeAddr, &script_node);
			serialize_script(&script_node, &oScript);
			release_zone_ref(&script_node);
		}

		tx_add_output(&new_tx, total_unspent - nAmount - paytxfee, &oScript);
		free_string	 (&oScript);
	}

	if (tree_manager_find_child_node(&new_tx, NODE_HASH("txsin"), NODE_BITCORE_VINLIST, &inList))
	{
		mem_zone_ref_ptr	input = PTR_NULL;

		for (nin = 0, tree_manager_get_first_child(&inList, &my_list, &input); ((input != PTR_NULL) && (input->zone != PTR_NULL)); tree_manager_get_next_child(&my_list, &input), nin++)
		{
			hash_t				txh,hh;
			hash_t				h;
			btc_addr_t			src_addr;
			struct string		script = { PTR_NULL };
			uint64_t			inAmount;
			unsigned int		oIdx,cnt;

			tree_manager_get_child_value_hash(input, NODE_HASH("txid"), h);
			tree_manager_get_child_value_i32(input, NODE_HASH("idx"), &oIdx);

			get_tx_output_script	(h, oIdx, &script,&inAmount);
			get_out_script_address	(&script, PTR_NULL, src_addr);


			tree_manager_set_child_value_btcaddr(input, "srcaddr", src_addr);
			tree_manager_set_child_value_i32(input, "index", nin);
			tree_manager_set_child_value_i64(input, "value", inAmount);



			compute_tx_sign_hash(&new_tx, nin, &script, 1, txh);
			free_string			(&script);

			cnt = 32;
			while (cnt--)
				hh[31 - cnt] = txh[cnt];

			tree_manager_set_child_value_hash(input, "signHash", hh);
		}
	}


	if (tree_manager_find_child_node(&my_node, NODE_HASH("tmp tx pool"), NODE_BITCORE_TX_LIST, &node_txs))
	{
		hash_t txh;
		compute_tx_hash						(&new_tx, txh);
		tree_manager_set_child_value_bhash	(&new_tx, "txid", txh);
		tree_manager_node_add_child			(&node_txs, &new_tx);

		
		release_zone_ref					(&node_txs);
	}
	tree_manager_node_add_child				(result, &new_tx);
	release_zone_ref						(&addrs);
	release_zone_ref						(&new_tx);
	
	return 1;
}

OS_API_C_FUNC(int) listunspent(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{
	mem_zone_ref		minconf = { PTR_NULL }, maxconf = { PTR_NULL }, unspents = { PTR_NULL }, addrs = { PTR_NULL };
	mem_zone_ref		my_list = { PTR_NULL };
	mem_zone_ref_ptr	addr;
	uint64_t			total=0;
	size_t				min_conf = 0, max_conf = 9999;
	size_t				max = 200,ntx=0;


	if (tree_manager_get_child_at(params, 0, &minconf))
	{
		tree_mamanger_get_node_dword(&minconf, 0, &min_conf);
		release_zone_ref(&minconf);
	}
	if (tree_manager_get_child_at(params, 1, &maxconf))
	{
		tree_mamanger_get_node_dword(&maxconf, 0, &max_conf);
		release_zone_ref(&maxconf);
	}
	if (!tree_manager_get_child_at(params, 2, &addrs))
		return 0;

	if (!tree_manager_add_child_node(result, "unspents", NODE_JSON_ARRAY, &unspents))
		return 0;

	for (tree_manager_get_first_child(&addrs, &my_list, &addr); ((addr != NULL) && (addr->zone != NULL)); tree_manager_get_next_child(&my_list, &addr))
	{
		btc_addr_t						my_addr;
		tree_manager_get_node_btcaddr	(addr, 0, my_addr);
		list_unspent					(my_addr, &unspents, min_conf, max_conf, &total, &ntx, &max);
	}


	tree_manager_set_child_value_i64(result, "ntx", ntx);
	tree_manager_set_child_value_i64(result, "total",total );

	release_zone_ref			(&addrs);
	release_zone_ref			(&unspents);


	return 1;
}

OS_API_C_FUNC(int) listreceivedbyaddress(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{
	mem_zone_ref	minconf = { PTR_NULL }, maxconf = { PTR_NULL },addr_list = { PTR_NULL };
	struct string	dir_list = { PTR_NULL };
	size_t			min_conf = 0, max_conf = 9999, ntx;
	size_t			cur, nfiles;


	if (!tree_manager_add_child_node(result, "addrs", NODE_JSON_ARRAY, &addr_list))
		return 0;
	
	if (tree_manager_get_child_at(params, 0, &minconf))
	{
		tree_mamanger_get_node_dword(&minconf, 0, &min_conf);
		release_zone_ref(&minconf);
	}
	else
		min_conf = 1;

	if (tree_manager_get_child_at(params, 1, &maxconf))
	{
		tree_mamanger_get_node_dword(&maxconf, 0, &max_conf);
		release_zone_ref(&maxconf);
	}
	else
		max_conf = 0;

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
				char				addr[35];
				uint64_t			amount;
				size_t				max = 0;

				memcpy_c(addr, optr, (sz<34)?sz:34); 
				addr[34] = 0;
				amount = 0;
				ntx = 0;
				
				list_received					(addr, PTR_NULL, min_conf, max_conf, &amount, &ntx,&max);
				tree_manager_set_child_value_str(&new_addr, "addr", addr);
				tree_manager_set_child_value_i64(&new_addr, "amount", amount);
				tree_manager_set_child_value_i64(&new_addr, "ntx", ntx);
				release_zone_ref				(&new_addr);
			}
			cur++;
			optr = ptr + 1;
			dir_list_len -= sz;
		}
		free_string(&dir_list);
	}
	
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

	if (tree_manager_get_child_at(params, 0, &pubkey_n))
	{
		tree_manager_get_node_istr(&pubkey_n, 0, &xpubkey, 0);
		release_zone_ref(&pubkey_n);
	}

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
	else if (xpubkey.len == 66)
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

	if (tree_manager_get_child_at(params, 0, &minconf))
	{
		tree_mamanger_get_node_dword(&minconf, 0, &iminconf);
		release_zone_ref			(&minconf);
	}

	if (iminconf < min_staking_depth)
		iminconf = min_staking_depth;

	if (tree_manager_get_child_at(params, 1, &maxconf))
	{
		//tree_mamanger_get_node_dword(&maxconf, 0, &iminconf);
		release_zone_ref(&maxconf);
	}
	if (!tree_manager_get_child_at(params, 2, &addrs))return 0;

	if (!tree_manager_find_child_node(&my_node, NODE_HASH("last_block"), NODE_BITCORE_BLK_HDR, &last_blk))
	{
		release_zone_ref(&addrs);
		return 0;
	}

	if (!tree_manager_add_child_node(result, "unspents", NODE_JSON_ARRAY, &unspents))
	{
		release_zone_ref(&last_blk);
		release_zone_ref(&addrs);
		return 0;
	}


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
	return 1;
}

int rescan_addr(btc_addr_t pubaddr)
{
	mem_zone_ref	 tx_list = { PTR_NULL }, txlist = { PTR_NULL };
	struct string	 adr_path = { PTR_NULL };
	mem_zone_ref_ptr tx=PTR_NULL;

	if (pubaddr == PTR_NULL)return 0;
	if (strlen_c(pubaddr) < 34)return 0;

	make_string		(&adr_path, "adrs");
	cat_ncstring_p	(&adr_path, pubaddr, 34);

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

	rm_dir(adr_path.str);
	create_dir(adr_path.str);

	if (tree_manager_create_node("txs", NODE_BITCORE_HASH_LIST, &tx_list))
	{
		load_tx_addresses(pubaddr, &tx_list);
		for (tree_manager_get_first_child(&tx_list, &txlist, &tx); ((tx != NULL) && (tx->zone != NULL)); tree_manager_get_next_child(&txlist, &tx))
		{
			hash_t tx_hash;
			tree_manager_get_node_hash(tx, 0, tx_hash);
			store_tx_wallet(pubaddr, tx_hash);
		}
		release_zone_ref(&tx_list);
	}

	free_string(&adr_path);

	return 1;
}

OS_API_C_FUNC(int) rescanaddrs(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{
	mem_zone_ref	 addrs = { PTR_NULL }, addr_list = { PTR_NULL };
	mem_zone_ref_ptr addr;

	if (!tree_manager_get_child_at(params, 0, &addrs))return 0;

	for (tree_manager_get_first_child(&addrs, &addr_list, &addr); ((addr != NULL) && (addr->zone != NULL)); tree_manager_get_next_child(&addr_list, &addr))
	{
		btc_addr_t			pubaddr;
		memset_c(pubaddr, 0, sizeof(btc_addr_t));
		if (!tree_manager_get_node_btcaddr(addr, 0, pubaddr))continue;
		rescan_addr(pubaddr);
	}
	release_zone_ref(&addrs);

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

	if (tree_manager_find_child_node(&my_node, NODE_HASH("submitted blocks"), NODE_BITCORE_BLOCK_LIST, &node_blks))
	{
		if (tree_find_child_node_by_member_name_hash(&node_blks, NODE_BITCORE_BLOCK, "blkHash", blkHash, &blk))
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
	int				ret = 0;
	unsigned int	n;
	unsigned char   hash_type = 1;
	struct	string  bsign = { PTR_NULL }, bpubkey = { PTR_NULL }, sign = { PTR_NULL }, inPubKey = { PTR_NULL };
	mem_zone_ref	pn = { PTR_NULL }, node_txs = { PTR_NULL }, tx = { PTR_NULL };
	
	if (!tree_manager_get_child_at(params, 0, &pn))return 0;
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
	if (!tree_manager_get_child_at(params, 1, &pn))return 0;
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

	if (tree_manager_get_child_at(params, 2, &pn))
	{
		struct string inPubKey = { PTR_NULL };

		tree_manager_get_node_istr	(&pn, 0, &inPubKey,16);
		release_zone_ref			(&pn);


		if (inPubKey.len == 66)
		{
			bpubkey.len		= 33;
			bpubkey.size	= bpubkey.len + 1;
			bpubkey.str		= malloc_c(bpubkey.size);

			n = 0;
			while (n < bpubkey.len)
			{
				char	hex[3];
				hex[0] = inPubKey.str[n * 2 + 0];
				hex[1] = inPubKey.str[n * 2 + 1];
				hex[2] = 0;
				bpubkey.str[n] = strtoul_c(hex, PTR_NULL, 16);
				n++;
			}
			free_string(&inPubKey);
		}
	}

	if (tree_manager_find_child_node(&my_node, NODE_HASH("tmp tx pool"), NODE_BITCORE_TX_LIST, &node_txs))
	{
		if (tree_find_child_node_by_member_name_hash(&node_txs, NODE_BITCORE_TX, "txid", txHash, &tx))
		{
			mem_zone_ref last_blk = { PTR_NULL }, newBlock = { PTR_NULL };
			ret = tx_sign(&tx, 0, hash_type, &bsign, &bpubkey);
			if (ret)
			{
				if (tree_manager_find_child_node(&my_node, NODE_HASH("last_block"), NODE_BITCORE_BLK_HDR, &last_blk))
				{
					hash_t block_hash;
					tree_manager_get_child_value_hash(&last_blk, NODE_HASH("blkHash"), block_hash);
					if (create_pos_block(block_hash, &tx, &newBlock))
					{
						mem_zone_ref txs = { PTR_NULL }, blk_list = { PTR_NULL };

						node_fill_block_from_mempool(&newBlock);

						if (tree_manager_find_child_node(&my_node, NODE_HASH("submitted blocks"), NODE_BITCORE_BLOCK_LIST, &blk_list))
						{
							hash_t h,rblkh;
							
							tree_manager_get_child_value_hash(&newBlock, NODE_HASH("blkHash"), h);
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
OS_API_C_FUNC(int) getrawmempool(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{
	mem_zone_ref tx_list = { PTR_NULL }, my_list = { PTR_NULL };
	mem_zone_ref_ptr tx = PTR_NULL;
	if (!tree_manager_find_child_node(params, NODE_HASH("mempool"), NODE_BITCORE_TX_LIST, &tx_list))return 0;

	for (tree_manager_get_first_child(&tx_list, &my_list, &tx); ((tx != NULL) && (tx->zone != NULL)); tree_manager_get_next_child(&my_list, &tx))
	{
		mem_zone_ref hn = { PTR_NULL };
		
		if (tree_manager_find_child_node(tx, NODE_HASH("txid"), 0xFFFFFFF, &hn))
		{
			tree_manager_node_add_child(result, &hn);
			release_zone_ref(&hn);
		}
	}
	return 1;
}

OS_API_C_FUNC(int) getstaketx(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{
	unsigned char	chash[65];
	hash_t			txHash, blkhash;
	btc_addr_t		pubaddr;
	char			toto = 0;
	mem_zone_ref	vout = { PTR_NULL }, prevtx = { PTR_NULL }, newtx = { PTR_NULL }, pn = { PTR_NULL };
	struct string   sPubk = { PTR_NULL }, script = { PTR_NULL }, null_str = { PTR_NULL }, bpubkey = { PTR_NULL };
	uint64_t		amount;
	unsigned int	OutIdx, newTxTime,n;
	int				ret;

	null_str.str  = &toto;
	null_str.len  = 0;
	null_str.size = 1;
	
	if (!tree_manager_get_child_at(params, 0, &pn))return 0;
	tree_manager_get_node_str(&pn, 0, chash, 65, 0);
	release_zone_ref(&pn);

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

	if (!tree_manager_get_child_at(params, 1, &pn))return 0;
	tree_mamanger_get_node_dword(&pn, 0, &OutIdx);
	release_zone_ref(&pn);

	if (!tree_manager_get_child_at(params, 2, &pn))return 0;
	tree_mamanger_get_node_dword(&pn, 0, &newTxTime);
	release_zone_ref(&pn);

	if (tree_manager_get_child_at(params, 3, &pn)){
		struct string inPubKey = { PTR_NULL };

		tree_manager_get_node_istr(&pn, 0, &inPubKey, 16);
		release_zone_ref(&pn);

		if (inPubKey.len == 66)
		{
			bpubkey.len = 33;
			bpubkey.size = bpubkey.len + 1;
			bpubkey.str = malloc_c(bpubkey.size);

			n = 0;
			while (n < bpubkey.len)
			{
				char	hex[3];
				hex[0] = inPubKey.str[n * 2 + 0];
				hex[1] = inPubKey.str[n * 2 + 1];
				hex[2] = 0;
				bpubkey.str[n] = strtoul_c(hex, PTR_NULL, 16);
				n++;
			}
		}
		free_string(&inPubKey);
		release_zone_ref(&pn);

	}


	ret = load_tx(&prevtx, blkhash, txHash);
	
	if (ret)ret = get_tx_output(&prevtx, OutIdx, &vout);
	if (ret)ret = tree_manager_get_child_value_istr(&vout, NODE_HASH("script"), &script, 0);
	if (ret)ret = tree_manager_get_child_value_i64(&vout, NODE_HASH("value"), &amount);
	if (ret)ret = get_out_script_address(&script, &sPubk, pubaddr);

	if (ret)
	{
		uint64_t			half_am,rew;
		uint64_t			lb;

		ret = 0;

		lb = get_last_block_height();

		get_stake_reward	(lb,&rew);
		half_am = muldiv64	(amount+rew, 1, 2);

		if (tree_manager_add_child_node(result, "transaction", NODE_BITCORE_TX, &newtx))
		{
			hash_t			txh;
			unsigned int	hash_type = 1;

			if (new_transaction(&newtx, newTxTime))
			{
				mem_zone_ref last_blk = { PTR_NULL };
				struct string oscript = { PTR_NULL };
				
				if (sPubk.str == PTR_NULL)
				{
					mem_zone_ref script_node = { PTR_NULL };
					
					if (tree_manager_create_node("script", NODE_BITCORE_SCRIPT, &script_node))
					{
						create_payment_script(&bpubkey, 0, &script_node);
						serialize_script(&script_node, &oscript);
						release_zone_ref(&script_node);
					}

				}
				else
				{
					clone_string(&oscript, &script);
				}

				tx_add_input (&newtx, txHash, OutIdx, &script);
				tx_add_output(&newtx, 0, &null_str);
				tx_add_output(&newtx, half_am, &oscript);
				tx_add_output(&newtx, half_am, &oscript);
				free_string  (&oscript);
				
				if (tree_manager_find_child_node(&my_node, NODE_HASH("last_block"), NODE_BITCORE_BLK_HDR, &last_blk))
				{
					hash_t					pos_hash, out_diff;
					hash_t					lastStakeModifier;
					unsigned int			ModTime,last_diff;
					uint64_t				weight;

					get_last_stake_modifier (&last_blk, lastStakeModifier, &ModTime);
					ret=compute_tx_pos		(&newtx, lastStakeModifier, newTxTime, pos_hash, &weight);

					if (ret)
					{
						mem_zone_ref			node_txs = { PTR_NULL };

						memset_c(out_diff, 0, sizeof(hash_t));
						last_diff = get_current_pos_difficulty();

						if (last_diff == 0xFFFFFFFF)
						{
							unsigned int					nBits;
							tree_manager_get_child_value_i32(&last_blk, NODE_HASH("bits"), &nBits);
							mul_compact						(nBits, weight, out_diff);
						}
						else
							mul_compact						(last_diff, weight, out_diff);

						//check proof of stake
						if (cmp_hashle(pos_hash, out_diff) >= 0)
						{
							hash_t					rtxhash;
							mem_zone_ref			node_txs = { PTR_NULL };

							compute_tx_sign_hash		(&newtx, 0, &script, hash_type, txh);

							n = 32;
							while (n--)rtxhash[n] = txh[31 - n];
							tree_manager_set_child_value_hash	(result, "txhash"	, rtxhash);
							tree_manager_set_child_value_btcaddr(result, "addr"		, pubaddr);
							
							if (tree_manager_find_child_node(&my_node, NODE_HASH("tmp tx pool"), NODE_BITCORE_TX_LIST, &node_txs))
							{
								tree_manager_set_child_value_bhash	(&newtx, "txid", txh);
								tree_manager_node_add_child			(&node_txs, &newtx);
								release_zone_ref					(&node_txs);
							}
							ret = 1;
						}
					}
				}
				release_zone_ref					(&newtx);
			}
		}
		free_string(&sPubk);
	}

	free_string(&bpubkey);
	release_zone_ref(&vout);
	release_zone_ref(&prevtx);
	free_string(&script);
	return ret;
}


OS_API_C_FUNC(int) getstaking(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{
	unsigned char	chash[65];
	hash_t			txHash, out_diff;
	mem_zone_ref	last_blk		= { PTR_NULL };
	mem_zone_ref pn = { PTR_NULL };
	struct string	pos_hash_data	= { PTR_NULL };
	unsigned int	OutIdx, target, block_time, n;
	uint64_t		amount;
	int ret = 0;


	if (!tree_manager_get_child_at(params, 0, &pn))return 0;
	tree_manager_get_node_str(&pn, 0, chash, 65, 0);
	release_zone_ref(&pn);

	if (!tree_manager_get_child_at(params, 1, &pn))return 0;
	tree_mamanger_get_node_dword(&pn, 0, &OutIdx);
	release_zone_ref(&pn);

	if (!tree_manager_find_child_node(&my_node, NODE_HASH("last_block"), NODE_BITCORE_BLK_HDR, &last_blk))
		return 0;

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
	

	return ret;
}


OS_API_C_FUNC(int) importkeypair(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{
	dh_key_t	pub, priv;
	char		clabel[32];
	btc_addr_t	pubaddr;
	mem_zone_ref username_n = { PTR_NULL }, pubkey_n = { PTR_NULL }, privkey_n = { PTR_NULL }, rescan_n = { PTR_NULL }, label_n = { PTR_NULL };
	mem_zone_ref tx_list = { PTR_NULL }, my_list = { PTR_NULL };
	mem_zone_ref_ptr tx = PTR_NULL;
	struct string username, xpubkey, xprivkey,  label;
	struct string user_key_file, adr_path;
	size_t keys_data_len = 0;
	unsigned char *keys_data = PTR_NULL;
	unsigned int found, rescan;
	unsigned int np;

	create_dir("keypairs");
	if (stat_file("keypairs") != 0)
		return 0;

	np = tree_manager_get_node_num_children(params);
	if (np < 5)return 0;
	
	init_string	(&username);
	init_string	(&xpubkey);
	init_string	(&xprivkey);
	init_string	(&label);
	memset_c(clabel, 0, 32); 
	
	tree_manager_get_child_at(params, 0, &username_n);
	tree_manager_get_child_at(params, 1, &label_n);
	tree_manager_get_child_at(params, 2, &pubkey_n);
	tree_manager_get_child_at(params, 3, &privkey_n);
	tree_manager_get_child_at(params, 4, &rescan_n);
	
	tree_manager_get_node_istr	(&username_n, 0, &username, 0);
	tree_manager_get_node_str	(&label_n, 0, clabel,32, 0);
	tree_manager_get_node_istr	(&pubkey_n, 0, &xpubkey, 0);
	tree_manager_get_node_istr	(&privkey_n, 0, &xprivkey, 0);
	
	if (!tree_mamanger_get_node_dword(&rescan_n, 0, &rescan))
		rescan = 0;

				
	release_zone_ref(&rescan_n);
	release_zone_ref(&privkey_n);
	release_zone_ref(&pubkey_n);
	release_zone_ref(&label_n);
	release_zone_ref(&username_n);

	if ((username.len < 1) || (xpubkey.len < 66))
	{
		free_string(&username);
		free_string(&xpubkey);
		free_string(&xprivkey);
		free_string(&label);
		return 0;
	}
	uname_cleanup(&username);
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
	if (xprivkey.len > 0) 
	{
		int n = (xprivkey.len < sizeof(dh_key_t)) ? xprivkey.len : sizeof(dh_key_t);
		while (n--)
		{
			char    hex[3];
			hex[0] = xprivkey.str[n * 2 + 0];
			hex[1] = xprivkey.str[n * 2 + 1];
			hex[2] = 0;
			priv[n] = strtoul_c(hex, PTR_NULL, 16);
		}
	}

	
	init_string		(&user_key_file);
	make_string		(&user_key_file, "keypairs");
	cat_cstring_p	(&user_key_file, username.str);

	found = 0;

	if (get_file(user_key_file.str, &keys_data, &keys_data_len))
	{

		struct key_entry *keys_ptr = (struct key_entry *)keys_data;
		size_t flen;
		flen = keys_data_len;
		while (keys_data_len > 0)
		{
			if (!memcmp_c(keys_ptr->addr, pubaddr, sizeof(btc_addr_t)))
			{
				if (strcmp_c(clabel, keys_ptr->label))
				{
					memcpy_c	(keys_ptr->label, clabel, 32);
					put_file	(user_key_file.str, keys_data, flen);
				}
				found = 1;
				break;
			}
			keys_ptr++;
			keys_data_len -= sizeof(struct key_entry);
		}
		free_c(keys_data);
	}

	if (!found)
	{
		append_file(user_key_file.str, clabel, 32);
		append_file(user_key_file.str, pubaddr, sizeof(btc_addr_t));
		append_file(user_key_file.str, priv, sizeof(dh_key_t));
	}
	free_string(&user_key_file);

	init_string		(&adr_path);
	make_string		(&adr_path, "adrs");
	cat_ncstring_p	(&adr_path, pubaddr, 34);
	if ((!found) || (rescan))
	{
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
		rm_dir		(adr_path.str);
		create_dir	(adr_path.str);
		if (tree_manager_create_node("txs", NODE_BITCORE_HASH_LIST, &tx_list))
		{
			load_tx_addresses	(pubaddr, &tx_list);
			for (tree_manager_get_first_child(&tx_list, &my_list, &tx); ((tx != NULL) && (tx->zone != NULL)); tree_manager_get_next_child(&my_list, &tx))
			{
				hash_t tx_hash;
				tree_manager_get_node_hash(tx, 0, tx_hash);
				store_tx_wallet(pubaddr, tx_hash);
			}
			release_zone_ref(&tx_list);
		}
	}
	tree_manager_set_child_value_i32(result, "new", found == 1 ? 0 : 1);
	

	free_string(&adr_path);
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

	uname_cleanup(&username);

	tree_manager_get_child_at	(params, 1, &pn);
	tree_manager_get_node_istr	(&pn, 0, &pubaddr, 0);
	release_zone_ref			(&pn);
	
	make_string		(&user_key_file, "keypairs");
	cat_cstring_p	(&user_key_file, username.str);
	if (get_file(user_key_file.str, &keys_data, &keys_data_len))
	{
		struct key_entry *keys_ptr = (struct key_entry *)keys_data;
		while (keys_data_len > 0)
		{
			if (!strncmp_c(keys_ptr->addr, pubaddr.str , sizeof(btc_addr_t)))
			{
				char hexk[129];
				int  n=0;
				while (n < 64)
				{
					hexk[n * 2 + 0] = hex_chars[keys_ptr->key[n] >> 4];
					hexk[n * 2 + 1] = hex_chars[keys_ptr->key[n] & 0x0F];
					n++;
				}
				hexk[128]	= 0;
				ret			= 1;
				tree_manager_set_child_value_str(result, "privkey", hexk);
				break;
			}
			keys_ptr++;
			keys_data_len  -= sizeof(struct key_entry);
		}
		free_c(keys_data);
	}
	free_string(&pubaddr);
	free_string(&username);
	free_string(&user_key_file);
	return ret;
}

OS_API_C_FUNC(int) setaccountpw(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{
	mem_zone_ref		pn = { PTR_NULL };
	struct string		username = { PTR_NULL }, pw = { PTR_NULL }, newpw = { PTR_NULL };
	int					ret;

	if (!tree_manager_get_child_at(params, 0, &pn))
		return 0;

	tree_manager_get_node_istr(&pn, 0, &username,0);
	release_zone_ref(&pn);

	uname_cleanup(&username);

	if (!tree_manager_get_child_at(params, 1, &pn))
	{
		free_string(&username);
		return 0;
	}
	tree_manager_get_node_istr(&pn, 0, &pw, 0);
	release_zone_ref(&pn);

	if (tree_manager_get_child_at(params, 2, &pn))
	{
		tree_manager_get_node_istr(&pn, 0, &newpw, 0);
		release_zone_ref(&pn);
	}
	ret = setpassword(&username, &pw, &newpw);

	free_string(&pw);
	free_string(&newpw);
	free_string(&username);
	

	return ret;
}

OS_API_C_FUNC(int) listaccounts(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{
	mem_zone_ref	page_idx_n = { PTR_NULL }, accnt_list = { PTR_NULL },addr_list = { PTR_NULL };
	struct string	user_list = { PTR_NULL }, user_key_file = { PTR_NULL };
	size_t			keys_data_len = 0, page_idx;
	size_t			nfiles;
	unsigned int	minconf;
	unsigned char	*keys_data = PTR_NULL;

	if (tree_manager_get_child_at(params, 0, &page_idx_n))
	{
		tree_mamanger_get_node_dword(&page_idx_n, 0, &page_idx);
		release_zone_ref(&page_idx_n);
	}
	else
		page_idx = 0;

	if (!tree_manager_add_child_node(result, "accounts", NODE_JSON_ARRAY, &accnt_list))
		return 0;

	minconf = 1;

	if ((nfiles=get_sub_files("keypairs", &user_list))>0)
	{ 
		size_t		dir_list_len;
		const char *ptr, *optr;
		size_t		cur;

		dir_list_len	= user_list.len;
		optr			= user_list.str;
		cur				= 0;
		while (cur < nfiles)
		{
			struct string	user_name = { PTR_NULL };
			mem_zone_ref	accnt = { PTR_NULL };
			size_t			sz;

			ptr = memchr_c	(optr, 10, dir_list_len);
			sz = mem_sub	(optr, ptr);

			make_string_l	(&user_name, optr, sz);
			make_string		(&user_key_file, "keypairs");
			cat_cstring_p	(&user_key_file, user_name.str);

			if (tree_manager_add_child_node(&accnt_list, user_name.str, NODE_GFX_OBJECT, &accnt))
			{
				struct string user_pw_file = { PTR_NULL };

				tree_manager_set_child_value_vstr	(&accnt, "name", &user_name);

				make_string				(&user_pw_file, "acpw");
				cat_cstring_p			(&user_pw_file, user_name.str);
				if (stat_file(user_pw_file.str) == 0)
					tree_manager_set_child_value_i32(&accnt, "pw", 1);
				else
					tree_manager_set_child_value_i32(&accnt, "pw", 0);

				free_string(&user_pw_file);
				release_zone_ref(&accnt);
			}
			/*
			if (get_file(user_key_file.str, &keys_data, &keys_data_len))
			{
				struct key_entry *keys_ptr = (struct key_entry *)keys_data;
				if (tree_manager_add_child_node(&accnt_list, user_name.str, NODE_GFX_OBJECT, &accnt))
				{
					tree_manager_set_child_value_vstr(&accnt, "name", &user_name);
					if (tree_manager_add_child_node	 (&accnt, "addresses", NODE_JSON_ARRAY, &addr_list))
					{
						while (keys_data_len >= sizeof(struct key_entry))
						{
							mem_zone_ref	new_addr = { PTR_NULL };
							if (tree_manager_add_child_node(&addr_list, "addr", NODE_GFX_OBJECT, &new_addr))
							{
								tree_manager_set_child_value_str(&new_addr, "label", keys_ptr->label);
								tree_manager_set_child_value_btcaddr(&new_addr, "address", keys_ptr->addr);
								release_zone_ref(&new_addr);
							}
							keys_ptr++;
							keys_data_len -= sizeof(struct key_entry);
						}
						release_zone_ref(&addr_list);
					}
					release_zone_ref(&accnt);
				}
				free_c(keys_data);
			}
			*/
			free_string(&user_name);
			free_string(&user_key_file);
			cur++;

			optr = ptr + 1;
			dir_list_len -= sz;
		}
	}
	release_zone_ref(&accnt_list);
	free_string		(&user_list);
	return 1;
}

OS_API_C_FUNC(int) getpubaddrs(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{
	mem_zone_ref username_n = { PTR_NULL }, addr_list = { PTR_NULL };
	
	if (!tree_manager_get_child_at(params, 0, &username_n))
		return 0;

	if (!tree_manager_add_child_node(result, "addrs", NODE_JSON_ARRAY, &addr_list))
	{
		release_zone_ref(&username_n);
		return 0;
	}
		
	wallet_list_addrs		(&username_n, &addr_list);
	release_zone_ref		(&username_n);
	release_zone_ref		(&addr_list);
	
	
	return 1;
}