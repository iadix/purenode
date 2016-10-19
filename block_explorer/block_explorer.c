#include <base/std_def.h>
#include <base/std_mem.h>
#include <base/mem_base.h>
#include <base/std_str.h>


#include <strs.h>
#include <http.h>
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
C_IMPORT int			C_API_FUNC   get_out_script_address(struct string *script, btc_addr_t addr);
C_IMPORT int			C_API_FUNC    load_tx_input(mem_zone_ref_const_ptr tx, unsigned int idx, mem_zone_ref_ptr	vin, mem_zone_ref_ptr tx_out);
C_IMPORT int			C_API_FUNC     get_tx_output(mem_zone_ref_const_ptr tx, unsigned int idx, mem_zone_ref_ptr vout);
C_IMPORT int			C_API_FUNC      get_tx_input(mem_zone_ref_const_ptr tx, unsigned int idx, mem_zone_ref_ptr vout);
C_IMPORT int			C_API_FUNC	  get_blk_txs(const char* blk_hash, mem_zone_ref_ptr txs);
C_IMPORT int			C_API_FUNC	  blk_load_tx_hash(const char *blk_hash, const char *tx_hash, mem_zone_ref_ptr tx);
C_IMPORT int			C_API_FUNC is_tx_null(mem_zone_ref_const_ptr tx);
C_IMPORT size_t			C_API_FUNC	  get_node_size(mem_zone_ref_ptr key);

unsigned int			WALLET_VERSION = 60000;
mem_zone_ref			my_node = { PTR_INVALID };


OS_API_C_FUNC(int) block_explorer_set_node(mem_zone_ref_ptr node, tpo_mod_file *pos_mod)
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

OS_API_C_FUNC(int) node_get_hash_idx(uint64_t block_idx, hash_t hash)
{
	mem_zone_ref	block_index_node = { PTR_NULL};
	uint64_t		nblks;

	if (!tree_manager_get_child_value_i64(&my_node, NODE_HASH("block height"), &nblks))
		nblks = 0;

	if (block_idx > nblks)return 0;

	if (tree_manager_find_child_node(&my_node, NODE_HASH("block index"), NODE_BITCORE_HASH, &block_index_node))
	{
		tree_manager_get_node_hash(&block_index_node, block_idx * 32, hash);
		release_zone_ref(&block_index_node);
	}
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

OS_API_C_FUNC(int) block_index(const char *params, const struct http_req *req, mem_zone_ref_ptr result)
{
	unsigned int idx;
	hash_t		 hash;
	idx = strtoul_c(params, PTR_NULL, 10);
	

	if (!node_get_hash_idx( idx, hash))return 0;
	tree_manager_set_child_value_hash(result, "blockHash", hash);
	return 1;
}


OS_API_C_FUNC(int) block(const char *params, const struct http_req *req, mem_zone_ref_ptr result)
{
	char   chash[65];
	hash_t merkle, proof, nullhash, nexthash, rdiff, hdiff, prev;
	hash_t block_hash;
	mem_zone_ref block = { PTR_NULL }, txs = { PTR_NULL };
	size_t n = 0;
	size_t size;
	unsigned int version, time, bits, nonce;
	uint64_t	 height;
	size_t		 nxt_prm_pos;

	nxt_prm_pos = strlpos_c(params, 0, '/');
	if (nxt_prm_pos == INVALID_SIZE)
		nxt_prm_pos = strlen_c(params);

	memset_c(nullhash, 0, 32);

	if (nxt_prm_pos >= 64)
	{
		n = 0;
		while (n < 32)
		{
			char    hex[3];

			chash[(31 - n) * 2 + 0] = params[n * 2 + 0];
			chash[(31 - n) * 2 + 1] = params[n * 2 + 1];

			hex[0] = params[n * 2 + 0];
			hex[1] = params[n * 2 + 1];
			hex[2] = 0;
			block_hash[31-n] = strtoul_c(hex, PTR_NULL, 16);
			n++;
		}
		chash[64] = 0;

		
	}
	else
	{
		uint64_t nblks;
		nblks = get_last_block_height();
		
		if ((nblks>0) && (node_get_hash_idx( nblks - 1, block_hash)))
		{
			n = 0;
			while (n < 32)
			{
				chash[n * 2 + 0] = hex_chars[block_hash[n] >> 4];
				chash[n * 2 + 1] = hex_chars[block_hash[n] & 0x0F];
				n++;
			}
			chash[64] = 0;
		}

	}

	if (!load_blk_hdr(&block, chash))return 0;

	
	tree_manager_get_child_value_hash(&block, NODE_HASH("merkle_root"), merkle);
	tree_manager_get_child_value_hash(&block, NODE_HASH("prev"), prev);
	tree_manager_get_child_value_i32(&block, NODE_HASH("version"), &version);
	tree_manager_get_child_value_i32(&block, NODE_HASH("time"), &time);
	tree_manager_get_child_value_i32(&block, NODE_HASH("bits"), &bits);
	tree_manager_get_child_value_i32(&block, NODE_HASH("nonce"), &nonce);

	
	if (!get_block_size(chash, &size))
		size = 0;

	get_blk_height(chash, &height);

	if (node_get_hash_idx(height + 1, nexthash) <= 0)
		memcpy_c(nexthash, nullhash,sizeof(hash_t));



	tree_manager_set_child_value_i64(result, "height", height);
	tree_manager_set_child_value_i32(result, "size", size);
	tree_manager_set_child_value_hash(result, "hash", block_hash);
	tree_manager_set_child_value_i32(result, "confirmations", 0);
	tree_manager_set_child_value_i32(result, "time", time);
	tree_manager_set_child_value_i32(result, "version", version);
	tree_manager_set_child_value_i32(result, "bits", bits);
	tree_manager_set_child_value_i32(result, "nonce", nonce);
	tree_manager_set_child_value_hash(result, "merkleroot", merkle);
	tree_manager_set_child_value_hash(result, "previousblockhash", prev);
	tree_manager_set_child_value_hash(result, "nextblockhash", nexthash);
	tree_manager_set_child_value_float(result, "difficulty", GetDifficulty(bits));

	if (is_pow_block(chash))
	{
		uint64_t reward;
		SetCompact(bits, hdiff);
		get_pow_block(chash, proof);
		
		if (!tree_manager_get_child_value_i64(&my_node, NODE_HASH("block reward"), &reward))
			reward = 0;

		n = 32;
		while (n--)
		{
			rdiff[n] = hdiff[31 - n];
		}
			
		tree_manager_set_child_value_i64(result, "reward", reward);

		tree_manager_set_child_value_hash(result, "proofhash", proof);
		tree_manager_set_child_value_hash(result, "hbits", rdiff);
		tree_manager_set_child_value_bool(result, "isCoinbase", 1);

	}
	else if (get_blk_staking_infos)
	{
		tree_manager_set_child_value_bool(result, "isCoinbase", 0);
		get_blk_staking_infos(&block, chash, result);
	}

	if(tree_manager_add_child_node	(result, "tx", NODE_JSON_ARRAY, &txs))
		get_blk_txs					(chash, &txs);	
	


	release_zone_ref(&txs);
	release_zone_ref(&block);

	return 1;
		/*
	{   
		"chainwork" : "0000000000000000000000000000000000000000000998b7adec271cd0ea7258", 
		"nextblockhash" : "000000000000000013677449d7375ed22f9c66a94940328081412179795a1ac5", 
		"reward" : 25, 
		"isMainChain" : true, 
		"poolInfo" : {}
	}
	*/
}
OS_API_C_FUNC(int) tx(const char *params, const struct http_req *req, mem_zone_ref_ptr result)
{
	char hexscript[2048];
	hash_t blk_hash, tx_hash, nullhash;
	mem_zone_ref my_tx = { PTR_NULL }, txout_list = { PTR_NULL }, txin_list = { PTR_NULL };
	uint64_t height, blk_time, ttx_time;
	unsigned int version, locktime, nblks, n, tx_time;
	size_t		 nxt_prm_pos, size;

	nxt_prm_pos = strlpos_c(params, 0, '/');
	if (nxt_prm_pos == INVALID_SIZE)
		nxt_prm_pos = strlen_c(params);

	if (nxt_prm_pos < 64)return 0;

	n = 0;
	while (n<32)
	{
		char    hex[3];
		hex[0] = params[(31 - n) * 2 + 0];
		hex[1] = params[(31 - n) * 2 + 1];
		hex[2] = 0;
		tx_hash[n] = strtoul_c(hex, PTR_NULL, 16);
		n++;
	}
	if (!load_tx(&my_tx, blk_hash, tx_hash))return 0;

	size = get_node_size(&my_tx);

	memset_c(nullhash, 0, sizeof(hash_t));

	get_tx_blk_height(tx_hash, &height, &blk_time, &ttx_time);
	nblks = get_last_block_height();

	tree_manager_get_child_value_i32(&my_tx, NODE_HASH("version")	, &version);
	tree_manager_get_child_value_i32(&my_tx, NODE_HASH("locktime")	, &locktime);
	tree_manager_get_child_value_i32(&my_tx, NODE_HASH("time")		, &tx_time);
	

	tree_manager_set_child_value_hash(result, "txid", tx_hash);
	tree_manager_set_child_value_hash(result, "blockhash", blk_hash);
	tree_manager_set_child_value_i64 (result, "blockheight", height);
	tree_manager_set_child_value_i64 (result, "confirmations", nblks- height);
	tree_manager_set_child_value_i32 (result, "blocktime", blk_time);
	tree_manager_set_child_value_i32(result, "size", size);
	
	tree_manager_set_child_value_i32 (result, "time", tx_time);

	if (is_tx_null(&my_tx))
	{
		tree_manager_set_child_value_bool(result, "isNull", 1);
		release_zone_ref(&my_tx);
		return 1;
	}
	if (tree_manager_find_child_node(&my_tx, NODE_HASH("txsin"), NODE_BITCORE_VINLIST, &txin_list))
	{
		mem_zone_ref my_list = { PTR_NULL }, vin_list = { PTR_NULL };
		mem_zone_ref_ptr in = PTR_NULL;
		unsigned int nin = 0;

		tree_manager_add_child_node(result, "vin", NODE_JSON_ARRAY, &vin_list);
		for (nin = 0, tree_manager_get_first_child(&txin_list, &my_list, &in); ((in != PTR_NULL) && (in->zone != PTR_NULL)); tree_manager_get_next_child(&my_list, &in), nin++)
		{
			mem_zone_ref new_vin = { PTR_NULL };
			if (tree_manager_add_child_node(&vin_list, "vin", NODE_GFX_OBJECT, &new_vin))
			{
				hash_t phash;
				
				struct string script = { PTR_NULL };
				unsigned int seq,idx;

				tree_manager_get_child_value_hash(in, NODE_HASH("tx hash")	, phash);
				tree_manager_get_child_value_i32 (in, NODE_HASH("idx")		, &idx);
				tree_manager_get_child_value_i32 (in, NODE_HASH("sequence")	, &seq);
				

				if (!memcmp_c(phash, nullhash, 32))
				{
					tree_manager_get_child_value_istr(in, NODE_HASH("script"), &script,0);

					if (script.len > 0)
					{
						unsigned char *p = (unsigned char *)script.str;
						n = 0;	
						while (n<script.len)
						{
							hexscript[n * 2 + 0] = hex_chars[p[n] >> 4];
							hexscript[n * 2 + 1] = hex_chars[p[n] & 0x0F];
							n++;
						}
						hexscript[n * 2] = 0;
						tree_manager_set_child_value_str(&new_vin, "coinbase", hexscript);
						tree_manager_set_child_value_bool(result, "isCoinBase", 1);
					}
					free_string(&script);
				}
				else
				{
					hash_t prev_bhash;
					mem_zone_ref addrs = { PTR_NULL }, prev_tx = { PTR_NULL };

					if (load_tx(&prev_tx, prev_bhash, phash))
					{
						mem_zone_ref vout = { PTR_NULL };
						uint64_t value;

						if (get_tx_output(&prev_tx, idx, &vout))
						{
							tree_manager_get_child_value_i64(&vout, NODE_HASH("value"), &value);
							tree_manager_set_child_value_i64(&new_vin, "value", value);

							if (tree_manager_add_child_node(&new_vin, "addresses", NODE_JSON_ARRAY, &addrs))
							{
								btc_addr_t addr;
								mem_zone_ref ad = { PTR_NULL };
								tree_manager_get_child_value_istr(&vout, NODE_HASH("script"), &script, 0);
								if (get_out_script_address(&script, addr))
								{
									if (tree_manager_add_child_node(&addrs, "addr", NODE_BITCORE_WALLET_ADDR, &ad))
									{
										tree_manager_write_node_btcaddr(&ad, 0, addr);
										release_zone_ref(&ad);
									}
								}
								free_string(&script);
								release_zone_ref(&addrs);
							}
							release_zone_ref(&vout);
						}
						release_zone_ref(&prev_tx);
					}
					tree_manager_set_child_value_hash(&new_vin, "prevhash", phash);
					tree_manager_set_child_value_i32(&new_vin, "idx", idx);
					tree_manager_set_child_value_bool(result, "isCoinBase", 0);
				}
				
				tree_manager_set_child_value_i32(&new_vin, "n", nin);
				tree_manager_set_child_value_i32(&new_vin, "sequence", seq);
				release_zone_ref(&new_vin);
			}
		}
		release_zone_ref(&vin_list);
		release_zone_ref(&txin_list);
	}
	if (tree_manager_find_child_node(&my_tx, NODE_HASH("txsout"), NODE_BITCORE_VOUTLIST, &txout_list))
	{
		mem_zone_ref vout_list = { PTR_NULL }, my_list = { PTR_NULL };
		mem_zone_ref_ptr out = PTR_NULL;
		unsigned int nout = 0;

		tree_manager_add_child_node(result, "vout", NODE_JSON_ARRAY, &vout_list);
		for (nout = 0, tree_manager_get_first_child(&txout_list, &my_list, &out); ((out != PTR_NULL) && (out->zone != PTR_NULL)); tree_manager_get_next_child(&my_list, &out), nout++)
		{
			mem_zone_ref new_vout = { PTR_NULL };
			struct		 string script = { PTR_NULL };
			uint64_t	 value;


			tree_manager_get_child_value_i64(out, NODE_HASH("value"), &value);
			tree_manager_get_child_value_istr(out, NODE_HASH("script"), &script, 0);

	

			if (tree_manager_add_child_node(&vout_list, "vout", NODE_GFX_OBJECT, &new_vout))
			{
				mem_zone_ref scriptkey = { PTR_NULL };
				
				tree_manager_set_child_value_i64(&new_vout, "value" , value);
				tree_manager_set_child_value_i32(&new_vout, "n"		, nout);

				if ((value == 0) && (script.len == 0))
				{
					tree_manager_set_child_value_bool(&new_vout, "isNull", 1);
				}
				else
				{
					tree_manager_set_child_value_bool(&new_vout, "isNull", 0);
					if (tree_manager_add_child_node(&new_vout, "scriptPubKey", NODE_GFX_OBJECT, &scriptkey))
					{
						mem_zone_ref addrs = { PTR_NULL };
						unsigned char *p = script.str;


						n = 0;
						while (n < script.len)
						{
							hexscript[n * 2 + 0] = hex_chars[p[n] >> 4];
							hexscript[n * 2 + 1] = hex_chars[p[n] & 0x0F];
							n++;
						}
						hexscript[n * 2] = 0;
						tree_manager_set_child_value_str(&scriptkey, "hex", hexscript);


						if (tree_manager_add_child_node(&new_vout, "addresses", NODE_JSON_ARRAY, &addrs))
						{
							btc_addr_t addr;
							mem_zone_ref ad = { PTR_NULL };
							int ret;

							ret = get_out_script_address(&script, addr);

							if (ret == 1)
								tree_manager_set_child_value_str(&scriptkey, "type", "pubkeyhash");

							if (ret == 2)
								tree_manager_set_child_value_str(&scriptkey, "type", "paytoscript");

							if (tree_manager_add_child_node(&addrs, "addr", NODE_BITCORE_WALLET_ADDR, &ad))
							{
								tree_manager_write_node_btcaddr(&ad, 0, addr);
								release_zone_ref(&ad);
							}
							release_zone_ref(&addrs);
						}
						release_zone_ref(&scriptkey);
					}
				}
				free_string(&script);
				release_zone_ref(&new_vout);
			}
		}
		release_zone_ref(&vout_list);
		release_zone_ref(&txout_list);
	}
	release_zone_ref(&my_tx);
	return 1;
	/*
	{	
		"txid":"5756ff16e2b9f881cd15b8a7e478b4899965f87f553b6210d0f8e5bf5be7df1d", 
		"version" : 1, 
		"locktime" : 981825022, 
		"confirmations" : 62823,
		"time" : 1440604784,
		"isCoinBase" : true,
		"valueOut" : 25.37726812,
		"size" : 185

		"blockhash" : "0000000000000000027d0985fef71cbc05a5ee5cdbdc4c6baf2307e6c5db8591",
		"blockheight" : 371622,
		"blocktime" : 1440604784,
		"vin" : 
		[
			{"coinbase":"03a6ab05e4b883e5bda9e7a59ee4bb99e9b1bc76a3a2bb0e9c92f06e4a6349de9ccc8fbe0fad11133ed73c78ee12876334c13c02000000f09f909f2f4249503130302f4d696e65642062792073647a686162636400000000000000000000000000000000", 
			 "sequence" : 2765846367, 
			 "n" : 0}
		], 
		"vout" : 
		[
			{   
				"value":"25.37726812", 
				"n" : 0, 
				"scriptPubKey" : 
				{
					"hex":"76a914c825a1ecf2a6830c4401620c3a16f1995057c2ab88ac", 
					"asm" : "OP_DUP OP_HASH160 c825a1ecf2a6830c4401620c3a16f1995057c2ab OP_EQUALVERIFY OP_CHECKSIG", 
					"addresses" : ["1KFHE7w8BhaENAswwryaoccDb6qcT6DbYY"], 
					"type" : "pubkeyhash"
				}, 
				"spentTxId" : "a01b32246795ca47ed77ef78d56736677ec2f2aae7b400ebbcc95cd784492dc2", 
				"spentIndex" : 6, 
				"spentHeight" : 371831
			}
		], 
	}
	*/
}

OS_API_C_FUNC(int) txs(const char *params, const struct http_req *req, mem_zone_ref_ptr result)
{
	const struct http_hdr   *hdr;
	mem_zone_ref	  new_block = { PTR_NULL }, tx_list = { PTR_NULL };
	mem_zone_ref	  my_list = { PTR_NULL };
	mem_zone_ref	  txs = { PTR_NULL };
	mem_zone_ref_ptr  ptx=PTR_NULL;

	tree_manager_add_child_node(result, "txs", NODE_JSON_ARRAY, &tx_list);

	tree_manager_create_node("txs", NODE_BITCORE_HASH_LIST, &txs);

	if ((hdr = find_key(req->query_vars, "block")) != PTR_NULL)
	{
		char chash[65];
		hash_t block_hash;
		int		n;
		n = 0;
		while (n < 32)
		{
			char    hex[3];

			chash[(31 - n) * 2 + 0] = hdr->value.str[n * 2 + 0];
			chash[(31 - n) * 2 + 1] = hdr->value.str[n * 2 + 1];
			hex[0] = hdr->value.str[n * 2 + 0];
			hex[1] = hdr->value.str[n * 2 + 1];
			hex[2] = 0;
			block_hash[31 - n] = strtoul_c(hex, PTR_NULL, 16);
			n++;
		}
		chash[64] = 0;

		get_blk_txs(chash, &txs);
	}
	else if ((hdr = find_key(req->query_vars, "address")) != PTR_NULL)
	{
		load_tx_addresses	(hdr->value.str, &txs);
	}

	for (tree_manager_get_first_child(&txs, &my_list, &ptx);((ptx != PTR_NULL) && (ptx->zone != PTR_NULL)); tree_manager_get_next_child(&my_list, &ptx))
	{
		hash_t			txhash;
		char			tx_hash[65];
		mem_zone_ref	my_tx = { PTR_NULL };
		int				n;

		tree_manager_get_node_hash	(ptx, 0, txhash);

		n = 0;
		while (n<32)
		{
			tx_hash[n * 2 + 0] = hex_chars[txhash[31 - n] >> 4];
			tx_hash[n * 2 + 1] = hex_chars[txhash[31 - n] & 0x0F];
			n++;
		}
		tx_hash[64] = 0;

		tree_manager_add_child_node	(&tx_list, "tx", NODE_GFX_OBJECT, &my_tx);
		tx							(tx_hash, req, &my_tx);
		release_zone_ref			(&my_tx);
	}
	release_zone_ref(&txs);
	release_zone_ref(&tx_list);

	return 1;
	//txs / ? block = 00000000fa6cf7367e50ad14eb0ca4737131f256fc4c5841fd3c3f140140e6b6
}

OS_API_C_FUNC(int) blocks(const char *params, const struct http_req *req, mem_zone_ref_ptr result)
{
	char			chash[65], prm[65];
	mem_zone_ref	 block_index_node = { PTR_NULL }, new_block = { PTR_NULL }, block_list = { PTR_NULL };
	struct string	blk_path = { PTR_NULL };
	ctime_t			ctime,time;
	uint64_t			nblks;
	unsigned int	 block_time, limit, num, idx,n;
	const struct http_hdr *blockdate;

	tree_manager_find_child_node		(&my_node, NODE_HASH("block index"), NODE_BITCORE_HASH, &block_index_node);
	tree_manager_get_child_value_i64	(&my_node, NODE_HASH("block height"), &nblks);
	
	
	if ((blockdate = find_key(req->query_vars, "BlockDate")) != PTR_NULL)
		time = parseDate(blockdate->value.str);
	else
		time = get_time_c()-24*3600;

	if (isdigit_c(params[0]))
		limit = strtoul_c(params, PTR_NULL, 10);
	else
		limit = 0;

	if ((limit < 1) || (limit > 100))
		limit = 100;

	block_time	 = 0xFFFFFFFF;
	idx			 = nblks;

	while ((idx--)&&(block_time > (time + 24 * 3600)))
	{
		hash_t hash;
		if (!tree_manager_get_node_hash(&block_index_node, idx*32, hash))
			break;
		n = 0;
		while (n<32)
		{
			chash[n * 2 + 0] = hex_chars[hash[n] >> 4];
			chash[n * 2 + 1] = hex_chars[hash[n] & 0x0F];
			n++;
		}
		chash[64] = 0;
		make_string		(&blk_path , "blks");
		cat_ncstring_p	(&blk_path , chash, 2);
		cat_ncstring_p	(&blk_path , chash+ 2, 2);
		cat_cstring_p	(&blk_path , chash);

		if (!get_ftime(blk_path.str, &ctime))
			ctime = 0;

		free_string(&blk_path);
		block_time = ctime;
	}

	tree_manager_add_child_node		 (result, "blocks", NODE_JSON_ARRAY, &block_list);
	n = 0;
	while (n<32)
	{
		prm[(31 - n) * 2 + 0] = chash[n * 2 + 0];
		prm[(31 - n) * 2 + 1] = chash[n * 2 + 0];
		n++;
	}
	prm[64] = 0;
	
	num = 0;

	while ((idx--) && (num<limit) && (block_time>time))
	{
		hash_t hash;
		tree_manager_add_child_node	(&block_list, "block", NODE_GFX_OBJECT, &new_block);
		block						(prm, req, &new_block);
		release_zone_ref			(&new_block);
		num++;

		if (!tree_manager_get_node_hash(&block_index_node, idx*32, hash))
			break;
		n = 0;
		while (n<32)
		{
			prm[(31 - n) * 2 + 0] = hex_chars[hash[n] >> 4];
			prm[(31 - n) * 2 + 1] = hex_chars[hash[n] & 0x0F];
			n++;
		}
		prm[64] = 0;

		make_string(&blk_path, "blks");
		cat_ncstring_p(&blk_path, chash, 2);
		cat_ncstring_p(&blk_path, chash + 2, 2);
		cat_cstring_p(&blk_path, chash);

		if (!get_ftime(blk_path.str, &ctime))
			ctime = 0;

		free_string(&blk_path);
		block_time = ctime;
	}
	tree_manager_set_child_value_i32(result, "length", num);

	release_zone_ref(&block_list);
	release_zone_ref(&block_index_node);


	return 1;
	
}