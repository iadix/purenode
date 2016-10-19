#include <base/std_def.h>
#include <base/std_mem.h>
#include <base/mem_base.h>
#include <base/std_str.h>

#include <sha256.h>
#include <md5.h>
#include <strs.h>
#include <tree.h>
#include <fsio.h>

hash_t			nullhash = { 0xCD };
hash_t			Difflimit = { 0xCD };
unsigned int	Di = 0xFFFFFFFF, last_diff = 0xFFFFFFFF;
static int64_t	TargetSpacing = 0xFFFFFFFF;
static int64_t	nTargetTimespan = 0xFFFFFFFF;
static int64_t	nStakeReward= 0xFFFFFFFF;

C_IMPORT int			C_API_FUNC  load_blk_tx_input(const char *blk_hash, unsigned int tx_idx, unsigned int vin_idx, mem_zone_ref_ptr vout);
C_IMPORT int  C_API_FUNC load_blk_hdr			(mem_zone_ref_ptr hdr, const char *blk_hash);
C_IMPORT int  C_API_FUNC get_tx_output			(mem_zone_ref_const_ptr tx, unsigned int idx, mem_zone_ref_ptr vout);
C_IMPORT int  C_API_FUNC get_tx_input			(mem_zone_ref_const_ptr tx, unsigned int idx, mem_zone_ref_ptr vin);
C_IMPORT int  C_API_FUNC is_tx_null				(mem_zone_ref_const_ptr tx);
C_IMPORT int  C_API_FUNC is_vout_null			(mem_zone_ref_const_ptr tx, unsigned int idx);
C_IMPORT int  C_API_FUNC load_tx_input			(mem_zone_ref_const_ptr tx, unsigned int idx, mem_zone_ref_ptr	vin, mem_zone_ref_ptr tx_out);
C_IMPORT int  C_API_FUNC load_tx				(mem_zone_ref_ptr tx, hash_t blk_hash, const char *tx_hash);
C_IMPORT int  C_API_FUNC get_tx_output_amount	(const hash_t tx_hash, unsigned int idx, uint64_t *amount);

C_IMPORT int  C_API_FUNC compute_block_hash		(mem_zone_ref_ptr hdr, hash_t blk_hash);
C_IMPORT int  C_API_FUNC compute_block_pow		(mem_zone_ref_ptr block, hash_t hash);
C_IMPORT int  C_API_FUNC SetCompact				(unsigned int bits, hash_t out);
C_IMPORT void C_API_FUNC mul_compact			(unsigned int nBits, uint64_t op, hash_t hash);
C_IMPORT int  C_API_FUNC cmp_hashle				(hash_t hash1, hash_t hash2);
C_IMPORT unsigned int C_API_FUNC calc_new_target(unsigned int nActualSpacing, unsigned int TargetSpacing, unsigned int nTargetTimespan, unsigned int pBits);
C_IMPORT int  C_API_FUNC get_block_height		();
#define ONE_COIN		100000000ULL
#define ONE_CENT		1000000ULL


OS_API_C_FUNC(int) init_pos(mem_zone_ref_ptr stake_conf)
{
	memset_c(nullhash, 0, 32);

	if(!tree_manager_get_child_value_i64(stake_conf, NODE_HASH("target spacing"), &TargetSpacing))
		TargetSpacing= 64;


	if (!tree_manager_get_child_value_i64(stake_conf, NODE_HASH("target timespan"), &nTargetTimespan))
		nTargetTimespan = 16 * 60;  // 16 mins

	if (!tree_manager_get_child_value_i64(stake_conf, NODE_HASH("stake reward"), &nStakeReward))
		nStakeReward = 150 * ONE_CENT;  // 16 mins

	if (!tree_manager_get_child_value_i32(stake_conf, NODE_HASH("limit"), &Di))
		Di = 0x1E00FFFF;

	/*
	memset_c(Difflimit, 0, sizeof(hash_t));
	memset_c(Difflimit, 0xFF, 26);
	*/
	SetCompact(Di, Difflimit);

	
	return 1;
}


OS_API_C_FUNC(int) generated_stake_modifier(const char *blk_hash, hash_t StakeMod)
{
	struct string		blk_path = { PTR_NULL };
	int					ret = 0;

	make_string(&blk_path, "blks");
	cat_ncstring_p(&blk_path, blk_hash+0,2);
	cat_ncstring_p(&blk_path, blk_hash+2, 2);
	cat_cstring_p(&blk_path, blk_hash);
	cat_cstring_p(&blk_path, "stakemodifier2");
	if (stat_file(blk_path.str) == 0)
	{
		unsigned char	*data;
		size_t			data_len;
		if (get_file(blk_path.str, &data, &data_len))
		{
			if (data_len >= sizeof(hash_t))
			{
				memcpy_c(StakeMod, data, sizeof(hash_t));
				ret = 1;
			}
			free_c(data);
		}
	}
	free_string(&blk_path);
	return ret;
}

// Get the last stake modifier and its generation time from a given block
OS_API_C_FUNC(int) get_last_stake_modifier(mem_zone_ref_ptr pindex, hash_t nStakeModifier, unsigned int *nModifierTime)
{
	char			chash[65],newHash[65];
	int				ret=0;

    if (pindex==PTR_NULL)return 0;
	if (pindex->zone==PTR_NULL)return 0;
	if (!tree_manager_get_child_value_str(pindex, NODE_HASH("blk hash"), chash, 65, 16))return 0;
	if (generated_stake_modifier(chash, nStakeModifier))
	{
		tree_manager_set_child_value_hash(pindex, "StakeMod2", nStakeModifier);
		tree_manager_get_child_value_i32(pindex, NODE_HASH("time"), nModifierTime);
		return 1;
	}
	memcpy_c(newHash, chash,32);
	while (!generated_stake_modifier(chash, nStakeModifier))
	{
		tree_manager_get_child_value_str(pindex, NODE_HASH("prev"), chash,65,16);
		if (!load_blk_hdr(pindex, chash))
			return 0;
	}
	//compute stake modifiers for blocks from last computed stake modifier to newhash
	
	return ret;
}
OS_API_C_FUNC(int) is_pos_block(const char *blk_hash)
{
	struct string file_path = { 0 };
	int stat, ret;

	make_string(&file_path, "blks");
	cat_ncstring_p(&file_path, blk_hash + 0, 2);
	cat_ncstring_p(&file_path, blk_hash + 2, 2);
	cat_cstring_p(&file_path, blk_hash);
	cat_cstring_p(&file_path, "pos");
	stat = stat_file(file_path.str);
	free_string(&file_path);
	ret = (stat == 0) ? 1 : 0;
	return ret;
}


// Get the last pos block and its generation time from a given block
int get_last_pos_block(mem_zone_ref_ptr pindex, unsigned int *block_time)
{
	char			chash[65];
	int				ret = 0;
	tree_manager_get_child_value_str(pindex, NODE_HASH("blk hash"), chash, 65, 16);
	while (!is_pos_block(chash))
	{
		tree_manager_get_child_value_str(pindex, NODE_HASH("prev"), chash, 65, 16);
		if (!load_blk_hdr(pindex, chash))
			return 0;
	}
	if (is_pos_block(chash))
	{
		tree_manager_get_child_value_i32(pindex, NODE_HASH("time"), block_time);
		return 1;
	}
	return 0;
}


OS_API_C_FUNC(int) store_last_pos_hash(hash_t hash)
{
	int ret;
	struct string path = { PTR_NULL };

	make_string(&path, "node");
	cat_cstring_p(&path, "last_pos");
	ret=put_file(path.str, hash, sizeof(hash_t));
	free_string(&path);
	return (ret > 0);
}


OS_API_C_FUNC(int) load_last_pos_blk(mem_zone_ref_ptr header)
{
	unsigned char   *data;
	size_t			len;
	struct string	path = { PTR_NULL };
	int				ret = 0;

	make_string(&path, "node");
	cat_cstring_p(&path, "last_pos");
	if (get_file(path.str, &data, &len) > 0)
	{
		if (len >= sizeof(hash_t))
		{
			char chash[65];
			int	 n;
			n = 0;
			while (n<32)
			{
				chash[n * 2 + 0] = hex_chars[data[n] >> 4];
				chash[n * 2 + 1] = hex_chars[data[n] & 0x0F];
				n++;
			}
			chash[64] = 0;
			ret = load_blk_hdr(header, chash);
		}
		free_c(data);
	}
	free_string(&path);

	return (ret>0);
}



OS_API_C_FUNC(int) store_tx_staking(mem_zone_ref_ptr tx, hash_t tx_hash, btc_addr_t stake_addr, uint64_t	stake_in)
{
	mem_zone_ref	 txout_list = { PTR_NULL }, my_list = { PTR_NULL };
	mem_zone_ref_ptr out = PTR_NULL;
	uint64_t		 stake_out = 0, staked;
	struct string	 stake_path = { 0 };


	make_string(&stake_path, "adrs");
	cat_ncstring_p(&stake_path, stake_addr, 34);
	if (stat_file(stake_path.str) != 0)
	{
		free_string(&stake_path);
		return 0;
	}

	if (tree_manager_find_child_node(tx, NODE_HASH("txsout"), NODE_BITCORE_VOUTLIST, &txout_list))
	{
		for (tree_manager_get_first_child(&txout_list, &my_list, &out); ((out != NULL) && (out->zone != NULL)); tree_manager_get_next_child(&my_list, &out))
		{
			uint64_t amount = 0;
			if (!tree_manager_get_child_value_i64(out, NODE_HASH("value"), &amount))continue;
			stake_out += amount;
		}
		release_zone_ref(&txout_list);
	}
	staked = stake_out - stake_in;


	cat_cstring_p(&stake_path, "stakes");
	append_file	(stake_path.str, &staked, sizeof(uint64_t));
	append_file	(stake_path.str, tx_hash, sizeof(hash_t));
	free_string(&stake_path);

	/*
	cat_cstring_p(&stake_path, "stake");
	create_dir(stake_path.str);
	cat_cstring_p(&stake_path, tx_hash);
	put_file(stake_path.str, &staked, sizeof(uint64_t));
	free_string(&stake_path);
	*/

	return 1;

}

OS_API_C_FUNC(int) store_blk_staking(mem_zone_ref_ptr header, mem_zone_ref_ptr tx_list)
{
	char blk_hash[65];
	struct string blk_path = { 0 }, file_path = { 0 };
	hash_t StakeMod, hashPos;
	int stat, ret;

	if (!tree_manager_get_child_value_str(header, NODE_HASH("blk hash"), blk_hash, 65, 16))return 0;

	make_string(&blk_path, "blks");
	cat_ncstring_p(&blk_path, blk_hash + 0, 2);
	cat_ncstring_p(&blk_path, blk_hash + 2, 2);
	cat_cstring_p(&blk_path, blk_hash);
	stat = stat_file(blk_path.str);
	if (stat != 0)
	{
		free_string(&blk_path);
		return 0;
	}
	ret = 1;
	if (tree_manager_get_child_value_hash(header, NODE_HASH("StakeMod2"), StakeMod))
	{
		clone_string(&file_path, &blk_path);
		cat_cstring_p(&file_path, "stakemodifier2");
		ret = put_file(file_path.str, StakeMod, sizeof(hash_t));
		free_string(&file_path);
	}
	if (tree_manager_get_child_value_hash(header, NODE_HASH("blk pos"), hashPos))
	{
		clone_string(&file_path, &blk_path);
		cat_cstring_p(&file_path, "pos");
		ret = put_file(file_path.str, hashPos, sizeof(hash_t));
		free_string(&file_path);
	}
	free_string(&blk_path);


	if (tx_list != PTR_NULL)
	{
		mem_zone_ref tx = { PTR_NULL };

		if (tree_manager_get_child_at(tx_list, 1, &tx))
		{
			if (is_vout_null(&tx, 0))
			{
				mem_zone_ref vin = { PTR_NULL };
				btc_addr_t	stake_addr;
				uint64_t	stake_in;
				if (get_tx_input(&tx, 0, &vin))
				{
					if (tree_manager_get_child_value_btcaddr(&vin, NODE_HASH("src addr"), stake_addr))
					{
						hash_t			tx_hash;
						
						tree_manager_get_child_value_i64	(&vin, NODE_HASH("amount"), &stake_in);
						tree_manager_get_child_value_hash	(&tx, NODE_HASH("tx hash"), tx_hash);
			
						store_tx_staking(&tx, tx_hash, stake_addr, stake_in);
					}
					release_zone_ref(&vin);
				}
			}
			release_zone_ref(&tx);
		}
	}

	return ret;
}
OS_API_C_FUNC(int) get_pos_block(const char *blk_hash, hash_t pos)
{
	unsigned char   *data;
	size_t			len;
	struct string file_path = { 0 };
	int ret = 0;

	make_string(&file_path, "blks");
	cat_ncstring_p(&file_path, blk_hash + 0, 2);
	cat_ncstring_p(&file_path, blk_hash + 2, 2);
	cat_cstring_p(&file_path, blk_hash);
	cat_cstring_p(&file_path, "pos");
	if (get_file(file_path.str, &data, &len) > 0)
	{
		if (len >= sizeof(hash_t))
		{
			memcpy_c(pos, data, sizeof(hash_t));
			ret = 1;
		}
		free_c(data);
	}
	free_string(&file_path);
	return ret;
}

OS_API_C_FUNC(int) get_blk_staking_infos(mem_zone_ref_ptr blk, const char *blk_hash, mem_zone_ref_ptr infos)
{
	hash_t stakemod, rdiff, diff;
	mem_zone_ref vout = { PTR_NULL };
	unsigned int staketime, nBits;
	unsigned char *data, n;
	uint64_t weight;
	size_t len;
	struct string blk_path = { 0 }, file_path = { 0 };

	tree_manager_get_child_value_i32(blk, NODE_HASH("bits"), &nBits);

	tree_manager_set_child_value_i64(infos, "reward", nStakeReward);

	if (get_last_stake_modifier(blk, stakemod, &staketime))
		tree_manager_set_child_value_hash(infos, "stakemodifier2", stakemod);
	else
		tree_manager_set_child_value_hash(infos, "stakemodifier2", nullhash);

	if (load_blk_tx_input(blk_hash, 1, 0, &vout))
	{
		tree_manager_get_child_value_i64(&vout, NODE_HASH("value"), &weight);
		tree_manager_set_child_value_i64(infos, "stake weight", weight);
		release_zone_ref(&vout);
		mul_compact(nBits, weight, rdiff);
	}
	else
	{
		SetCompact(nBits, diff);
		n = 32;
		while (n--)
		{
			rdiff[n] = diff[31 - n];
		}

	}


	tree_manager_set_child_value_hash(infos, "hbits", rdiff);

	make_string(&blk_path, "blks");
	cat_ncstring_p(&blk_path, blk_hash + 0, 2);
	cat_ncstring_p(&blk_path, blk_hash + 2, 2);
	cat_cstring_p(&blk_path, blk_hash);
	

	clone_string(&file_path, &blk_path);
	cat_cstring_p(&file_path, "pos");
	if (get_file(file_path.str, &data, &len) > 0)
	{
		if (len >= sizeof(hash_t))
			tree_manager_set_child_value_hash(infos, "proofhash", data);

		free_c(data);
	}
	free_string(&file_path);
	free_string(&blk_path);

	return 1;

}

int compute_tx_pos(mem_zone_ref_ptr tx, hash_t StakeModifier, unsigned int txTime, hash_t pos_hash, hash_t prevOutHash, unsigned int *prevOutIdx)
{
	
	hash_t tmp;
	mbedtls_sha256_context ctx;
	mem_zone_ref	vin = { PTR_NULL }, prev_tx = { PTR_NULL };
	unsigned int txPrevTime;
	
	if (!load_tx_input(tx, 0, &vin, &prev_tx))return 0;

	tree_manager_get_child_value_i32(&prev_tx, NODE_HASH("time"), &txPrevTime);
	tree_manager_get_child_value_hash(&vin, NODE_HASH("tx hash"), prevOutHash);
	tree_manager_get_child_value_i32(&vin, NODE_HASH("idx"), prevOutIdx);
	release_zone_ref(&prev_tx);
	release_zone_ref(&vin);

	mbedtls_sha256_init(&ctx);
	mbedtls_sha256_starts(&ctx, 0);
	mbedtls_sha256_update(&ctx, StakeModifier, sizeof(hash_t));
	mbedtls_sha256_update(&ctx, (unsigned char *)&txPrevTime, sizeof(unsigned int));

	mbedtls_sha256_update(&ctx, prevOutHash, sizeof(hash_t));
	mbedtls_sha256_update(&ctx, (unsigned char *)prevOutIdx, sizeof(unsigned int));
	mbedtls_sha256_update(&ctx, (unsigned char *)&txTime, sizeof(unsigned int));
	mbedtls_sha256_finish(&ctx, tmp);
	mbedtls_sha256_free(&ctx);
	mbedtls_sha256(tmp, 32, pos_hash, 0);
	return 1;
}


int compute_next_stake_modifier(mem_zone_ref_ptr newBlock,hash_t		nStakeModifier, hash_t Kernel)
{
	hash_t tmp;
	mbedtls_sha256_context ctx;
	mem_zone_ref pindex = { PTR_NULL };
	hash_t	nStakeModifierNew;

	/*
	mem_zone_ref log = { PTR_NULL };
	tree_manager_create_node			("log", NODE_LOG_PARAMS, &log);
	tree_manager_set_child_value_hash	(&log, "StakeMod", nStakeModifier);
	tree_manager_set_child_value_hash	(&log, "kernel", Kernel);
	log_message							("stake_pos3: ComputeNextStakeModifier:\n\tprev modifier:\n\t%StakeMod%\n\tkernel:\n\t%kernel%\n", &log);
	release_zone_ref					(&log);
	*/

	
	mbedtls_sha256_init(&ctx);
	mbedtls_sha256_starts(&ctx, 0);
	mbedtls_sha256_update(&ctx, Kernel, sizeof(hash_t));
	mbedtls_sha256_update(&ctx, nStakeModifier, sizeof(hash_t));
	mbedtls_sha256_finish(&ctx, tmp);
	mbedtls_sha256_free(&ctx);
	mbedtls_sha256(tmp, 32, nStakeModifierNew, 0);
	tree_manager_set_child_value_hash(newBlock, "StakeMod2", nStakeModifierNew);
	log_message("new modifier=%StakeMod2% time=%time% hash=%blk hash%", newBlock);
	return 1;
}
#define tree_zone 2

OS_API_C_FUNC(unsigned int) get_current_pos_difficulty()
{
	return last_diff;
}

OS_API_C_FUNC(int) find_last_pos_block(mem_zone_ref_ptr pindex, unsigned int *block_time)
{
	char			chash[65];
	int				ret = 0;
	tree_manager_get_child_value_str(pindex, NODE_HASH("blk hash"), chash, 65, 16);
	while (!is_pos_block(chash))
	{
		tree_manager_get_child_value_str(pindex, NODE_HASH("prev"), chash, 65, 16);
		if (!load_blk_hdr(pindex, chash))
			return 0;
	}
	if (is_pos_block(chash))
	{
		tree_manager_get_child_value_i32(pindex, NODE_HASH("time"), block_time);
		return 1;
	}
	return 0;
}
OS_API_C_FUNC(int) compute_last_pos_diff(mem_zone_ref_ptr lastPOS, unsigned int *nBits)
{
	hash_t			od1;
	unsigned int	prevTime, pprevTime;
	unsigned int	pBits;
	int64_t			nActualSpacing;
	int				ret;
	char			cpphash[65];
	mem_zone_ref	pprev = { PTR_NULL };

	if (!tree_manager_get_child_value_i32(lastPOS, NODE_HASH("bits"), &pBits))
		pBits = Di;

	tree_manager_get_child_value_i32(lastPOS, NODE_HASH("time"), &prevTime);
	tree_manager_get_child_value_str(lastPOS, NODE_HASH("prev"), cpphash, 65, 16);

	if (!load_blk_hdr(&pprev, cpphash))
	{
		*nBits = pBits;
		return 1;
	}
	
	ret = get_last_pos_block(&pprev, &pprevTime);
	if (ret)
	{
		nActualSpacing = prevTime - pprevTime;

		if (nActualSpacing > TargetSpacing * 10)
			nActualSpacing = TargetSpacing * 10;

		*(nBits) = calc_new_target(nActualSpacing, TargetSpacing, nTargetTimespan, pBits);

		SetCompact(*(nBits), od1);
		if (memcmp_c(od1, Difflimit, sizeof(hash_t)) > 0)
			*(nBits) = Di;

		last_diff = *(nBits);
	}
	release_zone_ref(&pprev);
	return ret;
}

OS_API_C_FUNC(int) compute_blk_staking(mem_zone_ref_ptr prev, mem_zone_ref_ptr prevPOS, mem_zone_ref_ptr hdr, mem_zone_ref_ptr tx_list, uint64_t *staking_reward)
{
	hash_t				StakeModKernel;
	hash_t				lastStakeModifier;
	mem_zone_ref		my_list = { PTR_NULL };
	mem_zone_ref		tx = { PTR_NULL }, tx2 = { PTR_NULL };
	unsigned int		lastStakeModifiertime;
	char				prevHash[65];
	int					ret=1;

	tree_manager_get_child_value_str(hdr, NODE_HASH("prev"), prevHash, 65, 16);
	
	if (!memcmp_c(prevHash, nullhash, 32))
	{
		tree_manager_get_child_value_i32(hdr, NODE_HASH("time"), &lastStakeModifiertime);
		if (!tree_manager_get_child_value_hash(hdr, NODE_HASH("StakeMod2"), lastStakeModifier))
		{
			memset_c(lastStakeModifier, 0, 32);
			tree_manager_set_child_value_hash(hdr, "StakeMod2", lastStakeModifier);
		}
		return 1;
	}

	if (!tree_manager_get_child_at(tx_list, 0, &tx))
		return 0;

	ret = tree_manager_get_child_at(tx_list, 1, &tx2);
	
	if (!get_last_stake_modifier(prev, lastStakeModifier, &lastStakeModifiertime))
	{
		memset_c(lastStakeModifier, 0, sizeof(hash_t));
		tree_manager_get_child_value_i32(hdr, NODE_HASH("time"), &lastStakeModifiertime);
	}

	if (ret && is_tx_null(&tx) && is_vout_null(&tx2, 0))
	{
		//block is proof of stake
		hash_t				rpos, rdiff;
		hash_t				pos_hash, out_diff,blk_hash = { 0 };
		unsigned int		prevOutIdx, txTime;
		mem_zone_ref		log = { PTR_NULL };
		uint64_t			weight;
		int					n;

		
		tree_manager_get_child_value_hash(hdr, NODE_HASH("blk hash"), blk_hash);
		tree_manager_get_child_value_i32(&tx2, NODE_HASH("time"), &txTime);
		
		compute_tx_pos						(&tx2, lastStakeModifier, txTime, pos_hash, StakeModKernel, &prevOutIdx);

		tree_manager_set_child_value_hash	(hdr, "blk pos", pos_hash);
		memset_c							(out_diff, 0, sizeof(hash_t));

		get_tx_output_amount(StakeModKernel, prevOutIdx, &weight);

		if (last_diff == 0xFFFFFFFF)
		{
			unsigned int					nBits;
			tree_manager_get_child_value_i32(hdr, NODE_HASH("bits"), &nBits);
			mul_compact						(nBits, weight, out_diff);
		}
		else
			mul_compact(last_diff, weight, out_diff);
			
		n = 32;
		while (n--)
		{
			rpos[n] = pos_hash[31 - n];
			rdiff[n] = out_diff[31 - n];
		}
		//check proof of stake
		if (cmp_hashle(pos_hash, out_diff) >= 0)
		{
			*staking_reward = nStakeReward;
			tree_manager_create_node("log", NODE_LOG_PARAMS, &log);
			tree_manager_set_child_value_hash(&log, "diff", rdiff);
			tree_manager_set_child_value_hash(&log, "pos", rpos);
			tree_manager_set_child_value_hash(&log, "hash", blk_hash);
			log_message("----------------\nNEW POS BLOCK\n%diff%\n%pos%\n%hash%\n", &log);
			release_zone_ref(&log);
		}
		else
		{
			tree_manager_create_node("log", NODE_LOG_PARAMS, &log);
			tree_manager_set_child_value_hash(&log, "diff", rdiff);
			tree_manager_set_child_value_hash(&log, "pos", rpos);
			tree_manager_set_child_value_hash(&log, "hash", blk_hash);
			log_message("----------------\nNBAD POS BLOCK\n%diff%\n%pos%\n%hash%\n", &log);
			release_zone_ref(&log);
			ret = 0;
		}
	}
	else
	{
		//get the kernel hash to compute the next stake modifier based on the new block hash
		tree_manager_get_child_value_hash(hdr, NODE_HASH("blk hash"), StakeModKernel);
		*staking_reward = 0;
		ret = 1;
	}
	
	release_zone_ref(&tx);
	release_zone_ref(&tx2);
	
	if (ret)
		ret = compute_next_stake_modifier(hdr, lastStakeModifier, StakeModKernel);
	else
	{
		int xx;
		xx = 0;
	}



	return ret;
}

