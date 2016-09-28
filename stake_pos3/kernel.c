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
hash_t			Difflimit = { 0xCD };;
static int64_t	TargetSpacing = 0xFFFFFFFF;
static int64_t	nTargetTimespan = 0xFFFFFFFF;
static int64_t	nStakeReward= 0xFFFFFFFF;


C_IMPORT int  C_API_FUNC load_blk_hdr			(mem_zone_ref_ptr hdr, const char *blk_hash);
C_IMPORT int  C_API_FUNC get_tx_output			(mem_zone_ref_const_ptr tx, unsigned int idx, mem_zone_ref_ptr vout);
C_IMPORT int  C_API_FUNC get_tx_input			(mem_zone_ref_const_ptr tx, unsigned int idx, mem_zone_ref_ptr vin);
C_IMPORT int  C_API_FUNC compute_block_hash		(mem_zone_ref_ptr hdr, hash_t blk_hash);
C_IMPORT int  C_API_FUNC compute_block_pow		(mem_zone_ref_ptr block, hash_t hash);
C_IMPORT int  C_API_FUNC is_tx_null				(mem_zone_ref_const_ptr tx);
C_IMPORT int  C_API_FUNC is_vout_null			(mem_zone_ref_const_ptr tx, unsigned int idx);
C_IMPORT int  C_API_FUNC load_tx_input			(mem_zone_ref_const_ptr tx, unsigned int idx, mem_zone_ref_ptr	vin , mem_zone_ref_ptr tx_out);
C_IMPORT int  C_API_FUNC load_tx				(mem_zone_ref_ptr tx, const char *tx_hash);
C_IMPORT int  C_API_FUNC SetCompact				(unsigned int bits, hash_t out);
C_IMPORT int  C_API_FUNC get_tx_output_amount	(const char *tx_hash, unsigned int idx, uint64_t *amount);
C_IMPORT void C_API_FUNC mul_compact			(unsigned int nBits, uint64_t op, hash_t hash);
C_IMPORT int  C_API_FUNC cmp_hashle				(hash_t hash1, hash_t hash2);
C_IMPORT int  C_API_FUNC check_diff				(unsigned int nActualSpacing, unsigned int TargetSpacing, unsigned int nTargetTimespan,hash_t limit, unsigned int pBits, unsigned int nBits);

#define ONE_COIN		100000000ULL
#define ONE_CENT		1000000ULL


OS_API_C_FUNC(int) init_pos(mem_zone_ref_ptr stake_conf)
{
	unsigned int Di;
	memset_c(nullhash, 0, 32);

	if(!tree_manager_get_child_value_i64(stake_conf, NODE_HASH("target spacing"), &TargetSpacing))
		TargetSpacing= 64;


	if (!tree_manager_get_child_value_i64(stake_conf, NODE_HASH("target timespan"), &nTargetTimespan))
		nTargetTimespan = 16 * 60;  // 16 mins

	if (!tree_manager_get_child_value_i64(stake_conf, NODE_HASH("stake reward"), &nStakeReward))
		nStakeReward = 150 * ONE_CENT;  // 16 mins

	if (!tree_manager_get_child_value_i32(stake_conf, NODE_HASH("limit"), &Di))
		Di = 0x1B00FFFF;

	SetCompact(Di, Difflimit);
	return 1;
}


OS_API_C_FUNC(int) generated_stake_modifier(const char *blk_hash, hash_t StakeMod)
{
	struct string		blk_path = { PTR_NULL };
	int					ret = 0;

	make_string(&blk_path, "./blks/");
	cat_ncstring(&blk_path, blk_hash+0,2);
	cat_cstring(&blk_path, "/");
	cat_ncstring(&blk_path, blk_hash+2, 2);
	cat_cstring(&blk_path, "/");
	cat_cstring(&blk_path, blk_hash);
	cat_cstring(&blk_path, "/stakemodifier2");
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
int get_last_stake_modifier(mem_zone_ref_ptr pindex, hash_t nStakeModifier, unsigned int *nModifierTime)
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

	make_string(&file_path, "./blks/");
	cat_ncstring(&file_path, blk_hash + 0, 2);
	cat_cstring(&file_path, "/");
	cat_ncstring(&file_path, blk_hash + 2, 2);
	cat_cstring(&file_path, "/");
	cat_cstring(&file_path, blk_hash);
	cat_cstring(&file_path, "/pos");
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



OS_API_C_FUNC(int) store_blk_staking(mem_zone_ref_ptr header)
{
	char blk_hash[65];
	struct string blk_path = { 0 }, file_path = { 0 };
	hash_t StakeMod, hashPos;
	int stat, ret;

	if (!tree_manager_get_child_value_str(header, NODE_HASH("blk hash"), blk_hash, 65, 16))return 0;

	make_string(&blk_path, "./blks/");
	cat_ncstring(&blk_path, blk_hash + 0, 2);
	cat_cstring(&blk_path, "/");
	cat_ncstring(&blk_path, blk_hash + 2, 2);
	cat_cstring(&blk_path, "/");
	cat_cstring(&blk_path, blk_hash);

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
		cat_cstring(&file_path, "/stakemodifier2");
		ret = put_file(file_path.str, StakeMod, sizeof(hash_t));
		free_string(&file_path);
	}
	if (tree_manager_get_child_value_hash(header, NODE_HASH("pos"), hashPos))
	{
		clone_string(&file_path, &blk_path);
		cat_cstring(&file_path, "/pos");
		ret = put_file(file_path.str, hashPos, sizeof(hash_t));
		free_string(&file_path);
	}
	free_string(&blk_path);

	return ret;
}
#define tree_zone 2

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
	mem_zone_ref log = { PTR_NULL };
	hash_t	nStakeModifierNew;


	
	tree_manager_create_node			("log", NODE_LOG_PARAMS, &log);
	tree_manager_set_child_value_hash	(&log, "StakeMod", nStakeModifier);
	tree_manager_set_child_value_hash	(&log, "kernel", Kernel);
	log_message							("stake_pos3: ComputeNextStakeModifier:\n\tprev modifier:\n\t%StakeMod%\n\tkernel:\n\t%kernel%\n", &log);
	release_zone_ref					(&log);

	
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


OS_API_C_FUNC(int) compute_blk_staking(mem_zone_ref_ptr prev, mem_zone_ref_ptr hdr, mem_zone_ref_ptr tx_list, uint64_t *staking_reward)
{
	hash_t				StakeModKernel;
	hash_t				lastStakeModifier;
	mem_zone_ref		my_list = { PTR_NULL }, prevStakeMod = { PTR_NULL };
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
	/*
	if (!load_blk_hdr(&prev, prevHash))
	{
		release_zone_ref(&my_list);
		return 0;
	}
	*/

	copy_zone_ref			(&prevStakeMod, prev);
	get_last_stake_modifier	(&prevStakeMod, lastStakeModifier, &lastStakeModifiertime);
	release_zone_ref		(&prevStakeMod);

	
	if (!tree_manager_get_child_at(tx_list, 0, &tx))
		return 0;

	ret = tree_manager_get_child_at(tx_list, 1, &tx2);

	
	if (ret && is_tx_null(&tx) && is_vout_null(&tx2, 0))
	{
		//block is proof of stake
		char				cphash[65];
		hash_t				pos_hash, blk_hash = { 0 }, diff_hash = { 0 };
		unsigned int		pBits,nBits, prevOutIdx, txTime;
		unsigned int		prevTime, pprevTime;
		mem_zone_ref		prevPOS = { PTR_NULL },log = { PTR_NULL };
		uint64_t			weight;
		int					n,sRet;

		tree_manager_get_child_value_i32(hdr, NODE_HASH("bits"), &nBits);
		tree_manager_get_child_value_hash(hdr, NODE_HASH("blk hash"), blk_hash);
	
		tree_manager_get_child_value_i32(&tx2, NODE_HASH("time"), &txTime);
		compute_tx_pos					(&tx2, lastStakeModifier, txTime, pos_hash, StakeModKernel, &prevOutIdx);


		//get last two pos blocks
		copy_zone_ref(&prevPOS, prev);
		sRet = get_last_pos_block(&prevPOS, &prevTime);
		if (sRet)
		{
			char			cpphash[65];
			mem_zone_ref	pprev = { PTR_NULL };

			tree_manager_get_child_value_i32(&prevPOS, NODE_HASH("bits"), &pBits);
			tree_manager_get_child_value_str(&prevPOS, NODE_HASH("prev"), cpphash, 65, 16);
			
			sRet = load_blk_hdr(&pprev, cpphash);
			if (sRet)
			{
				sRet = get_last_pos_block(&pprev, &pprevTime);
				release_zone_ref(&pprev);
			}
		}
		release_zone_ref(&prevPOS);


		//compute current block difficulty
		if (sRet)
		{
			int64_t				nActualSpacing;
			
			nActualSpacing = prevTime - pprevTime;

			if (nActualSpacing > TargetSpacing * 10)
				nActualSpacing = TargetSpacing * 10;

			if (!check_diff(nActualSpacing, TargetSpacing, nTargetTimespan, Difflimit, pBits, nBits))
			{
				tree_manager_create_node("log", NODE_LOG_PARAMS, &log);
				tree_manager_set_child_value_i32(&log, "diff"   , pBits);
				tree_manager_set_child_value_i32(&log, "diff2"  , nBits);
				tree_manager_set_child_value_i32(&log, "spacing", nActualSpacing);
				tree_manager_set_child_value_hash(&log, "hash"  , blk_hash);
				log_message("----------------\nBAD POS DIFF %diff% + %spacing% !=0 %diff2%\n%hash%\n", &log);
				release_zone_ref(&log);
				ret = 0;
			}
		}
	
		if (ret)
		{
			hash_t rpos,rdiff;
			//StakeModKernel is prev out hash
			
			//get weighted difficulty
			n = 0;
			while (n < 32)
			{
				cphash[n * 2 + 0] = hex_chars[StakeModKernel[n] >> 0x04];
				cphash[n * 2 + 1] = hex_chars[StakeModKernel[n] & 0x0F];
				n++;
			}
			cphash[64] = 0;

			get_tx_output_amount(cphash, prevOutIdx, &weight);
			mul_compact(nBits, weight, diff_hash);

			n = 32;
			while (n--)
			{
				rpos[n] = pos_hash[31 - n];
				rdiff[n] = diff_hash[31 - n];
			}

	
			
			//check proof of stake
			if (cmp_hashle(pos_hash, diff_hash) >= 0)
			{
				tree_manager_set_child_value_hash(hdr, "pos", pos_hash);
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



	return ret;
}

