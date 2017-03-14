//copyright iadix 2016
#include <base/std_def.h>
#include <base/std_mem.h>
#include <base/mem_base.h>
#include <base/std_str.h>

#include <sha256.h>
#include <md5.h>
#include <strs.h>
#include <tree.h>
#include <fsio.h>

static  unsigned int nModifierInterval = 0xFFFFFFFF;
// MODIFIER_INTERVAL_RATIO:
// ratio of group interval length between the last group and the first group
static  int			MODIFIER_INTERVAL_RATIO = 3;
hash_t				nullhash = { 0xCD };
unsigned int		TargetSpacing;

C_IMPORT int C_API_FUNC load_blk_hdr			(mem_zone_ref_ptr hdr, const char *blk_hash);
C_IMPORT int C_API_FUNC get_tx_output			(mem_zone_ref_const_ptr tx, unsigned int idx, mem_zone_ref_ptr vout);
C_IMPORT int C_API_FUNC	compute_block_hash		(mem_zone_ref_ptr hdr, hash_t blk_hash);
C_IMPORT int C_API_FUNC compute_block_pow		(mem_zone_ref_ptr block, hash_t hash);
C_IMPORT int C_API_FUNC is_tx_null				(mem_zone_ref_const_ptr tx);
C_IMPORT int C_API_FUNC is_vout_null			(mem_zone_ref_const_ptr tx, unsigned int idx);
C_IMPORT int C_API_FUNC load_tx_input			(mem_zone_ref_const_ptr tx, unsigned int idx, mem_zone_ref_ptr	vin , mem_zone_ref_ptr tx_out);
C_IMPORT int C_API_FUNC load_tx					(mem_zone_ref_ptr tx, const char *tx_hash);

#define ONE_COIN		100000000ULL
#define ONE_CENT		1000000ULL


OS_API_C_FUNC(int) init_pos(mem_zone_ref_ptr stake_conf)
{
	memset_c(nullhash, 0, 32);
	tree_manager_get_child_value_i32(stake_conf, NODE_HASH("ModifierInterval"), &nModifierInterval);
	tree_manager_get_child_value_si32(stake_conf, NODE_HASH("IntervalRatio"), &MODIFIER_INTERVAL_RATIO);
	if (!tree_manager_get_child_value_i32(stake_conf, NODE_HASH("target spacing"), &TargetSpacing))
		TargetSpacing = 60;


	return 1;
}


OS_API_C_FUNC(int) generated_stake_modifier(const char *blk_hash, uint64_t *StakeMod)
{
	char				dir[2][3];
	struct string		blk_path = { PTR_NULL };
	int					ret = 0;
	memcpy_c(dir[0], &blk_hash[0], 2);
	memcpy_c(dir[1], &blk_hash[2], 2);

	dir[0][2] = 0;
	dir[1][2] = 0;

	make_string(&blk_path, "./blks/");
	cat_cstring(&blk_path, dir[0]);
	cat_cstring(&blk_path, "/");
	cat_cstring(&blk_path, dir[1]);
	cat_cstring(&blk_path, "/");
	cat_cstring(&blk_path, blk_hash);
	cat_cstring(&blk_path, "/stakemodifier");
	if (stat_file(blk_path.str) == 0)
	{
		unsigned char	*data;
		size_t			data_len;
		if (get_file(blk_path.str, &data, &data_len))
		{
			if (data_len >= sizeof(uint64_t))
			{
				*StakeMod = *((uint64_t *)(data));
				ret = 1;
			}
			free_c(data);
		}
	}
	free_string(&blk_path);
	return ret;
}
// entropy bit for stake modifier if chosen by modifier
int GetStakeEntropyBit(mem_zone_ref_ptr blk, unsigned int *nEntropyBit)
{
	hash_t	blk_hash;
	// Take last bit of block hash as entropy bit
	if (!tree_manager_get_child_value_hash(blk, NODE_HASH("blk hash"), blk_hash))
		return 0;

	*nEntropyBit = (blk_hash[0] & 0x01);
	//LogPrint("stakemodifier", "GetStakeEntropyBit: hashBlock=%s nEntropyBit=%u\n", GetHash().ToString(), nEntropyBit);
	return 1;
}

OS_API_C_FUNC(unsigned int) SetStakeEntropyBit(mem_zone_ref_ptr block)
{
	unsigned int EntropyBit;
	if (!GetStakeEntropyBit(block, &EntropyBit))return 0;
	return tree_manager_set_child_value_i32(block, "Entropy", EntropyBit);
}
// Get the last stake modifier and its generation time from a given block
OS_API_C_FUNC(int) get_last_stake_modifier(mem_zone_ref_ptr pindex, uint64_t *nStakeModifier, unsigned int *nModifierTime)
{
	char			chash[65];
	int				ret=0;

    if (pindex==PTR_NULL)return 0;
	if (pindex->zone==PTR_NULL)return 0;
	if (!tree_manager_get_child_value_str(pindex, NODE_HASH("blk hash"), chash, 65, 16))return 0;

	while (!generated_stake_modifier(chash, nStakeModifier))
	{
		tree_manager_get_child_value_str(pindex, NODE_HASH("prev"), chash,65,16);
		if (!load_blk_hdr(pindex, chash))
			return 0;
	}
	if (generated_stake_modifier(chash, nStakeModifier))
	{
		tree_manager_set_child_value_i64(pindex, "StakeMod", *nStakeModifier);
		ret = tree_manager_get_child_value_i32(pindex, NODE_HASH("time"), nModifierTime);
	}

	return ret;
}
// Get selection interval section (in seconds)
static int64_t GetStakeModifierSelectionIntervalSection(int nSection)
{
    return (nModifierInterval * 63 / (63 + ((63 - nSection) * (MODIFIER_INTERVAL_RATIO - 1))));
}

// Get stake modifier selection interval (in seconds)
static int64_t GetStakeModifierSelectionInterval()
{
    int64_t nSelectionInterval = 0;
    for (int nSection=0; nSection<64; nSection++)
        nSelectionInterval += GetStakeModifierSelectionIntervalSection(nSection);
    return nSelectionInterval;
}



int IsProofOfStake(mem_zone_ref_ptr block)
{
	return 0;
	//load_tx()
}

// select a block from the candidate blocks in vSortedByTimestamp, excluding
// already selected blocks in vSelectedBlocks, and with timestamp up to
// nSelectionIntervalStop.
static int SelectBlockFromCandidates(mem_zone_ref_ptr vSortedByTimestamp,ctime_t nSelectionIntervalStop, uint64_t nStakeModifierPrev, mem_zone_ref_ptr pindexSelected)
{
    int   fSelected				= 0;
	hash_t rhashBest = { 0xFF }, hashBest = { 0xFF };
	mem_zone_ref		log = { PTR_NULL },my_list = { PTR_NULL };
	mem_zone_ref_ptr	block =  PTR_NULL ;
	int n;
	

	for (tree_manager_get_first_child(vSortedByTimestamp, &my_list, &block); ((block != PTR_NULL) && (block->zone != PTR_NULL)); tree_manager_get_next_child(&my_list, &block))
	{
		mbedtls_sha256_context ctx;
		unsigned int selected;
		ctime_t block_time;
		hash_t blk_hash, hashSelection, blk_pow,tmp;
		
		tree_manager_get_child_value_i64(block , NODE_HASH("time")		, &block_time);
		tree_manager_get_child_value_hash(block, NODE_HASH("blk hash")	, blk_hash);

		if (fSelected && block_time > nSelectionIntervalStop)
		{
			release_zone_ref(&my_list);
			break;
		}

		if (tree_manager_get_child_value_i32(block, NODE_HASH("selected"), &selected))
			continue;

		//CDataStream ss(SER_GETHASH, 0);
		//ss << pindex->hashProof << nStakeModifierPrev;
		//uint256 hashSelection = Hash(ss.begin(), ss.end());

		compute_block_pow(block, blk_pow);

		mbedtls_sha256_init(&ctx);
		mbedtls_sha256_starts(&ctx, 0);
		mbedtls_sha256_update(&ctx, blk_pow, 32);
		mbedtls_sha256_update(&ctx,(unsigned char *)&nStakeModifierPrev, sizeof(uint64_t));
		mbedtls_sha256_finish(&ctx, tmp);
		mbedtls_sha256_free(&ctx);
		mbedtls_sha256(tmp, 32, hashSelection, 0);
		// the selection hash is divided by 2**32 so that proof-of-stake block
		// is always favored over proof-of-work block. this is to preserve
		// the energy efficiency property
		if (IsProofOfStake(block))
		{
			memmove_c(&hashSelection[4], hashSelection, 28);
			*((unsigned int*)(hashSelection)) = 0;
		}
		
		if (fSelected && (hashSelection < hashBest))
		{
			memcpy_c(hashBest ,hashSelection,sizeof(hash_t));
			copy_zone_ref(pindexSelected,block);
		}
		else if (!fSelected)
		{
			fSelected = 1;
			memcpy_c(hashBest, hashSelection, sizeof(hash_t));
			copy_zone_ref(pindexSelected, block);
		}
	}


	n = 32;
	while (n--)
 		rhashBest[n] = hashBest[31 - n];

	tree_manager_create_node			("log", NODE_LOG_PARAMS, &log);
	tree_manager_set_child_value_hash	(&log, "hashBest", rhashBest);
	log_message							("stake_pos3: SelectBlockFromCandidates: selection hash=%hashBest%\n",&log);
	release_zone_ref					(&log);
	//a0e24563d29570abbe5b971c589ebf7734d2d8109ad61c4131683bf4b6ff820d
	return fSelected;
#if 0
	BOOST_FOREACH(const PAIRTYPE(int64_t, uint256)& item, vSortedByTimestamp)
    {
        if (!mapBlockIndex.count(item.second))
            return error("SelectBlockFromCandidates: failed to find block index for candidate block %s", item.second.ToString());
        const CBlockIndex* pindex = mapBlockIndex[item.second];
        if (fSelected && pindex->GetBlockTime() > nSelectionIntervalStop)
            break;
        if (mapSelectedBlocks.count(pindex->GetBlockHash()) > 0)
            continue;
        // compute the selection hash by hashing its proof-hash and the
        // previous proof-of-stake modifier
        CDataStream ss(SER_GETHASH, 0);
        ss << pindex->hashProof << nStakeModifierPrev;
        uint256 hashSelection = Hash(ss.begin(), ss.end());
        // the selection hash is divided by 2**32 so that proof-of-stake block
        // is always favored over proof-of-work block. this is to preserve
        // the energy efficiency property
        if (pindex->IsProofOfStake())
            hashSelection >>= 32;
        if (fSelected && hashSelection < hashBest)
        {
            hashBest = hashSelection;
            *pindexSelected = (const CBlockIndex*) pindex;
        }
        else if (!fSelected)
        {
            fSelected = true;
            hashBest = hashSelection;
            *pindexSelected = (const CBlockIndex*) pindex;
        }
    }
    LogPrint("stakemodifier", "SelectBlockFromCandidates: selection hash=%s\n", hashBest.ToString());
#endif
}


int compute_tx_pos(mem_zone_ref_ptr tx, unsigned int TimeBlockFrom,uint64_t StakeModifier, hash_t pos_hash)
{
	hash_t tmp, prevOutHash;
	mbedtls_sha256_context ctx;
	mem_zone_ref	vin = { PTR_NULL }, prev_tx = { PTR_NULL };
	unsigned int prevOutIdx;

	uint64_t	txPrevTime, txTime;
	tree_manager_get_child_value_i64(tx, NODE_HASH("time"), &txTime);

	load_tx_input(tx, 0, &vin, &prev_tx);
	tree_manager_get_child_value_i64(&prev_tx, NODE_HASH("time"), &txPrevTime);
	tree_manager_get_child_value_hash(&vin, NODE_HASH("tx hash"), prevOutHash);
	tree_manager_get_child_value_i32(&vin, NODE_HASH("idx"), &prevOutIdx);

	release_zone_ref(&vin);
	release_zone_ref(&prev_tx);


	mbedtls_sha256_init(&ctx);
	mbedtls_sha256_starts(&ctx, 0);
	mbedtls_sha256_update(&ctx, (unsigned char *)&StakeModifier, sizeof(uint64_t));
	mbedtls_sha256_update(&ctx, (unsigned char *)&TimeBlockFrom, sizeof(unsigned int));
	mbedtls_sha256_update(&ctx, (unsigned char *)&txPrevTime, sizeof(uint64_t));
	mbedtls_sha256_update(&ctx, prevOutHash, sizeof(hash_t));
	mbedtls_sha256_update(&ctx, (unsigned char *)&prevOutIdx, 4);
	mbedtls_sha256_update(&ctx, (unsigned char *)&txTime, sizeof(uint64_t));
	mbedtls_sha256_finish(&ctx, tmp);
	mbedtls_sha256_free(&ctx);
	mbedtls_sha256(tmp, 32, pos_hash, 0);

	return 1;

}


int compute_next_stake_modifier(mem_zone_ref_ptr pindexPrev, mem_zone_ref_ptr newBlock)
{
	char				prevHash[65];
	mem_zone_ref pindex = { PTR_NULL };
	mem_zone_ref log = { PTR_NULL };
	mem_zone_ref vSortedByTimestamp = { PTR_NULL };
	uint64_t nStakeModifierNew;
	uint64_t nStakeModifier;
	int64_t nSelectionInterval;
	int64_t nSelectionIntervalStart;
	int64_t nSelectionIntervalStop;
	unsigned int block_time, nModifierTime = 0;
	size_t		maxRound;
	int nc;

	// First find current stake modifier and its generation block time
	// if it's not old enough, return the same stake modifier
	if (!tree_manager_find_child_node(newBlock, NODE_HASH("blk prev"), NODE_BITCORE_BLK_HDR, &pindex))
	{
		tree_manager_get_child_value_str(newBlock, NODE_HASH("prev"), prevHash, 65, 16);
		tree_manager_add_child_node(newBlock, "blk prev", NODE_BITCORE_BLK_HDR, &pindex);
		if (!load_blk_hdr(&pindex, prevHash))
		{
			release_zone_ref(&pindex);
			return 0;
		}
	}
	SetStakeEntropyBit(newBlock);

	tree_manager_get_child_value_i32(&pindex, NODE_HASH("time"), &block_time);
	tree_manager_get_child_value_i32(pindexPrev, NODE_HASH("time"), &nModifierTime);
	tree_manager_get_child_value_i64(pindexPrev, NODE_HASH("StakeMod"), &nStakeModifier);

	tree_manager_create_node("log", NODE_LOG_PARAMS, &log);
	tree_manager_set_child_value_i64(&log, "StakeMod", nStakeModifier);
	tree_manager_set_child_value_si64(&log, "time", nModifierTime);
	log_message("stake_pos3: ComputeNextStakeModifier: prev modifier=%StakeMod% %time%\n", &log);
	release_zone_ref(&log);


	if (nModifierTime / nModifierInterval >= block_time / nModifierInterval)
		return 1;

	// Sort candidate blocks by timestamp
	tree_manager_create_node("SortedByTimestamp", NODE_BITCORE_BLK_HDR_LIST, &vSortedByTimestamp);
	nSelectionInterval = GetStakeModifierSelectionInterval();
	nSelectionIntervalStart = (block_time / nModifierInterval) * nModifierInterval - nSelectionInterval;
	//const CBlockIndex* pindex = pindexPrev;


	while (pindex.zone != PTR_NULL && block_time >= nSelectionIntervalStart)
	{
		char	chash[65];
		tree_manager_node_add_child(&vSortedByTimestamp, &pindex);
		tree_manager_get_child_value_str(&pindex, NODE_HASH("prev"), chash, 65, 16);
		if (!load_blk_hdr(&pindex, chash))
		{
			release_zone_ref(&pindex);
			break;
		}
		tree_manager_get_child_value_i32(&pindex, NODE_HASH("time"), &block_time);
	}
	tree_manager_sort_childs(&vSortedByTimestamp, "time", 0);
	nc = tree_manager_get_node_num_children(&vSortedByTimestamp);


	// Select 64 blocks from candidate blocks to generate stake modifier
	nStakeModifierNew = 0;
	nSelectionIntervalStop = nSelectionIntervalStart;
	maxRound = nc<64 ? nc : 64;//min(64, (int)vSortedByTimestamp.size())	
	for (unsigned int nRound = 0; nRound<maxRound; nRound++)
	{
		unsigned int nEntropyBit = 0;
		// add an interval section to the current selection round
		nSelectionIntervalStop += GetStakeModifierSelectionIntervalSection(nRound);
		// select a block from the candidates of current round

		if (!SelectBlockFromCandidates(&vSortedByTimestamp, nSelectionIntervalStop, nStakeModifier, &pindex))
			return 0;

		// write the entropy bit of the selected block
		GetStakeEntropyBit(&pindex, &nEntropyBit);
		nStakeModifierNew |= (nEntropyBit << nRound);
		tree_manager_set_child_value_i32(&pindex, "selected", 1);
		release_zone_ref(&pindex);
		// add the selected block from candidates to selected list
		//LogPrint("stakemodifier", "ComputeNextStakeModifier: selected round %d stop=%s height=%d bit=%d\n", nRound, DateTimeStrFormat(nSelectionIntervalStop), pindex->nHeight, pindex->GetStakeEntropyBit());
	}

	release_zone_ref(&pindex);
	release_zone_ref(&vSortedByTimestamp);

	tree_manager_set_child_value_i64(newBlock, "StakeMod", nStakeModifierNew);
	return 1;
}
OS_API_C_FUNC(int) compute_blk_staking(mem_zone_ref_ptr prev, mem_zone_ref_ptr hdr, mem_zone_ref_ptr tx_list, uint64_t *staking_reward)
{
	char				prevHash[65];
	uint64_t			lastStakeModifier;
	unsigned int		lastStakeModifiertime;
	mem_zone_ref		my_list = { PTR_NULL };
	mem_zone_ref_ptr	ttx = PTR_NULL, tx = PTR_NULL, tx2 = PTR_NULL;
	int					ret;
	tree_manager_get_child_value_str(hdr, NODE_HASH("prev"), prevHash, 65, 16);

	if (!memcmp_c(prevHash, nullhash, 32))
	{
		lastStakeModifier = 0;
		if (!tree_manager_get_child_value_i64(hdr, NODE_HASH("StakeMod"), &lastStakeModifier))
			tree_manager_set_child_value_i64(hdr, "StakeMod", lastStakeModifier);

		tree_manager_get_child_value_i32(hdr, NODE_HASH("time"), &lastStakeModifiertime);
		*staking_reward = 0;
		return 1;
	}

	if (!tree_manager_get_first_child(tx_list, &my_list, &ttx))return 0;
	tx = ttx;
	if (!tree_manager_get_next_child(&my_list, &ttx))	{
		return 1;
	}
	tx2 = ttx;
		

	ret=get_last_stake_modifier(prev, &lastStakeModifier, &lastStakeModifiertime);

	if (is_tx_null(tx) && is_vout_null(tx2, 0))
	{
		hash_t		pos_hash;
		unsigned int blockTime;

		ret = tree_manager_get_child_value_i32(hdr, NODE_HASH("time"), &blockTime);
		ret = compute_tx_pos(tx, blockTime, lastStakeModifier, pos_hash);
		*staking_reward = 15 * ONE_CENT;
	}
	else
	{
		ret = 1;
		*staking_reward = 0;
	}
	ret = compute_next_stake_modifier(prev, hdr);
	

	release_zone_ref(tx);
	release_zone_ref(tx2);
	release_zone_ref(&my_list);
	return ret;
}

OS_API_C_FUNC(int) store_blk_staking(mem_zone_ref_ptr header)
{
	char blk_hash[65];
	struct string blk_path = { 0 };
	struct string file_path = { 0 };
	uint64_t StakeMod;
	int stat;
	unsigned int EntropyBit;

	if (!tree_manager_get_child_value_str(header, NODE_HASH("blk hash"), blk_hash,65,16))return 0;

	make_string	(&blk_path, "./blks/");
	cat_ncstring(&blk_path, blk_hash + 62, 2);
	cat_cstring	(&blk_path, "/");
	cat_ncstring(&blk_path, blk_hash + 60, 2);
	cat_cstring	(&blk_path, "/");
	cat_cstring	(&blk_path, blk_hash);

	stat = stat_file(blk_path.str);
	if (stat != 0)
	{
		free_string(&blk_path);
		return 0;
	}
	if (tree_manager_get_child_value_i64(header, NODE_HASH("StakeMod"), &StakeMod))
	{
		
		clone_string		(&file_path		, &blk_path);
		cat_cstring			(&file_path		, "/stakemodifier");
		put_file			(file_path.str	, &StakeMod, sizeof(uint64_t));
		free_string			(&file_path);
	}

	if (tree_manager_get_child_value_i32(header, NODE_HASH("Entropy"), &EntropyBit))
	{
		clone_string		(&file_path, &blk_path);
		cat_cstring			(&file_path, "/entropy");
		stat = stat_file	(file_path.str);
		if (EntropyBit)
		{
			if (stat != 0)
				put_file(file_path.str, PTR_NULL, 0);
		}
		else
		{
			if (stat == 0)
				del_file(file_path.str);
		}
		free_string(&file_path);
	}

	return 1;
}

/*
OS_API_C_FUNC(int)	store_stakemodifier(mem_zone_ref_ptr genesis, uint64_t StakeMod)
{
	char				file_name[65];
	hash_t				blk_hash;
	char				dir[2][3];
	struct string		blk_path = { 0 };
	int					n;

	tree_manager_get_child_value_hash(genesis, NODE_HASH("blk hash"), blk_hash);

	itoa_s(blk_hash[0], dir[0], 3, 16);
	itoa_s(blk_hash[1], dir[1], 3, 16);

	n = 0;
	while (n<32)
	{
		file_name[n * 2 + 0] = hex_chars[blk_hash[n] >> 4];
		file_name[n * 2 + 1] = hex_chars[blk_hash[n] & 0x0F];
		n++;
	}
	file_name[64] = 0;

	make_string(&blk_path, "./blks/");
	cat_cstring(&blk_path, dir[0]);
	cat_cstring(&blk_path, "/");
	cat_cstring(&blk_path, dir[1]);
	cat_cstring(&blk_path, "/");
	cat_cstring(&blk_path, file_name);
	cat_cstring(&blk_path, "/stakemodifier");
	put_file(blk_path.str, &StakeMod, sizeof(uint64_t));
}
*/