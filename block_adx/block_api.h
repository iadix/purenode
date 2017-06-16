#ifndef BLOCK_API
#define BLOCK_API C_IMPORT
#endif

/*
*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=
block.c
*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=
*/

/* init block module */
BLOCK_API  int	C_API_FUNC init_blocks(mem_zone_ref_ptr node_config);

/* 128 bit mul of 32 bits compact with 64 bits operand to 256 bit */
BLOCK_API  void	C_API_FUNC mul_compact(unsigned int nBits, uint64_t op, hash_t hash);

/* compare 256 bits hash */
BLOCK_API  int	C_API_FUNC cmp_hashle(hash_t hash1, hash_t hash2);

/* compute difficulty retargeting */
BLOCK_API unsigned int	C_API_FUNC calc_new_target(unsigned int nActualSpacing, unsigned int TargetSpacing, unsigned int nTargetTimespan, unsigned int pBits);

/* get block index size */
BLOCK_API  int	C_API_FUNC get_block_height();

/* get block reward at given block height */
BLOCK_API  int	C_API_FUNC get_blockreward(uint64_t block, uint64_t *block_reward);

/* get hash list from block header list */
BLOCK_API  int	C_API_FUNC get_hash_list(mem_zone_ref_ptr hdr_list, mem_zone_ref_ptr hash_list);

/* build merklee root */
BLOCK_API  int	C_API_FUNC build_merkel_tree(mem_zone_ref_ptr txs, hash_t merkleRoot);

/* build genesis block */
BLOCK_API  int	C_API_FUNC make_genesis_block(mem_zone_ref_ptr genesis_conf, mem_zone_ref_ptr genesis_blk);

/* get output from tx at specified index */
BLOCK_API int	C_API_FUNC   get_tx_output(mem_zone_ref_const_ptr tx, unsigned int idx, mem_zone_ref_ptr vout);

/* parse infos from signature script */
BLOCK_API  int	C_API_FUNC   get_insig_info(const struct string *script, struct string *sign, struct string *pubk, unsigned char *hash_type);

/* parse signature */
BLOCK_API  int	C_API_FUNC   parse_sig_seq(const struct string *sign_seq, struct string *sign, unsigned char *hashtype, int rev);

/* serialize script */
BLOCK_API  int	C_API_FUNC	serialize_script(mem_zone_ref_ptr script_node, struct string *script);

/* create null tx */
BLOCK_API  int	C_API_FUNC create_null_tx(mem_zone_ref_ptr tx, unsigned int time, unsigned int block_height);

/* check is tx is null */
BLOCK_API  int	C_API_FUNC is_tx_null(mem_zone_ref_const_ptr tx);

/* check is tx vout is null */
BLOCK_API  int	C_API_FUNC is_vout_null(mem_zone_ref_const_ptr tx, unsigned int idx);

/* create new transaction with the specified time */
BLOCK_API  int	C_API_FUNC new_transaction(mem_zone_ref_ptr tx, ctime_t time);

/* add output to the transaction */
BLOCK_API  int	C_API_FUNC tx_add_output(mem_zone_ref_ptr tx, uint64_t value, const struct string *script);
/* add input to the transaction */
BLOCK_API  int	C_API_FUNC tx_add_input(mem_zone_ref_ptr tx, const hash_t tx_hash, unsigned int index, struct string *script);
/* create paiment script */
BLOCK_API  int	C_API_FUNC create_payment_script(struct string *pubk, unsigned int type, mem_zone_ref_ptr script_node);

/* create paiment script */
BLOCK_API  int	C_API_FUNC create_p2sh_script(btc_addr_t addr, mem_zone_ref_ptr script_node);

/* compute transaction signature hash */
BLOCK_API  int	C_API_FUNC compute_tx_sign_hash(mem_zone_ref_const_ptr tx, unsigned int nIn, const struct string *script, unsigned int hash_type, hash_t txh);

/* check tx input signature */
BLOCK_API  int	C_API_FUNC check_tx_input_sig(mem_zone_ref_ptr tx, unsigned int nIn, struct string *vpubK);

/* check tx inputs */
BLOCK_API  int	C_API_FUNC check_tx_outputs(mem_zone_ref_ptr tx, uint64_t *total, unsigned int *is_staking);

/* check tx outputs */
BLOCK_API  int	C_API_FUNC check_tx_inputs(mem_zone_ref_ptr tx, uint64_t *total_in, unsigned int *is_coinbase,unsigned int check_sig);


/*check block pow */
BLOCK_API  int	C_API_FUNC check_block_pow(mem_zone_ref_ptr hdr, hash_t diff_hash);

/*check block signature */
BLOCK_API  int	C_API_FUNC check_block_sign(const struct string *sign, const hash_t hash, const struct string *pubk);

/* get parent txid */
BLOCK_API  int	C_API_FUNC get_tx_input_hash(mem_zone_ref_ptr tx, unsigned int idx, hash_t hash);

/* get amount from tx output */
BLOCK_API  int	C_API_FUNC get_tx_output_amount(mem_zone_ref_ptr tx, unsigned int idx, uint64_t *amount);

/* get output addr from tx output idx */
BLOCK_API  int	C_API_FUNC get_tx_output_addr(const hash_t tx_hash, unsigned int idx, btc_addr_t addr);
/* sign transaction input */
BLOCK_API  int	C_API_FUNC tx_sign(mem_zone_ref_const_ptr tx, unsigned int nIn, unsigned int hashType, const struct string *sign, const struct string *inPubKey);
/* compute sha256d hash from block header */
BLOCK_API int	C_API_FUNC	compute_block_hash(mem_zone_ref_ptr block, hash_t hash);

/* compute pow hash from block header */
BLOCK_API int	C_API_FUNC	compute_block_pow(mem_zone_ref_ptr block, hash_t hash);

/* compute current pow target */
BLOCK_API  int	C_API_FUNC block_compute_pow_target(mem_zone_ref_ptr ActualSpacing, mem_zone_ref_ptr diff);

/* compute txid from tx object */
BLOCK_API  int	C_API_FUNC compute_tx_hash(mem_zone_ref_ptr tx, hash_t hash);

/* get block version */
BLOCK_API int	C_API_FUNC	get_block_version(unsigned int *v);

/* check hash signature */
BLOCK_API int	C_API_FUNC	blk_check_sign(const struct string *sign, const struct string *pubk, const hash_t hash);

/* check validity of input transactions */
BLOCK_API  int	C_API_FUNC check_tx_list(mem_zone_ref_ptr tx_list, uint64_t block_reward,hash_t merkle,unsigned int check_sig);

/* get tx input idx */
BLOCK_API int	C_API_FUNC	get_tx_input(mem_zone_ref_const_ptr tx, unsigned int idx, mem_zone_ref_ptr vin);


/* set hash from compact from */
BLOCK_API unsigned int	C_API_FUNC SetCompact(unsigned int bits, hash_t out);


/*
*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=
script.c
*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=
*/

/* get public key / address from output script */
BLOCK_API int C_API_FUNC   get_out_script_address(const struct string *script, struct string *pubk, btc_addr_t addr);

/* get tx ouput script */
BLOCK_API int C_API_FUNC   get_tx_output_script(const hash_t tx_hash, unsigned int idx, struct string *script, uint64_t *amount);

/* public key get to hash */
BLOCK_API void C_API_FUNC   key_to_hash(unsigned char *pkey, unsigned char *keyHash);

/* public key  to addr */
BLOCK_API void C_API_FUNC  key_to_addr(unsigned char *pkey, btc_addr_t addr);

/* private address to private key */
BLOCK_API void C_API_FUNC   paddr_to_key(btc_paddr_t addr, dh_key_t key);


/*
*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=
store.c
*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=
*/
/* get total money supply */
BLOCK_API int C_API_FUNC  get_moneysupply(uint64_t *amount);

/* get block index size */
BLOCK_API int C_API_FUNC get_last_block_height();

/* find block hash from tx hash */
BLOCK_API int C_API_FUNC  find_blk_hash(const hash_t tx_hash, hash_t blk_hash);

/* find block hash in local store */
BLOCK_API int C_API_FUNC  find_hash(hash_t hash);

/* load block header from local store */
BLOCK_API int C_API_FUNC  load_blk_hdr(mem_zone_ref_ptr hdr, const char *blk_hash);

/* load block signature from local store */
BLOCK_API int C_API_FUNC  get_blk_sign(const char *blk_hash, struct string *sign);

/* load block height from local store */
BLOCK_API int C_API_FUNC  get_blk_height(const char *blk_hash, uint64_t *height);

/* load block header infos from tx hash */
BLOCK_API int C_API_FUNC  get_tx_blk_height(const hash_t tx_hash, uint64_t *height, uint64_t *block_time, uint64_t *tx_time);

/* check if block is pow */
BLOCK_API int C_API_FUNC  is_pow_block(const char *blk_hash);

/* store block in local storage */
BLOCK_API int C_API_FUNC  store_block(mem_zone_ref_ptr header, mem_zone_ref_ptr tx_list);

/* load tx from a block based on the tx hash */
BLOCK_API int C_API_FUNC  blk_load_tx_hash(const char *blk_hash, const char *tx_hash, mem_zone_ref_ptr tx);

/* load tx from a block based on its index */
BLOCK_API int C_API_FUNC  load_blk_tx(mem_zone_ref_ptr tx, const char *blk_hash, unsigned int tx_idx);

/* load tx from its hash */
BLOCK_API int C_API_FUNC  load_tx(mem_zone_ref_ptr tx, hash_t blk_hash, const hash_t tx_hash);

/* load tx input and parent tx */
BLOCK_API int C_API_FUNC  load_tx_input(mem_zone_ref_const_ptr tx, unsigned int idx, mem_zone_ref_ptr	vin, mem_zone_ref_ptr tx_out);

/* load input from block hash and tx hash + input id */
BLOCK_API int C_API_FUNC  load_blk_tx_input(const char *blk_hash, unsigned int tx_idx, unsigned int vin_idx, mem_zone_ref_ptr vout);

/* get amount of tx output*/
BLOCK_API int C_API_FUNC  load_tx_output_amount(const hash_t tx_hash, unsigned int idx, uint64_t *amount);

/* load parent output from an input */
BLOCK_API int C_API_FUNC  load_tx_input_vout(mem_zone_ref_const_ptr tx, unsigned int vin_idx, mem_zone_ref_ptr vout);

/* load all tx hashes from an address */
BLOCK_API int C_API_FUNC  load_tx_addresses(btc_addr_t addr, mem_zone_ref_ptr tx_hashes);

/* load block size from local store */
BLOCK_API int C_API_FUNC  get_block_size(const char *blk_hash, size_t *size);

/* load block hash from txs in block hash */
BLOCK_API int C_API_FUNC  get_blk_tx_hash(const char* blk_hash, unsigned int idx, hash_t tx_hash);

/* load tx hashes from block hash */
BLOCK_API int C_API_FUNC  get_blk_txs(const char* blk_hash, mem_zone_ref_ptr txs, size_t max);

/* load number of tx from block */
BLOCK_API unsigned int C_API_FUNC  get_blk_ntxs(const char* blk_hash);

/* load tx hashes from block hash */
BLOCK_API int C_API_FUNC  load_blk_txs(const char* blk_hash, mem_zone_ref_ptr txs);

/* load block time from local store */
BLOCK_API int C_API_FUNC  get_block_time(const char *blkHash, ctime_t *time);

/* get block pow from local store */
BLOCK_API int C_API_FUNC  get_pow_block(const char *blk_hash, hash_t pow);


/*store tx inputs */
BLOCK_API int C_API_FUNC  store_tx_inputs(mem_zone_ref_ptr tx);

/*store tx outputs */
BLOCK_API int C_API_FUNC  store_tx_outputs(mem_zone_ref_ptr tx, const char *blk_hash);

/*store tx hash into index */
BLOCK_API int C_API_FUNC  store_tx_index(const char * blk_hash, mem_zone_ref_ptr tx, hash_t thash);

/*store tx hash into address index */
BLOCK_API int C_API_FUNC  store_tx_addresses(btc_addr_t addr, hash_t tx_hash);

/* remove tx from address index */
BLOCK_API int C_API_FUNC  remove_tx_addresses(const btc_addr_t addr, const hash_t tx_hash);

/* remove tx from storage*/
BLOCK_API int C_API_FUNC  remove_tx(hash_t tx_hash);

/* load block index from storage */
BLOCK_API  int	C_API_FUNC load_block_indexes(mem_zone_ref_ptr hdr_list);

/* store block height for block hash*/
BLOCK_API  int	C_API_FUNC store_block_height(const char *hash, uint64_t height);

/*store block hash/txid index */
BLOCK_API  int	C_API_FUNC store_tx_blk_index(const hash_t tx_hash, const hash_t blk_hash);

/* clear all transaction indexes */
BLOCK_API  int	C_API_FUNC clear_tx_index();



/* staking API definition */

typedef int  C_API_FUNC				get_blk_staking_infos_func(mem_zone_ref_ptr blk, const char *blk_hash, mem_zone_ref_ptr infos);
typedef get_blk_staking_infos_func *get_blk_staking_infos_func_ptr;

typedef int	C_API_FUNC	store_tx_staking_func(mem_zone_ref_ptr tx, hash_t tx_hash, btc_addr_t stake_addr, uint64_t	stake_in);
typedef store_tx_staking_func		*store_tx_staking_func_ptr;

typedef int	C_API_FUNC	get_tx_pos_hash_data_func(mem_zone_ref_ptr hdr, const hash_t txHash, unsigned int OutIdx, struct string *hash_data, uint64_t *amount, hash_t out_diff);
typedef  get_tx_pos_hash_data_func *get_tx_pos_hash_data_func_ptr;

typedef int	C_API_FUNC get_target_spacing_func(unsigned int *target);
typedef  get_target_spacing_func   *get_target_spacing_func_ptr;

typedef int	C_API_FUNC get_stake_reward_func(uint64_t height, uint64_t *reward);
typedef get_stake_reward_func   *get_stake_reward_func_ptr;

typedef int	C_API_FUNC  get_last_stake_modifier_func(mem_zone_ref_ptr pindex, hash_t nStakeModifier, unsigned int *nModifierTime);
typedef get_last_stake_modifier_func   *get_last_stake_modifier_func_ptr;

typedef int	C_API_FUNC compute_tx_pos_func(mem_zone_ref_ptr tx, hash_t StakeModifier, unsigned int txTime, hash_t pos_hash, uint64_t *weight);
typedef compute_tx_pos_func   *compute_tx_pos_func_ptr;

typedef unsigned int	C_API_FUNC	get_current_pos_difficulty_func();
typedef get_current_pos_difficulty_func		*get_current_pos_difficulty_func_ptr;

typedef int	 C_API_FUNC	create_pos_block_func(hash_t pHash, mem_zone_ref_ptr tx, mem_zone_ref_ptr newBlock);
typedef create_pos_block_func *create_pos_block_func_ptr;

typedef int				C_API_FUNC	check_tx_pos_func(mem_zone_ref_ptr blk, mem_zone_ref_ptr tx);
typedef check_tx_pos_func					*check_tx_pos_func_ptr;


typedef int				C_API_FUNC	get_min_stake_depth_func(unsigned int *depth);
typedef get_min_stake_depth_func	*get_min_stake_depth_func_ptr;