Module to handle blocks and transactions.

block.c : manipulation of block in memory

store.c : loading and storing of blocks in the local storage

script.c : manipulation of transaction script


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

/* create paiment script with return data */

OS_API_C_FUNC(int) create_payment_script_data(struct string *pubk, unsigned int type, mem_zone_ref_ptr script_node, unsigned char *data, size_t len);

/* create paiment script */

BLOCK_API  int	C_API_FUNC create_p2sh_script(btc_addr_t addr, mem_zone_ref_ptr script_node);

/* create paiment script with byte data */

BLOCK_API  int	C_API_FUNC create_p2sh_script_byte(btc_addr_t addr,mem_zone_ref_ptr script_node,unsigned char val);


/* create paiment script with data */

BLOCK_API  int	C_API_FUNC create_p2sh_script_data(btc_addr_t addr, mem_zone_ref_ptr script_node, unsigned char *data, size_t len);

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

/* find input in tx list */

BLOCK_API  int	C_API_FUNC find_inputs	(mem_zone_ref_ptr tx_list, hash_t txid, unsigned int oidx);

/* get tx input idx */

BLOCK_API int	C_API_FUNC	get_tx_input(mem_zone_ref_const_ptr tx, unsigned int idx, mem_zone_ref_ptr vin);

/* set hash from compact from */

BLOCK_API unsigned int	C_API_FUNC SetCompact(unsigned int bits, hash_t out);

/*check utxo */

BLOCK_API int C_API_FUNC check_utxo(const char *tx, unsigned int oidx);

/* dump infos about tx */

BLOCK_API int C_API_FUNC dump_tx_infos(mem_zone_ref_ptr tx);

/* dump infos about tx from hash*/

BLOCK_API int C_API_FUNC dump_txh_infos(const char *hash);

/* set node's root application */

BLOCK_API int C_API_FUNC set_root_app(mem_zone_ref_ptr tx);

/* get node's root application */

BLOCK_API int C_API_FUNC get_root_app(mem_zone_ref_ptr  rootAppHash);

/* get node's root application address */

BLOCK_API int C_API_FUNC get_root_app_addr(mem_zone_ref_ptr rootAppAddr);

/* get node's root application fees */

BLOCK_API int C_API_FUNC get_root_app_fee(mem_zone_ref_ptr rootAppFees);

/* check tx for root transaction */

BLOCK_API int C_API_FUNC is_app_root(mem_zone_ref_ptr tx);

/* get node's applications */

BLOCK_API int C_API_FUNC get_apps(mem_zone_ref_ptr Apps);

/* generate application root transaction */

BLOCK_API int C_API_FUNC make_approot_tx(mem_zone_ref_ptr tx, ctime_t time,btc_addr_t addr);

/* parse application root tx */

BLOCK_API int C_API_FUNC parse_approot_tx	(mem_zone_ref_ptr tx);

/* generate application transaction */

BLOCK_API int C_API_FUNC make_app_tx		(mem_zone_ref_ptr tx,const char *app_name,btc_addr_t appAddr);

/* generate application item transaction */

BLOCK_API int C_API_FUNC make_app_item_tx	(mem_zone_ref_ptr tx, const struct string *app_name, unsigned int item_id);

/* get application name from script definition */

BLOCK_API int C_API_FUNC get_app_name		(const struct string *script, struct string *app_name);

/* get type informations from script */

BLOCK_API int C_API_FUNC get_type_infos(struct string *script, char *name, unsigned int *id, unsigned int *flags);

/* get application type definitions */

BLOCK_API int C_API_FUNC get_app_types		(mem_zone_ref_ptr app, mem_zone_ref_ptr types);

/* get application scripts */

BLOCK_API int C_API_FUNC get_app_scripts	(mem_zone_ref_ptr app, mem_zone_ref_ptr scripts);

/* get file hash from transaction */

BLOCK_API  int  C_API_FUNC get_tx_file(mem_zone_ref_ptr tx, mem_zone_ref_ptr hash_list);

/* check if tx is application file */

BLOCK_API  int	C_API_FUNC tx_is_app_file(mem_zone_ref_ptr tx, struct string *appName, mem_zone_ref_ptr file);

/* retrieve key information from type definition */

BLOCK_API  int	C_API_FUNC get_app_type_key(struct string *appName, unsigned int type_id, const char *kname, unsigned int *ktype, unsigned int *flags);

/* get type definition indexes */

BLOCK_API  int	C_API_FUNC get_app_type_idxs(const char *appName, unsigned int type_id, mem_zone_ref_ptr keys);

/* load type definition from local storage */

BLOCK_API  int	C_API_FUNC load_obj_type(const char *app_name, const char *objHash, unsigned int *type_id, btc_addr_t objAddr);

/* check if object has only unique value for unique indexes */

BLOCK_API  int	C_API_FUNC check_app_obj_unique(const char *appName, unsigned int type_id, mem_zone_ref_ptr obj);

/* get binary tree of block inputs */

BLOCK_API  int	C_API_FUNC get_block_tree(node **blktree);

/* get transaction data for getblocktemplate format */

BLOCK_API  int	C_API_FUNC get_tx_data(mem_zone_ref_ptr tx, mem_zone_ref_ptr txData);

/* find last pow block */

BLOCK_API  int	C_API_FUNC blk_find_last_pow_block(mem_zone_ref_ptr pindex, unsigned int *block_time);

/* check if node can accept block pow at current height */

BLOCK_API  int	C_API_FUNC block_pow(uint64_t height);

/* exctract public key from private key */

BLOCK_API  int	C_API_FUNC extract_key(dh_key_t priv, dh_key_t pub);

/*remove a transaction from the index */

BLOCK_API  int	C_API_FUNC remove_tx_index(hash_t tx_hash);





/*
*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=
script.c
*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=
*/






/* get public key / address from output script */

BLOCK_API int C_API_FUNC   get_out_script_address(const struct string *script, struct string *pubk, btc_addr_t addr);

/* get return value from script */

BLOCK_API int C_API_FUNC   get_out_script_return_val(const struct string *script, struct string *data);

/* get tx ouput script */

BLOCK_API int C_API_FUNC   get_tx_output_script(const hash_t tx_hash, unsigned int idx, struct string *script, uint64_t *amount);

/* public key get to hash */

BLOCK_API void C_API_FUNC   key_to_hash(unsigned char *pkey, unsigned char *keyHash);

/* public key  to addr */

BLOCK_API void C_API_FUNC  key_to_addr(unsigned char *pkey, btc_addr_t addr);

/* private address to private key */

BLOCK_API void C_API_FUNC   paddr_to_key(btc_paddr_t addr, dh_key_t key);

/* make script from file definition */

BLOCK_API int C_API_FUNC   make_script_file(mem_zone_ref_ptr file, struct string *pKey, struct string *sign, mem_zone_ref_ptr script);

/* make script from layout definition */

BLOCK_API int C_API_FUNC   make_script_layout(mem_zone_ref_ptr file, mem_zone_ref_ptr script);

/* make script from module definition */

BLOCK_API int C_API_FUNC   make_script_module(mem_zone_ref_ptr file, mem_zone_ref_ptr script);




/*
*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=
store.c
*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=
*/





/* load application root */

BLOCK_API int C_API_FUNC blk_load_app_root();

/* load applications definitions */

BLOCK_API int C_API_FUNC blk_load_apps(mem_zone_ref_ptr apps);


/* get total money supply */

BLOCK_API int C_API_FUNC  get_moneysupply(uint64_t *amount);

/* get block index size */

BLOCK_API int C_API_FUNC get_last_block_height();

/* find block hash from tx hash */

BLOCK_API int C_API_FUNC  find_blk_hash(const hash_t tx_hash, hash_t blk_hash,uint64_t *height,unsigned int *ofset,unsigned int *tx_time);

/* find block hash in local store */

BLOCK_API int C_API_FUNC  find_hash(hash_t hash);

/* find hash in block index */

BLOCK_API int C_API_FUNC  find_index_hash(hash_t h);

/* load block header from local store */

BLOCK_API int C_API_FUNC  load_blk_hdr(mem_zone_ref_ptr hdr, const char *blk_hash);

/* load block height from local store */

BLOCK_API int C_API_FUNC  get_blk_height(const char *blk_hash, uint64_t *height);

/* load block header infos from tx hash */

BLOCK_API int C_API_FUNC  get_tx_blk_height(const hash_t tx_hash, uint64_t *height, uint64_t *block_time, unsigned int *tx_time);

/* check if block is pow */

BLOCK_API int C_API_FUNC  is_pow_block(const char *blk_hash);

/* store block in local storage */

BLOCK_API int C_API_FUNC  store_block(mem_zone_ref_ptr header, mem_zone_ref_ptr tx_list);

/* load tx from a block based on the tx ofset */

BLOCK_API int C_API_FUNC  blk_load_tx_ofset(const char *blk_hash, unsigned int ofset, mem_zone_ref_ptr tx);

/* load tx from its hash */

BLOCK_API int C_API_FUNC  load_tx(mem_zone_ref_ptr tx, hash_t blk_hash, const hash_t tx_hash);

/* load tx input and parent tx */

BLOCK_API int C_API_FUNC  load_tx_input(mem_zone_ref_const_ptr tx, unsigned int idx, mem_zone_ref_ptr	vin, mem_zone_ref_ptr tx_out);

/* load input from block hash and tx hash + input id */

BLOCK_API int C_API_FUNC  load_blk_tx_input(const char *blk_hash, unsigned int tx_ofset, unsigned int vin_idx, mem_zone_ref_ptr vout);

/* get amount of tx output*/

BLOCK_API int C_API_FUNC  load_tx_output_amount(const hash_t tx_hash, unsigned int idx, uint64_t *amount);

/* load parent output from an input */

BLOCK_API int C_API_FUNC  load_tx_input_vout(mem_zone_ref_const_ptr tx, unsigned int vin_idx, mem_zone_ref_ptr vout);

/* load all tx hashes from an address */

BLOCK_API int C_API_FUNC  load_tx_addresses(btc_addr_t addr, mem_zone_ref_ptr tx_hashes);

/*load app object */
BLOCK_API int C_API_FUNC  load_obj(const char *app_name, const char *objHash, const char *objName, unsigned int opts, mem_zone_ref_ptr obj, btc_addr_t objAddr);

/*add child obj tx */

BLOCK_API int C_API_FUNC  make_app_child_obj_tx(mem_zone_ref_ptr tx, const char *app_name, hash_t objHash, const char *keyName, unsigned int ktype,hash_t childHash);

/* get obj hashes list */

BLOCK_API int C_API_FUNC  get_app_obj_hashes(const char *app_name, mem_zone_ref_ptr hash_list);

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

/*store tx inputs */

BLOCK_API int C_API_FUNC  store_tx_inputs(mem_zone_ref_ptr tx);

/*store tx outputs */

BLOCK_API int C_API_FUNC  store_tx_outputs(mem_zone_ref_ptr tx);

/*store tx hash into address index */

BLOCK_API int C_API_FUNC  store_tx_addresses(btc_addr_t addr, hash_t tx_hash);

/* remove tx from address index */

BLOCK_API int C_API_FUNC  remove_tx_addresses(const btc_addr_t addr, const hash_t tx_hash);

/* remove tx from storage*/

BLOCK_API int C_API_FUNC  remove_tx(hash_t tx_hash);

/* load block index from storage */

BLOCK_API  int	C_API_FUNC load_block_indexes(mem_zone_ref_ptr hdr_list);

/*store block hash/txid index */

BLOCK_API  int	C_API_FUNC store_tx_blk_index(const hash_t tx_hash, const hash_t blk_hash,uint64_t height,size_t tx_ofset,unsigned int time);

/*store block tx hashes */

BLOCK_API int  C_API_FUNC store_block_txs(mem_zone_ref_ptr header, mem_zone_ref_ptr tx_list);

/* clear all transaction indexes */

BLOCK_API  int	C_API_FUNC clear_tx_index();

/* load obj hash from type */

BLOCK_API  int	C_API_FUNC get_app_type_obj_hashes(const char *app_name, unsigned int type_id, size_t first, size_t max, mem_zone_ref_ptr hash_list);

/* load number of obj from type */

BLOCK_API  int	C_API_FUNC get_app_type_nobjs(const char *app_name, unsigned int type_id);

/* get application file definition */

BLOCK_API  int	C_API_FUNC get_app_file(mem_zone_ref_ptr file_tx, struct string *app_name, mem_zone_ref_ptr file);

/* get application file transaction */

BLOCK_API  int	C_API_FUNC get_appfile_tx(const char *app_name, hash_t fileHash, hash_t txHash);

/* check stored application file from hash */

BLOCK_API  int	C_API_FUNC has_app_file(struct string *app_name, hash_t fileHash);

/* check stored application files */

BLOCK_API  int	C_API_FUNC get_app_files(struct string *app_name, size_t first, size_t num, mem_zone_ref_ptr files);

/* check application missing files */

BLOCK_API  int	C_API_FUNC get_app_missing_files(struct string *app_name, mem_zone_ref_ptr pending, mem_zone_ref_ptr files);