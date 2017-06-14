#ifndef WALLET_API
	#define WALLET_API C_IMPORT
#endif

WALLET_API int C_API_FUNC init_wallet(mem_zone_ref_ptr node, tpo_mod_file *pos_mod);
WALLET_API int C_API_FUNC find_stake_hash(hash_t hash, unsigned char *stakes, unsigned int len);
WALLET_API int C_API_FUNC get_tx_inputs_from_addr(btc_addr_t addr, uint64_t *total_unspent, uint64_t min_amount, size_t min_conf, size_t max_conf, mem_zone_ref_ptr tx);
WALLET_API int C_API_FUNC list_unspent(btc_addr_t addr, mem_zone_ref_ptr unspents, size_t min_conf, size_t max_conf, uint64_t *total_unspent, size_t *ntx, size_t *max);
WALLET_API int C_API_FUNC list_spent(btc_addr_t addr, mem_zone_ref_ptr spents, size_t min_conf, size_t max_conf, uint64_t *total_spent, size_t *ntx, size_t *max);
WALLET_API int C_API_FUNC get_balance(btc_addr_t addr, uint64_t *conf_amount, uint64_t *amount, unsigned int minconf);
WALLET_API int C_API_FUNC list_received(btc_addr_t addr, mem_zone_ref_ptr received, size_t min_conf, size_t max_conf, uint64_t *amount, size_t *ntx, size_t *max);
WALLET_API int C_API_FUNC remove_wallet_tx(const hash_t tx_hash);
WALLET_API int C_API_FUNC add_unspent(btc_addr_t	addr, const char *tx_hash, unsigned int oidx, uint64_t amount, btc_addr_t *src_addrs, unsigned int n_addrs);
WALLET_API int C_API_FUNC spend_tx_addr(btc_addr_t addr, const char *tx_hash, unsigned int vin, const char *ptx_hash, unsigned int oidx, btc_addr_t *addrs_to, unsigned int n_addrs_to);
WALLET_API int C_API_FUNC store_tx_wallet(btc_addr_t addr, hash_t tx_hash);
WALLET_API int C_API_FUNC store_wallet_tx(mem_zone_ref_ptr tx);
WALLET_API int C_API_FUNC store_wallet_txs(mem_zone_ref_ptr tx_list);
WALLET_API int C_API_FUNC list_staking_unspent(mem_zone_ref_ptr last_blk, btc_addr_t addr, mem_zone_ref_ptr unspents, unsigned int min_depth, int *max);