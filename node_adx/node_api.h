#ifndef NODE_API
	#define NODE_API C_IMPORT 
#endif
//node module
NODE_API int			C_API_FUNC		node_init_self(mem_zone_ref_ptr self_node);
NODE_API int			C_API_FUNC		node_set_last_block(mem_zone_ref_ptr header);
NODE_API int			C_API_FUNC		node_find_last_pow_block(mem_zone_ref_ptr pindex, unsigned int *block_time);
NODE_API int			C_API_FUNC		node_load_last_blks();
NODE_API int			C_API_FUNC		node_log_addr_infos(mem_zone_ref_ptr addr);
NODE_API int			C_API_FUNC		update_peernodes();
NODE_API int			C_API_FUNC		node_add_block_index(hash_t hash, unsigned int time);
NODE_API int			C_API_FUNC		node_add_tx_to_mempool(mem_zone_ref_ptr tx);
NODE_API int			C_API_FUNC		node_fill_block_from_mempool(mem_zone_ref_ptr block);
NODE_API int			C_API_FUNC		node_del_txs_from_mempool(mem_zone_ref_ptr tx_list);
NODE_API int			C_API_FUNC		node_get_hash_idx(uint64_t block_idx, hash_t hash);
NODE_API int			C_API_FUNC		node_get_last_block_time(ctime_t *otime);
NODE_API int			C_API_FUNC		node_truncate_chain(uint64_t height);
NODE_API int			C_API_FUNC		node_remove_last_block();
NODE_API int			C_API_FUNC		node_rewrite_txs(uint64_t nums);
NODE_API int			C_API_FUNC		node_check_chain(mem_zone_ref_ptr node, mem_zone_ref_ptr hdr);
NODE_API int			C_API_FUNC		node_zip_self(struct string *out_data, mem_zone_ref_ptr opts);
NODE_API int			C_API_FUNC	    node_get_script_modules(mem_zone_ref_ptr modules);
NODE_API int			C_API_FUNC	    node_get_script_msg_handlers(mem_zone_ref_ptr handlers);
NODE_API int			C_API_FUNC		node_set_script(mem_zone_ref_ptr script);
NODE_API int			C_API_FUNC		remove_block(hash_t blk_hash);
NODE_API int			C_API_FUNC		node_list_accounts(mem_zone_ref_ptr account_list);
NODE_API int			C_API_FUNC		node_list_addrs(mem_zone_ref_ptr account_name, mem_zone_ref_ptr addr_list);
NODE_API int			C_API_FUNC		set_next_check(mem_zone_ref_ptr nSecs);
NODE_API int			C_API_FUNC		node_check_new_connections();

NODE_API int			C_API_FUNC		node_dump_memory(unsigned int flags);
NODE_API int			C_API_FUNC		node_init_service(mem_zone_ref_ptr service, mem_zone_ref_ptr pos_mod_def);
NODE_API int			C_API_FUNC		proccess_http_reqs(mem_zone_ref_ptr service);
NODE_API int			C_API_FUNC		get_file_mime(mem_zone_ref_ptr service, const char *filepath, struct string *mime);
NODE_API int			C_API_FUNC		check_http_request(mem_zone_ref_ptr service);
NODE_API int			C_API_FUNC		node_init_service(mem_zone_ref_ptr service, mem_zone_ref_ptr pos_mod_def);
NODE_API int			C_API_FUNC		node_process_event_handler(const char *msg_list_name, mem_zone_ref_ptr node, mem_zone_ref_ptr msg);

NODE_API int			C_API_FUNC		node_is_next_block(mem_zone_ref_const_ptr header);
NODE_API int			C_API_FUNC		connect_peer_node(mem_zone_ref_ptr node_def);
NODE_API int			C_API_FUNC		read_node_msg(mem_zone_ref_ptr node);
NODE_API int			C_API_FUNC		send_node_messages(mem_zone_ref_ptr node);
NODE_API int			C_API_FUNC		node_add_block_header(mem_zone_ref_ptr node, mem_zone_ref_ptr hdr);
NODE_API int			C_API_FUNC		queue_version_message(mem_zone_ref_ptr node);
NODE_API int			C_API_FUNC		queue_verack_message(mem_zone_ref_ptr node);
NODE_API int			C_API_FUNC		queue_ping_message(mem_zone_ref_ptr node);
NODE_API int			C_API_FUNC		queue_pong_message(mem_zone_ref_ptr node, mem_zone_ref_ptr nonce);
NODE_API int			C_API_FUNC		queue_getaddr_message(mem_zone_ref_ptr node);
NODE_API int			C_API_FUNC		queue_getdata_message(mem_zone_ref_ptr node, mem_zone_ref_ptr hash_list);
NODE_API int			C_API_FUNC		get_locator_next_blocks(mem_zone_ref_ptr locator, mem_zone_ref_ptr inv_pack);

NODE_API int			C_API_FUNC		queue_block_message(mem_zone_ref_ptr node, mem_zone_ref_ptr header, mem_zone_ref_ptr tx_list, struct string *signature);
NODE_API int			C_API_FUNC		queue_tx_message(mem_zone_ref_ptr node, mem_zone_ref_ptr tx);
NODE_API int			C_API_FUNC		queue_getblocks_message(mem_zone_ref_ptr node);
NODE_API int			C_API_FUNC		queue_getblock_hdrs_message(mem_zone_ref_ptr node);
NODE_API int			C_API_FUNC		queue_send_message(mem_zone_ref_ptr node, mem_zone_ref_ptr msg);
NODE_API int			C_API_FUNC		queue_emitted_element(mem_zone_ref_ptr node, mem_zone_ref_ptr element);
NODE_API int			C_API_FUNC		queue_emitted_message(mem_zone_ref_ptr node, mem_zone_ref_ptr msg);
NODE_API int			C_API_FUNC		queue_inv_message(mem_zone_ref_ptr node, mem_zone_ref_ptr hash_list);
NODE_API int			C_API_FUNC		node_check_services();
NODE_API int			C_API_FUNC		reset_moneysupply();
NODE_API int			C_API_FUNC		add_moneysupply(uint64_t amount);
NODE_API int			C_API_FUNC		sub_moneysupply(uint64_t amount);
NODE_API int			C_API_FUNC		node_has_block(mem_zone_ref_ptr hash);
NODE_API int			C_API_FUNC		node_mempool_has_tx(mem_zone_ref_ptr tx_hash);


