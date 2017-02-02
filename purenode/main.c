//copyright iadix 2016
#include <stdio.h>

#include <base/std_def.h>
#include <base/std_mem.h>
#include <base/mem_base.h>
#include <base/std_str.h>
#include <fsio.h>


#include <strs.h>
#include <tree.h>
#include <connect.h>
#include <sha256.h>
#include <crypto.h>
#include <http.h>
#include <upnp.h>
#include <mem_stream.h>
#include <tpo_mod.h>

mem_zone_ref		self_node  = { PTR_INVALID };
mem_zone_ref		peer_nodes = { PTR_INVALID };
hash_t				null_hash = { 0xCD };
unsigned int		synching = 0xABCDABCD;
mem_zone_ref		node_config = { PTR_INVALID };
struct string		user_agent = { PTR_INVALID };;
unsigned int		node_port = 0xABCDABCD, seed_port = 0xABCDABCD;
struct string		node_port_str = { PTR_INVALID };
struct string		node_hostname = { PTR_INVALID };
tpo_mod_file		node_mod = { 0xFF };
tpo_mod_file		pos_kernel = { 0xFF };
unsigned int		ping_nonce = 0x01;

C_EXPORT int _fltused = 0;
C_EXPORT mod_name_decoration_t	 mod_name_deco_type = MOD_NAME_DECO;


C_IMPORT int			C_API_FUNC compute_block_hash(mem_zone_ref_ptr block, hash_t hash);
C_IMPORT int			C_API_FUNC find_hash(hash_t hash);
C_IMPORT int			C_API_FUNC load_blk_hdr(mem_zone_ref_ptr hdr, const char *blk_hash);
C_IMPORT int			C_API_FUNC make_genesis_block(mem_zone_ref_ptr genesis_conf, mem_zone_ref_ptr genesis);
C_IMPORT int			C_API_FUNC get_last_block_height();
C_IMPORT int			C_API_FUNC remove_block(hash_t blk_hash);
C_IMPORT int			C_API_FUNC add_moneysupply(uint64_t amount);
C_IMPORT int			C_API_FUNC is_tx_null(mem_zone_ref_const_ptr tx);
C_IMPORT int			C_API_FUNC is_vout_null(mem_zone_ref_const_ptr tx, unsigned int idx);
C_IMPORT int			C_API_FUNC get_tx_output_amount(const hash_t tx_hash, unsigned int idx, uint64_t *amount);

C_IMPORT int			C_API_FUNC load_tx(mem_zone_ref_ptr tx, hash_t blk_hash, const hash_t tx_hash);
C_IMPORT int			C_API_FUNC load_blk_txs(const char* blk_hash, mem_zone_ref_ptr txs);
C_IMPORT int			C_API_FUNC	SetCompact(unsigned int bits, hash_t out);
C_IMPORT int			C_API_FUNC	is_pow_block(const char *blk_hash);
C_IMPORT unsigned int	C_API_FUNC	calc_new_target(unsigned int nActualSpacing, unsigned int TargetSpacing, unsigned int nTargetTimespan, unsigned int pBits);
C_IMPORT int			C_API_FUNC	check_block_pow(mem_zone_ref_ptr hdr, hash_t diff_hash);
C_IMPORT int			C_API_FUNC	get_out_script_address(struct string *script, struct string *pubk, btc_addr_t addr);
C_IMPORT int			C_API_FUNC	add_unspent(btc_addr_t	addr, const char *tx_hash, unsigned int oidx, uint64_t amount, btc_addr_t *src_addrs, unsigned int n_addrs);
C_IMPORT int			C_API_FUNC	spend_tx_addr(btc_addr_t addr, const char *tx_hash, unsigned int vin, const char *ptx_hash, unsigned int oidx, btc_addr_t *addrs_to, unsigned int n_addrs_to);
C_IMPORT int			C_API_FUNC	get_tx_output_addr(const hash_t tx_hash, unsigned int idx, btc_addr_t addr);
C_IMPORT int			C_API_FUNC	check_block_sign(const struct string *sign, const hash_t hash, const struct string *pubk);
C_IMPORT int			C_API_FUNC	 get_blk_sign(const char *blk_hash, struct string *sign);
C_IMPORT int			C_API_FUNC	 store_tx_index(const char * blk_hash, mem_zone_ref_ptr tx, hash_t thash);


//node module
typedef int				C_API_FUNC node_init_self_func(mem_zone_ref_ptr out_self_node, mem_zone_ref_ptr node_config);
typedef int				C_API_FUNC node_set_last_block_func(mem_zone_ref_ptr header);
typedef int				C_API_FUNC node_load_last_blks_func();
typedef int				C_API_FUNC node_find_last_pow_block_func(mem_zone_ref_ptr pindex, unsigned int *block_time);
typedef int				C_API_FUNC node_is_next_block_func(mem_zone_ref_const_ptr header, mem_zone_ref_ptr lastBlk);
typedef int				C_API_FUNC new_peer_node_func(struct host_def *host, mem_zone_ref_ptr peer_nodes);
typedef int				C_API_FUNC node_add_block_func(mem_zone_ref_ptr header, mem_zone_ref_ptr txs, uint64_t staking_reward);
typedef int				C_API_FUNC read_node_msg_func(mem_zone_ref_ptr node);
typedef int				C_API_FUNC send_node_messages_func(mem_zone_ref_ptr node);
typedef int				C_API_FUNC node_add_block_header_func(mem_zone_ref_ptr node, mem_zone_ref_ptr hdr);
typedef int				C_API_FUNC queue_version_message_func(mem_zone_ref_ptr node, struct string *user_agent);
typedef int				C_API_FUNC queue_verack_message_func(mem_zone_ref_ptr node);
typedef int				C_API_FUNC queue_ping_message_func(mem_zone_ref_ptr node, uint64_t nonce);
typedef int				C_API_FUNC queue_pong_message_func(mem_zone_ref_ptr node, uint64_t nonce);
typedef int				C_API_FUNC queue_getaddr_message_func(mem_zone_ref_ptr node);
typedef int				C_API_FUNC queue_getdata_message_func(mem_zone_ref_ptr node, mem_zone_ref_ptr hash_list);
typedef int				C_API_FUNC queue_block_message_func(mem_zone_ref_ptr node, mem_zone_ref_ptr header, mem_zone_ref_ptr tx_list, struct string *signature);
typedef int				C_API_FUNC queue_getblocks_message_func(mem_zone_ref_ptr node);
typedef int				C_API_FUNC queue_getblock_hdrs_message_func(mem_zone_ref_ptr node);
typedef int				C_API_FUNC queue_send_message_func(mem_zone_ref_ptr node, mem_zone_ref_ptr msg);
typedef int				C_API_FUNC queue_emitted_element_func(mem_zone_ref_ptr node, mem_zone_ref_ptr element);
typedef int				C_API_FUNC queue_emitted_message_func(mem_zone_ref_ptr node, mem_zone_ref_ptr msg);
typedef int				C_API_FUNC node_init_rpc_func(mem_zone_ref_ptr in_config,tpo_mod_file *pos);
typedef int				C_API_FUNC check_rpc_request_func();
typedef int				C_API_FUNC node_init_block_explorer_func(mem_zone_ref_ptr in_config, tpo_mod_file *pos_mod);
typedef int				C_API_FUNC node_add_block_index_func(hash_t hash, unsigned int time);
typedef int				C_API_FUNC queue_inv_message_func(mem_zone_ref_ptr node, mem_zone_ref_ptr hash_list);



typedef node_init_self_func					 *node_init_self_func_ptr;
typedef node_set_last_block_func			 *node_set_last_block_func_ptr;
typedef node_load_last_blks_func			 *node_load_last_blks_func_ptr;
typedef node_is_next_block_func				 *node_is_next_block_func_ptr;
typedef node_find_last_pow_block_func		 *node_find_last_pow_block_func_ptr;
typedef new_peer_node_func					 *new_peer_node_func_ptr;
typedef node_add_block_func					 *node_add_block_func_ptr;
typedef read_node_msg_func					 *read_node_msg_func_ptr;
typedef send_node_messages_func				 *send_node_messages_func_ptr;
typedef node_add_block_header_func			 *node_add_block_header_func_ptr;
typedef queue_version_message_func			 *queue_version_message_func_ptr;
typedef queue_verack_message_func			 *queue_verack_message_func_ptr;
typedef queue_ping_message_func				 *queue_ping_message_func_ptr;
typedef queue_pong_message_func				 *queue_pong_message_func_ptr;
typedef queue_getaddr_message_func			 *queue_getaddr_message_func_ptr;
typedef queue_getdata_message_func			 *queue_getdata_message_func_ptr;
typedef queue_block_message_func			 *queue_block_message_func_ptr;
typedef queue_getblocks_message_func		 *queue_getblocks_message_func_ptr;
typedef queue_getblock_hdrs_message_func	 *queue_getblock_hdrs_message_func_ptr;
typedef queue_send_message_func				 *queue_send_message_func_ptr;
typedef queue_emitted_element_func			 *queue_emitted_element_func_ptr;
typedef queue_emitted_message_func			 *queue_emitted_message_func_ptr;
typedef queue_inv_message_func				 *queue_inv_message_func_ptr;
typedef node_init_rpc_func					 *node_init_rpc_func_ptr;
typedef check_rpc_request_func				 *check_rpc_request_func_ptr;
typedef node_init_block_explorer_func		 *node_init_block_explorer_func_ptr;
typedef node_add_block_index_func			 *node_add_block_index_func_ptr;






//POS kernel module
typedef int				C_API_FUNC	init_pos_func(mem_zone_ref_ptr stake_conf);
typedef int				C_API_FUNC	store_blk_staking_func(mem_zone_ref_ptr header,mem_zone_ref_ptr tx_list);
typedef int				C_API_FUNC	store_tx_staking_func(mem_zone_ref_ptr tx, hash_t tx_hash, btc_addr_t stake_addr, uint64_t	stake_in);
typedef int				C_API_FUNC	compute_blk_staking_func(mem_zone_ref_ptr prev, mem_zone_ref_ptr prevPOS, mem_zone_ref_ptr hdr, mem_zone_ref_ptr tx_list, uint64_t *staking_reward);
typedef int				C_API_FUNC	compute_last_pos_diff_func(mem_zone_ref_ptr lastPOS, unsigned int *nBits);
typedef unsigned int	C_API_FUNC	get_current_pos_difficulty_func();
typedef int				C_API_FUNC	load_last_pos_blk_func(mem_zone_ref_ptr header);
typedef int				C_API_FUNC	store_last_pos_hash_func(hash_t hash);
typedef int				C_API_FUNC	find_last_pos_block_func(mem_zone_ref_ptr pindex, unsigned int *block_time);

typedef init_pos_func						*init_pos_func_ptr;
typedef store_blk_staking_func				*store_blk_staking_func_ptr;
typedef store_tx_staking_func				*store_tx_staking_func_ptr;
typedef compute_blk_staking_func			*compute_blk_staking_func_ptr;
typedef compute_last_pos_diff_func			*compute_last_pos_diff_func_ptr;
typedef get_current_pos_difficulty_func		*get_current_pos_difficulty_func_ptr;
typedef load_last_pos_blk_func				*load_last_pos_blk_func_ptr;
typedef store_last_pos_hash_func			*store_last_pos_hash_func_ptr;
typedef find_last_pos_block_func			*find_last_pos_block_func_ptr;

//#define _DEBUG
#ifdef _DEBUG
C_IMPORT int			C_API_FUNC		node_init_self(mem_zone_ref_ptr out_self_node, mem_zone_ref_ptr node_config);
C_IMPORT int			C_API_FUNC		node_set_last_block(mem_zone_ref_ptr header);
C_IMPORT int			C_API_FUNC		node_find_last_pow_block(mem_zone_ref_ptr pindex, unsigned int *block_time);
C_IMPORT int			C_API_FUNC		node_load_last_blks();
C_IMPORT int			C_API_FUNC		node_add_block_index(hash_t hash,unsigned int time);
C_IMPORT int			C_API_FUNC		node_is_next_block(mem_zone_ref_const_ptr header, mem_zone_ref_ptr lastBlk);
C_IMPORT int			C_API_FUNC		new_peer_node(struct host_def *host, mem_zone_ref_ptr peer_nodes);
C_IMPORT int			C_API_FUNC		node_add_block(mem_zone_ref_ptr header, mem_zone_ref_ptr txs, uint64_t staking_reward);
C_IMPORT int			C_API_FUNC		read_node_msg(mem_zone_ref_ptr node);
C_IMPORT int			C_API_FUNC		send_node_messages(mem_zone_ref_ptr node);
C_IMPORT int			C_API_FUNC		node_add_block_header(mem_zone_ref_ptr node, mem_zone_ref_ptr hdr);
C_IMPORT int			C_API_FUNC		queue_version_message(mem_zone_ref_ptr node, struct string *user_agent);
C_IMPORT int			C_API_FUNC		queue_verack_message(mem_zone_ref_ptr node);
C_IMPORT int			C_API_FUNC		queue_ping_message(mem_zone_ref_ptr node, uint64_t nonce);
C_IMPORT int			C_API_FUNC		queue_pong_message(mem_zone_ref_ptr node, uint64_t nonce);
C_IMPORT int			C_API_FUNC		queue_getaddr_message(mem_zone_ref_ptr node);
C_IMPORT int			C_API_FUNC		queue_getdata_message(mem_zone_ref_ptr node, mem_zone_ref_ptr hash_list);
C_IMPORT int			C_API_FUNC		queue_block_message(mem_zone_ref_ptr node, mem_zone_ref_ptr header, mem_zone_ref_ptr tx_list, struct string *signature);
C_IMPORT int			C_API_FUNC		queue_getblocks_message(mem_zone_ref_ptr node);
C_IMPORT int			C_API_FUNC		queue_getblock_hdrs_message(mem_zone_ref_ptr node);
C_IMPORT int			C_API_FUNC		queue_send_message(mem_zone_ref_ptr node, mem_zone_ref_ptr msg);
C_IMPORT int			C_API_FUNC		queue_emitted_element(mem_zone_ref_ptr node, mem_zone_ref_ptr element);
C_IMPORT int			C_API_FUNC		queue_emitted_message(mem_zone_ref_ptr node, mem_zone_ref_ptr msg);
C_IMPORT int			C_API_FUNC		queue_inv_message(mem_zone_ref_ptr node, mem_zone_ref_ptr hash_list);
C_IMPORT int			C_API_FUNC		node_init_rpc(mem_zone_ref_ptr in_config, tpo_mod_file *pos);
C_IMPORT int			C_API_FUNC		node_init_block_explorer(mem_zone_ref_ptr in_config, tpo_mod_file *pos_mod);
C_IMPORT int			C_API_FUNC		check_rpc_request();


C_IMPORT int			C_API_FUNC		init_pos(mem_zone_ref_ptr stake_conf);
C_IMPORT int			C_API_FUNC		store_blk_staking(mem_zone_ref_ptr header, mem_zone_ref_ptr tx_list);
C_IMPORT int			C_API_FUNC		compute_blk_staking(mem_zone_ref_ptr prev, mem_zone_ref_ptr prevPOS, mem_zone_ref_ptr hdr, mem_zone_ref_ptr tx_list, uint64_t *staking_reward);
C_IMPORT int			C_API_FUNC		compute_last_pos_diff(mem_zone_ref_ptr lastPOS, unsigned int *nBits);
C_IMPORT int			C_API_FUNC		store_tx_staking(mem_zone_ref_ptr tx, hash_t tx_hash, btc_addr_t stake_addr, uint64_t	stake_in);
C_IMPORT unsigned int	C_API_FUNC		get_current_pos_difficulty();
C_IMPORT int			C_API_FUNC		load_last_pos_blk(mem_zone_ref_ptr header);
C_IMPORT int			C_API_FUNC		store_last_pos_hash(hash_t hash);
C_IMPORT int			C_API_FUNC		find_last_pos_block(mem_zone_ref_ptr pindex, unsigned int *block_time);

node_init_self_func_ptr						_node_init_self=PTR_INVALID;
node_set_last_block_func_ptr				_node_set_last_block = PTR_INVALID;
node_load_last_blks_func_ptr				_node_load_last_blks = PTR_INVALID;
node_add_block_index_func_ptr				_node_add_block_index = PTR_INVALID;
node_load_last_blks_func_ptr				_node_find_last_pow_block = PTR_INVALID;
node_is_next_block_func_ptr					_node_is_next_block = PTR_INVALID;
new_peer_node_func_ptr						_new_peer_node=PTR_INVALID;
node_add_block_func_ptr						_node_add_block=PTR_INVALID;
read_node_msg_func_ptr						_read_node_msg=PTR_INVALID;
send_node_messages_func_ptr					_send_node_messages=PTR_INVALID;
node_add_block_header_func_ptr				_node_add_block_header=PTR_INVALID;
queue_version_message_func_ptr				_queue_version_message=PTR_INVALID;
queue_verack_message_func_ptr				_queue_verack_message=PTR_INVALID;
queue_ping_message_func_ptr					_queue_ping_message=PTR_INVALID;
queue_pong_message_func_ptr					_queue_pong_message=PTR_INVALID;
queue_getaddr_message_func_ptr				_queue_getaddr_message=PTR_INVALID;
queue_getdata_message_func_ptr				_queue_getdata_message=PTR_INVALID;
queue_block_message_func_ptr				_queue_block_message = PTR_INVALID;

queue_getblocks_message_func_ptr			_queue_getblocks_message=PTR_INVALID;
queue_getblock_hdrs_message_func_ptr		_queue_getblock_hdrs_message=PTR_INVALID;
queue_send_message_func_ptr					_queue_send_message=PTR_INVALID;
queue_emitted_element_func_ptr				_queue_emitted_element=PTR_INVALID;
queue_emitted_message_func_ptr				_queue_emitted_message=PTR_INVALID;
queue_inv_message_func_ptr					_queue_inv_message = PTR_INVALID;
node_init_rpc_func_ptr						_node_init_rpc = PTR_INVALID;
check_rpc_request_func_ptr					_check_rpc_request = PTR_INVALID;
node_init_block_explorer_func_ptr			_node_init_block_explorer = PTR_INVALID;



init_pos_func_ptr							_init_pos = PTR_INVALID;
store_blk_staking_func_ptr					_store_blk_staking = PTR_INVALID;
store_tx_staking_func_ptr					_store_tx_staking = PTR_INVALID;
compute_blk_staking_func_ptr				_compute_blk_staking = PTR_INVALID;
compute_last_pos_diff_func_ptr				_compute_last_pos_diff = PTR_INVALID;
get_current_pos_difficulty_func_ptr			_get_current_pos_difficulty= PTR_INVALID;
load_last_pos_blk_func_ptr					_load_last_pos_blk = PTR_INVALID;
store_last_pos_hash_func_ptr				_store_last_pos_hash = PTR_INVALID;
find_last_pos_block_func_ptr				_find_last_pos_block = PTR_INVALID;

#else
node_init_self_func_ptr						node_init_self = PTR_INVALID;
node_set_last_block_func_ptr				node_set_last_block = PTR_INVALID;
node_load_last_blks_func_ptr				node_load_last_blks = PTR_INVALID;
node_add_block_index_func_ptr				node_add_block_index = PTR_INVALID;
node_find_last_pow_block_func_ptr			node_find_last_pow_block = PTR_INVALID;
node_is_next_block_func_ptr					node_is_next_block = PTR_INVALID;
node_init_rpc_func_ptr						node_init_rpc = PTR_INVALID;
check_rpc_request_func_ptr					check_rpc_request = PTR_INVALID;
new_peer_node_func_ptr						new_peer_node = PTR_INVALID;
node_add_block_func_ptr						node_add_block = PTR_INVALID;
read_node_msg_func_ptr						read_node_msg = PTR_INVALID;
send_node_messages_func_ptr					send_node_messages = PTR_INVALID;
node_add_block_header_func_ptr				node_add_block_header = PTR_INVALID;
queue_version_message_func_ptr				queue_version_message = PTR_INVALID;
queue_verack_message_func_ptr				queue_verack_message = PTR_INVALID;
queue_ping_message_func_ptr					queue_ping_message = PTR_INVALID;
queue_pong_message_func_ptr					queue_pong_message = PTR_INVALID;
queue_getaddr_message_func_ptr				queue_getaddr_message = PTR_INVALID;
queue_getdata_message_func_ptr				queue_getdata_message = PTR_INVALID;
queue_block_message_func_ptr				queue_block_message = PTR_INVALID;
queue_getblocks_message_func_ptr			queue_getblocks_message = PTR_INVALID;
queue_inv_message_func_ptr					queue_inv_message = PTR_INVALID;
queue_getblock_hdrs_message_func_ptr		queue_getblock_hdrs_message = PTR_INVALID;
queue_send_message_func_ptr					queue_send_message = PTR_INVALID;
queue_emitted_element_func_ptr				queue_emitted_element = PTR_INVALID;
queue_emitted_message_func_ptr				queue_emitted_message = PTR_INVALID;

init_pos_func_ptr							init_pos= PTR_INVALID;
store_blk_staking_func_ptr					store_blk_staking= PTR_INVALID;
store_tx_staking_func_ptr					store_tx_staking = PTR_INVALID;
compute_blk_staking_func_ptr				compute_blk_staking= PTR_INVALID;
compute_last_pos_diff_func_ptr				compute_last_pos_diff = PTR_INVALID;
get_current_pos_difficulty_func_ptr			get_current_pos_difficulty = PTR_INVALID;
load_last_pos_blk_func_ptr					load_last_pos_blk = PTR_INVALID;
store_last_pos_hash_func_ptr				store_last_pos_hash = PTR_INVALID;
find_last_pos_block_func_ptr				find_last_pos_block = PTR_INVALID;
node_init_block_explorer_func_ptr			node_init_block_explorer;
#endif


int read_config(const char *file,struct string *port, struct string *node_hostname)
{
	unsigned char	*data;
	size_t			data_len;
	int				ret;

	mem_zone_ref	iresp = { PTR_NULL };
	if (get_file(file, &data, &data_len)<=0)return 0;
	if (data_len == 0)return 0;

	if (!tree_manager_json_loadb(data, data_len, &iresp))
		ret = 0;
	else
		ret = 1;

	free_c(data);

	if (ret)ret = tree_manager_get_child_value_istr(&iresp, NODE_HASH("site_host"), node_hostname, 10);
	if (ret)ret = tree_manager_get_child_value_istr(&iresp, NODE_HASH("p2p_port"), port, 10);

	release_zone_ref(&iresp);
	
	return ret;
}
/*
void dump_tx_list(mem_zone_ref_ptr tx_list)
{
	mem_zone_ref_ptr	tx = PTR_NULL;
	mem_zone_ref		header = { PTR_NULL };
	mem_zone_ref		my_list = { PTR_NULL };
	printf("txs\n-----\n");
	for (tree_manager_get_first_child(tx_list, &my_list, &tx); ((tx != NULL) && (tx->zone != NULL)); tree_manager_get_next_child(&my_list, &tx))
	{
		hash_t tx_hash;
		compute_tx_hash(tx, tx_hash);
		for (auto n = 0; n < 32; n++)
		{
			printf("%02x", tx_hash[31 - n]);
		}
		printf("\n");
	}
	printf("\n");

}
void dump_block_header(mem_zone_ref_ptr hdr)
{
	hash_t				blk_hash, blk_pow, diff_hash;
	unsigned int		version, time, bits, nonce;
	hash_t				prev_hash, merkle;
	int					n;
	tree_manager_get_child_value_i32(hdr, NODE_HASH("version"), &version);
	tree_manager_get_child_value_hash(hdr, NODE_HASH("prev"), prev_hash);
	tree_manager_get_child_value_hash(hdr, NODE_HASH("merkle_root"), merkle);
	tree_manager_get_child_value_i32(hdr, NODE_HASH("time"), &time);
	tree_manager_get_child_value_i32(hdr, NODE_HASH("bits"), &bits);
	tree_manager_get_child_value_i32(hdr, NODE_HASH("nonce"), &nonce);
	tree_manager_get_child_value_hash(hdr, NODE_HASH("blk hash"), blk_hash);
	tree_manager_get_child_value_hash(hdr, NODE_HASH("blk pow"), blk_pow);

	SetCompact(bits, diff_hash);

	printf("\n------------------\nblock header v%d , time %d , bits %x , nonce %u", version, time, bits, nonce);
	printf("\nprev hash\n");
	for (n = 0; n < 32; n++)
	{
		printf("%02x", prev_hash[31 - n]);
	}
	printf("\nmerkle\n");
	for (n = 0; n < 32; n++)
	{
		printf("%02x", merkle[31 - n]);
	}
	printf("\ndiff:%08x\n", bits);
	for (n = 0; n < 32; n++)
	{
		printf("%02x", diff_hash[n]);
	}
	printf("\nblock pow\n");
	for (n = 0; n < 32; n++)
	{
		printf("%02x", blk_pow[31 - n]);
	}
	printf("\nblock hash\n");
	for (n = 0; n < 32; n++)
	{
		printf("%02x", blk_hash[31 - n]);
	}
	printf("\n");
}
*/
/*
void reset_addr_scan()
{
	struct string	dir_list = { PTR_NULL };
	size_t			cur, nfiles;

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
			struct string adr_path = { PTR_NULL };
			mem_zone_ref	new_addr = { PTR_NULL };
			size_t			sz;

			ptr = memchr_c	(optr, 10, dir_list_len);
			sz = mem_sub	(optr, ptr);


			make_string(&adr_path, "adrs");
			cat_ncstring_p(&adr_path, optr, 34);
			cat_cstring_p(&adr_path, "scanning");
			del_file(adr_path.str);
			free_string(&adr_path);
			
			cur++;
			optr = ptr + 1;
			dir_list_len -= sz;
		}
	}
	free_string(&dir_list);

}
OS_API_C_FUNC(int) rescan_addr(btc_addr_t addr)
{
	char			chash[65];
	struct string	scan_path = { 0 }, adr_path = { 0 };
	unsigned int	n_blks, last_blk;
	unsigned char	*data;
	size_t			data_len;


	n_blks = 0;
	make_string(&adr_path, "adrs");
	cat_ncstring_p(&adr_path, addr, 34);

	clone_string(&scan_path, &adr_path);
	cat_cstring_p(&scan_path, "scanning");

	if (stat_file(scan_path.str) == 0)
	{
		free_string(&adr_path);
		free_string(&scan_path);
		return 0;
	}
	free_string(&scan_path);

	clone_string(&scan_path, &adr_path);
	cat_cstring_p(&scan_path, "scan");
	if (get_file(scan_path.str, &data, &data_len)>0)
	{
		if (data_len >= 4)
			n_blks = (*((unsigned int *)(data))) * 32;
		else
			del_file(scan_path.str);

		free_c(data);
	}
	else if (stat_file(adr_path.str) == 0)
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
		cat_cstring_p(&path, "stake");
		rm_dir(path.str);
		free_string(&path);

		clone_string(&path, &adr_path);
		cat_cstring_p(&path, "stakes");
		del_file(path.str);
		free_string(&path);
	}

	if (!get_file("./blk_indexes", &data, &data_len))
	{
		free_string(&scan_path);
		free_string(&adr_path);
		return 0;
	}

	clone_string (&scan_path, &adr_path);
	cat_cstring_p(&scan_path, "scanning");
	n_blks = 0;
	put_file	 (scan_path.str, &n_blks, 4);

	last_blk = 0;
	while (n_blks<data_len)
	{
		struct string blk_path = { 0 };
		int		n;
		unsigned char *tx_list;
		unsigned int  txs_len, ntx;

		n = 0;
		while (n<32)
		{
			chash[n * 2 + 0] = hex_chars[data[n_blks + n] >> 4];
			chash[n * 2 + 1] = hex_chars[data[n_blks + n] & 0x0F];
			n++;
		}
		chash[64] = 0;

		make_string(&blk_path, "blks");
		cat_ncstring_p(&blk_path, chash + 0, 2);
		cat_ncstring_p(&blk_path, chash + 2, 2);
		cat_cstring_p(&blk_path, chash);
		cat_cstring_p(&blk_path, "txs");
		if (get_file(blk_path.str, &tx_list, &txs_len) >0)
		{
			ntx = 0;
			while (ntx < txs_len)
			{
				store_tx_wallet(addr, &tx_list[ntx]);
				
				ntx += 32;
			}
			free_c(tx_list);
		}
		n_blks += 32;
		free_string(&blk_path);

		if ((n_blks - last_blk) >= 100 * 32)
		{
			unsigned int bl = n_blks / 32;
			put_file(scan_path.str, &bl, sizeof(unsigned int));
			last_blk = n_blks;
		}
	}
	free_c(data);
	del_file(scan_path.str);
	free_string(&scan_path);

	clone_string(&scan_path, &adr_path);
	cat_cstring_p(&scan_path, "scan");
	del_file(scan_path.str);
	free_string(&scan_path);

	free_string(&adr_path);

	return 1;
}
*/


OS_API_C_FUNC(int) rebuild_block_index()
{
	char			chash[65];
	struct string	adr_path = { 0 };
	unsigned int	n_blks, last_blk;
	unsigned char	*data;
	size_t			data_len;

	log_output("building block index ... \n");

	if (get_file("./blk_indexes", &data, &data_len)<=0)
		return 0;

	n_blks = 0;
	last_blk = 0;
	while (n_blks<data_len)
	{
		struct string	blk_path = { 0 };
		mem_zone_ref	log = { PTR_NULL };
		int				n;
		unsigned char	*tx_list;
		unsigned int	txs_len, ntx;

		if (last_blk > 100)
		{
			tree_manager_create_node("log", NODE_LOG_PARAMS, &log);
			tree_manager_set_child_value_i32(&log, "blk", n_blks / 32);
			tree_manager_set_child_value_i32(&log, "nblk", data_len / 32);
			log_message("processing block %blk% / %nblk% \n", &log);
			release_zone_ref(&log);
			last_blk = 0;
		}

		n = 0;
		while (n<32)
		{
			chash[n * 2 + 0] = hex_chars[data[n_blks + n] >> 4];
			chash[n * 2 + 1] = hex_chars[data[n_blks + n] & 0x0F];
			n++;
		}
		chash[64] = 0;

		make_string(&blk_path, "blks");
		cat_ncstring_p(&blk_path, chash + 0, 2);
		cat_ncstring_p(&blk_path, chash + 2, 2);
		cat_cstring_p(&blk_path, chash);
		cat_cstring_p(&blk_path, "txs");
		if (get_file(blk_path.str, &tx_list, &txs_len) >0)
		{
			ntx = 0;
			while (ntx < txs_len)
			{
				hash_t b;
				mem_zone_ref tx = { PTR_NULL };

				if (!load_tx(&tx, b, &tx_list[ntx]))continue;
				store_tx_index(chash, &tx, &tx_list[ntx]);
				release_zone_ref(&tx);
				ntx += 32;
			}
			free_c(tx_list);
		}
		n_blks += 32;
		last_blk++;
		free_string(&blk_path);
	}
	free_c(data);
	free_string(&adr_path);

	return 1;
}

int handle_version(mem_zone_ref_ptr node, mem_zone_ref_ptr payload)
{
	char		 user_agent[32];
	mem_zone_ref log = { PTR_NULL }, block_index_node = { PTR_NULL };
	unsigned int proto_ver, last_blk, node_port,my_port;
	mem_zone_ref addrs[2] = { PTR_NULL };
	uint64_t	 time, services, timestamp;
	int			 index = 0;
	ipv4_t		 node_ip,my_ip;
	uint64_t		nblks;
	tree_manager_get_child_value_i32(payload, NODE_HASH("proto_ver"), &proto_ver);
	tree_manager_get_child_value_i64(payload, NODE_HASH("timestamp"), &time);
	tree_manager_get_child_value_i64(payload, NODE_HASH("services"), &services);
	tree_manager_get_child_value_i64(payload, NODE_HASH("timestamp"), &timestamp);
	tree_manager_get_child_value_str(payload, NODE_HASH("user_agent"),user_agent, 32, 16);
	tree_manager_get_child_value_i32(payload, NODE_HASH("last_blk"), &last_blk);

	index = 1;
	tree_node_list_child_by_type	(payload, NODE_BITCORE_ADDR, &addrs[0], 0);
	tree_node_list_child_by_type	(payload, NODE_BITCORE_ADDR, &addrs[1], 1);

	tree_manager_get_child_value_ipv4(&addrs[0], NODE_HASH("addr"), my_ip);
	tree_manager_get_child_value_i32(&addrs[0], NODE_HASH("port"), &my_port);
	
	tree_manager_get_child_value_ipv4(&addrs[1], NODE_HASH("addr"), node_ip);
	tree_manager_get_child_value_i32 (&addrs[1], NODE_HASH("port"), &node_port);


	tree_manager_create_node("log", NODE_LOG_PARAMS, &log);
	tree_manager_set_child_value_ipv4(&log, "nip", node_ip);
	tree_manager_set_child_value_i32(&log, "nport", node_port);
	tree_manager_set_child_value_ipv4(&log, "ip", my_ip);
	tree_manager_set_child_value_i32(&log, "port", my_port);
	tree_manager_set_child_value_str(&log, "services", services ? "network" : "no services");
	tree_manager_set_child_value_i32(&log, "version", proto_ver);
	tree_manager_set_child_value_str(&log, "user_agent", user_agent);
	tree_manager_set_child_value_i32(&log, "lastblk", last_blk);
	log_message("node %nip%:%nport% version %version% %services% last block: %lastblk%, me %ip%:%port% \n", &log);
	release_zone_ref(&log);




	//printf("node %u.%u.%u.%u:%d (%s) version %d '%s' last block : %d, me %u.%u.%u.%u:%d \n", node_ip[0], node_ip[1], node_ip[2], node_ip[3], node_port, services ? "network" : "no services", proto_ver, user_agent, last_blk, my_ip[0], my_ip[1], my_ip[2], my_ip[3], my_port);

	release_zone_ref(&addrs[0]);
	release_zone_ref(&addrs[1]);
	
	queue_verack_message	(node);
	queue_getaddr_message	(node);

	if (!tree_manager_get_child_value_i64(&self_node, NODE_HASH("block height"), &nblks))
		nblks = 0;
	if (nblks > (last_blk + 1))
	{
		mem_zone_ref hash_list = { PTR_NULL };
		if (tree_manager_create_node("hashes", NODE_BITCORE_HASH_LIST, &hash_list))
		{
			int num = 1000;
			while (last_blk < nblks)
			{
				if ((num--) == 0)break;
				if (tree_manager_find_child_node(&self_node, NODE_HASH("block index"), NODE_BITCORE_HASH, &block_index_node))
				{
					hash_t hash;
					if (tree_manager_get_node_hash(&block_index_node, last_blk*sizeof(hash_t), hash))
					{
						mem_zone_ref new_hash = { PTR_NULL };
						if (tree_manager_add_child_node(&hash_list, "hash", NODE_BITCORE_BLOCK_HASH, &new_hash))
						{
							tree_manager_write_node_hash(&new_hash, 0, hash);
							release_zone_ref(&new_hash);
						}
					}
					release_zone_ref(&block_index_node);
				}
				last_blk++;
			}
			queue_inv_message(node, &hash_list);
			release_zone_ref(&hash_list);
		}
	}

	return 1;
}
int handle_ping(mem_zone_ref_ptr node, mem_zone_ref_ptr payload)
{
	uint64_t	nonce;
	tree_manager_get_child_value_i64(payload, NODE_HASH("nonce"), &nonce);
	queue_pong_message				(node, nonce);
	return 1;
}

int handle_pong(mem_zone_ref_ptr node, mem_zone_ref_ptr payload)
{
	synching = 1;
	return 1;
}

int handle_verack(mem_zone_ref_ptr node, mem_zone_ref_ptr payload)
{
	queue_ping_message(node,ping_nonce++);
	return 1;
}

int handle_addr(mem_zone_ref_ptr node, mem_zone_ref_ptr payload)
{
	mem_zone_ref		log			= { PTR_NULL };
	mem_zone_ref		addr_list	= { PTR_NULL };
	mem_zone_ref		my_list		= { PTR_NULL };
	mem_zone_ref_ptr	addr;

	tree_manager_find_child_node(payload, NODE_HASH("addrs"), NODE_BITCORE_ADDR_LIST, &addr_list);
	for (tree_manager_get_first_child(&addr_list, &my_list, &addr); ((addr != NULL) && (addr->zone != NULL)); tree_manager_get_next_child(&my_list, &addr))
	{
		unsigned int	time;
		uint64_t		services;
		ipv4_t			ip;
		unsigned short	port;

		tree_manager_get_child_value_i32	(addr, NODE_HASH("time")	, &time);
		tree_manager_get_child_value_i64	(addr, NODE_HASH("services"), &services);

		tree_manager_get_child_value_ipv4	(addr, NODE_HASH("addr")	, ip);
		tree_manager_get_child_value_i16	(addr, NODE_HASH("port")	, &port);

		tree_manager_create_node("log", NODE_LOG_PARAMS, &log);
		tree_manager_set_child_value_ipv4(&log, "ip", ip);
		tree_manager_set_child_value_i32(&log, "port", port);
		tree_manager_set_child_value_str(&log, "services", services ? "network" : "no services");
		tree_manager_set_child_value_i32(&log, "time", time);
		log_message("new address %ip%:%port% %time% %services%\n", &log);
		release_zone_ref(&log);
	}
	release_zone_ref(&addr_list);
	return 1;
}

int handle_headers(mem_zone_ref_ptr node, mem_zone_ref_ptr payload)
{
	/*
	mem_zone_ref hash_list = { PTR_NULL }, hdr_list = { PTR_NULL };
	
	tree_manager_find_child_node(node, NODE_HASH("block headers"), NODE_BITCORE_BLK_HDR_LIST, &hdr_list);

	get_hash_list			(&hdr_list, &hash_list);
	release_zone_ref		(&hdr_list);

	queue_getdata_message	(node, &hash_list);
	release_zone_ref		(&hash_list);
	*/
	return 1;
}

int handle_inv(mem_zone_ref_ptr node, mem_zone_ref_ptr payload)
{
	mem_zone_ref hash_list = { PTR_NULL };

	//tree_manager_set_child_value_i64(node, "next_check", get_time_c() + 20);

	tree_manager_find_child_node(payload, NODE_HASH("hashes"), NODE_BITCORE_HASH_LIST, &hash_list);
	queue_getdata_message(node, &hash_list);
	release_zone_ref(&hash_list);


	return 1;
}	

int get_last_pow_diff(mem_zone_ref_ptr lastPOW,unsigned int	*pBits, int64_t *spacing)
{
	char				cpphash[65];
	hash_t				null_hash;
	mem_zone_ref		pprev = { PTR_NULL };
	unsigned int		prevTime, pprevTime;
	int					ret;
	//get last two pos blocks
	memset_c(null_hash, 0, sizeof(hash_t));
	tree_manager_get_child_value_i32(lastPOW, NODE_HASH("bits"), pBits);
	tree_manager_get_child_value_i32(lastPOW, NODE_HASH("time"), &prevTime);
	tree_manager_get_child_value_str(lastPOW, NODE_HASH("prev"), cpphash, 65, 16);
	ret = load_blk_hdr(&pprev, cpphash);
	if (ret)
	{
		hash_t pppp;
		tree_manager_get_child_value_hash(&pprev, NODE_HASH("prev"), pppp);

		if (!memcmp_c(pppp, null_hash, sizeof(hash_t)))
			ret = 0;

		if (ret)
			ret  =node_find_last_pow_block(&pprev, &pprevTime);

		if (ret)
			*spacing = prevTime - pprevTime;

		release_zone_ref(&pprev);
	}

	return ret;
}

int compute_last_pow_diff(mem_zone_ref_ptr lastPOWBlk,unsigned int *nBits)
{
	hash_t				out_diff, Difflimit;
	int64_t				nActualSpacing;
	unsigned int		pBits; 



	if (get_last_pow_diff(lastPOWBlk, &pBits, &nActualSpacing))
	{
		unsigned int		TargetSpacing;
		unsigned int		nTargetTimespan;
		unsigned int		Di;

		memset_c(out_diff, 0, sizeof(hash_t));

		if (!tree_manager_get_child_value_i32(&self_node, NODE_HASH("target spacing"), &TargetSpacing))return 0;
		if (!tree_manager_get_child_value_i32(&self_node, NODE_HASH("target timespan"), &nTargetTimespan))return 0;
		if (!tree_manager_get_child_value_i32(&self_node, NODE_HASH("limit"), &Di))return 0;


		if (nActualSpacing > TargetSpacing * 10)
			nActualSpacing = TargetSpacing * 10;

		*nBits = calc_new_target(nActualSpacing, TargetSpacing, nTargetTimespan, pBits);
		SetCompact(*nBits, out_diff);
		SetCompact(Di, Difflimit);

		if (memcmp_c(out_diff, Difflimit, sizeof(hash_t)) > 0)
			*nBits = Di;
		return 1;
	}
	return 0;
}

OS_API_C_FUNC(uint64_t) get_blockreward(uint64_t block)
{
	uint64_t block_reward;
	tree_manager_get_child_value_i64(&self_node, NODE_HASH("block reward"), &block_reward);
	return block_reward;
}

void remove_last_block()
{
	hash_t hash;
	mem_zone_ref block_index_node = { PTR_NULL };
	unsigned int block_idx;


	block_idx = get_last_block_height()-1;
	if (tree_manager_find_child_node(&self_node, NODE_HASH("block index"), NODE_BITCORE_HASH, &block_index_node))
	{
		tree_manager_get_node_hash(&block_index_node, (block_idx) * 32, hash);
		release_zone_ref(&block_index_node);
	}
	remove_block (hash);
	
	tree_manager_set_child_value_i64(&self_node, "block height", block_idx);
	truncate_file					("blk_indexes"	, (block_idx+1)* 32, PTR_NULL, 0);
	truncate_file					("blk_times"	, (block_idx+1)* 4, PTR_NULL, 0);
}

int accept_block(mem_zone_ref_ptr header, mem_zone_ref_ptr tx_list, struct string *signature)
{
	hash_t				blk_hash;
	mem_zone_ref		log = { PTR_NULL };
	struct string		sign = { PTR_NULL };
	uint64_t			block_reward = 0, staking_reward = 0, nblks;
	int					ret = 1, is_staking;
	mem_zone_ref		lastPOSBlk = { PTR_NULL }, lastPOWBlk = { PTR_NULL }, lastBlk = { PTR_NULL };

	if (!node_is_next_block(header, &lastBlk))
		return 0;

	tree_manager_get_child_value_i64(&self_node, NODE_HASH("block height"), &nblks);
	compute_block_hash(header, blk_hash);
	tree_manager_set_child_value_bhash(header, "blk hash", blk_hash);

	if (strlen_c(pos_kernel.name) > 0)
	{
		mem_zone_ref sig = { PTR_NULL };
		tree_manager_find_child_node		(&self_node, NODE_HASH("last pos block"), NODE_BITCORE_BLK_HDR, &lastPOSBlk);

		if (!tree_manager_find_child_node(header, NODE_HASH("signature"), NODE_BITCORE_ECDSA_SIG, &sig))
			tree_manager_add_child_node			(header, "signature", NODE_BITCORE_ECDSA_SIG, &sig);

		tree_manager_write_node_sig			(&sig, 0, signature->str, signature->len);
		release_zone_ref					(&sig);

		ret = compute_blk_staking			(&lastBlk, &lastPOSBlk, header, tx_list, &block_reward);
		release_zone_ref					(&lastPOSBlk);
	}
	tree_manager_find_child_node(&self_node, NODE_HASH("last pos block"), NODE_BITCORE_BLK_HDR, &lastPOSBlk);

	if (find_hash(blk_hash))
		remove_block(blk_hash);

	if (ret)
	{
		hash_t				out_diff;
		unsigned int		powbits;
		if (block_reward == 0)
		{
			if (!tree_manager_get_child_value_i32(&self_node, NODE_HASH("current pow diff"), &powbits))
				tree_manager_get_child_value_i32(header, NODE_HASH("bits"), &powbits);

			SetCompact(powbits, out_diff);
			ret = check_block_pow(header, out_diff);
			if (ret)
				block_reward = get_blockreward(nblks);

			is_staking = 0;
		}
		else
		{
			is_staking = 1;
		}
	}

	if (ret)
	{
		log_output("adding new block\n");
		ret = node_add_block(header, tx_list, block_reward);
	}

	if (ret)
	{
		unsigned int blocktime = 0;

		log_output("new block added\n");

		if (strlen_c(pos_kernel.name) > 0)
			store_blk_staking(header, tx_list);

		tree_manager_get_child_value_i32(header, NODE_HASH("time"), &blocktime);

		if (is_staking)
		{
			mem_zone_ref last_blk = { PTR_NULL };
			unsigned int pBits;

			store_last_pos_hash(blk_hash);

			if (!tree_manager_find_child_node(&self_node, NODE_HASH("last pos block"), NODE_BITCORE_BLK_HDR, &last_blk))
				tree_manager_add_child_node(&self_node, "last pos block", NODE_BITCORE_BLK_HDR, &last_blk);

			tree_manager_copy_children_ref(&last_blk, header);
			release_zone_ref(&last_blk);

			if (compute_last_pos_diff(header, &pBits))
				tree_manager_set_child_value_i32(&self_node, "current pos diff", pBits);
			else
				tree_manager_set_child_value_i32(&self_node, "current pos diff", 0x1FFFFFFF);
		}
		else
		{
			unsigned int powbits;

			if (compute_last_pow_diff(header, &powbits))
				tree_manager_set_child_value_i32(&self_node, "current pow diff", powbits);
			else
			{
				tree_manager_get_child_value_i32(header, NODE_HASH("bits"), &powbits);
				tree_manager_set_child_value_i32(&self_node, "current pow diff", powbits);
			}

		}
		node_add_block_index(blk_hash, blocktime);
		add_moneysupply(block_reward);
	}
	release_zone_ref(&lastBlk);
	return ret;
}
int handle_getdata(mem_zone_ref_ptr node, mem_zone_ref_ptr payload)
{
	mem_zone_ref hash_list = { PTR_NULL }, my_list = { PTR_NULL };
	mem_zone_ref_ptr hash_node;
	unsigned int data_type = 0;
	if (!tree_manager_find_child_node(payload, NODE_HASH("hashes"), NODE_BITCORE_HASH_LIST, &hash_list))return 0;
	for (tree_manager_get_first_child(&hash_list, &my_list, &hash_node); ((hash_node != NULL) && (hash_node->zone != NULL)); tree_manager_get_next_child(&my_list, &hash_node))
	{
		char chash[65];
		hash_t hash;
		mem_zone_ref block = { PTR_NULL }, txs = { PTR_NULL };
		unsigned char *hash_data;
		hash_data = tree_mamanger_get_node_data_ptr(hash_node, 0);
		if (tree_mamanger_get_node_type(hash_node) == NODE_BITCORE_BLOCK_HASH)
		{
			int n = 32;
			while (n--)hash[n] = hash_data[31 - n];
			n = 0;
			while (n<32)
			{
				chash[n * 2 + 0] = hex_chars[hash_data[n] >> 4];
				chash[n * 2 + 1] = hex_chars[hash_data[n] & 0x0F];
				n++;
			}
			chash[64] = 0;
		}
	
		if (load_blk_hdr(&block, chash))
		{
			if (tree_manager_create_node("txs", NODE_BITCORE_TX_LIST, &txs))
			{
				struct string sign = { 0 };
				get_blk_sign(chash, &sign);

				if (load_blk_txs(chash, &txs))
					queue_block_message	(node, &block, &txs,&sign);

				free_string(&sign);

				release_zone_ref(&txs);
			}
			release_zone_ref(&block);
		}
	}
	release_zone_ref(&hash_list);
	return 1;

}

int handle_block(mem_zone_ref_ptr node, mem_zone_ref_ptr payload)
{
	mem_zone_ref		header = { PTR_NULL }, tx_list = { PTR_NULL }, sig = { PTR_NULL };
	mem_zone_ref		log = { PTR_NULL };
	size_t				nz1 = 0, nz2 = 0;
	struct string		 signature = { PTR_NULL };
	int					ret = 1;
	uint64_t			nblks;
	
	if (!tree_manager_find_child_node(payload, NODE_HASH("header"), NODE_BITCORE_BLK_HDR, &header))return 0;
	if (!tree_manager_find_child_node(payload, NODE_HASH("txs"), NODE_BITCORE_TX_LIST, &tx_list)){ release_zone_ref(&header); return 0; }
	if (!tree_manager_find_child_node(payload, NODE_HASH("signature"), NODE_BITCORE_ECDSA_SIG, &sig)){ release_zone_ref(&tx_list); release_zone_ref(&header); return 0; }

	tree_manager_get_node_istr	(&sig, 0, &signature,0);
	release_zone_ref			(&sig);

	ret = accept_block			(&header, &tx_list, &signature);
	

	if (ret)
		log_message("accepted block: %blk hash% , %time% - %version% %merkle_root%\n", &header);
	else
		log_message("rejected block: %blk hash% , %time% - %version% %merkle_root%\n", &header);

	tree_manager_set_child_value_i64(node, "next_check", get_time_c() + 10);
	
	tree_manager_get_child_value_i64(&self_node, NODE_HASH("block height"), &nblks);
	tree_manager_create_node("log", NODE_LOG_PARAMS, &log);
	tree_manager_set_child_value_i32(&log, "nblocks", nblks);
#ifdef _DEBUG
	nz1 = find_zones_used(2);
	nz2 = find_zones_used(1);
	tree_manager_set_child_value_i32(&log, "zones1", nz1);
	tree_manager_set_child_value_i32(&log, "zones2", nz2);
	log_message("block height : %nblocks% , %zones1% - %zones2%\n", &log);
#else
	log_message("block height : %nblocks%\n", &log);
#endif
	release_zone_ref(&log);
	free_string(&signature);
	release_zone_ref(&header);
	release_zone_ref(&tx_list);
	
	return ret;
}

int handle_message(mem_zone_ref_ptr node,const char *cmd,mem_zone_ref_ptr payload)
{
	if (!strncmp_c(cmd, "verack", 6)){ return handle_verack(node,payload); }
	if (!strncmp_c(cmd, "version", 7))return handle_version(node, payload);
	if (!strncmp_c(cmd, "ping", 4))return handle_ping(node, payload);
	if (!strncmp_c(cmd, "pong", 4))return handle_pong(node, payload);
	if (!strncmp_c(cmd, "addr", 4))return handle_addr(node, payload);
	if (!strncmp_c(cmd, "headers", 7))return handle_headers(node, payload);
	if (!strncmp_c(cmd, "inv", 3))return handle_inv(node, payload);
	if (!strncmp_c(cmd, "block", 5))return handle_block(node, payload);
	if (!strncmp_c(cmd, "getdata", 7))return handle_getdata(node, payload);
	



	return 0;
}


int handle_element(mem_zone_ref_ptr node, mem_zone_ref_ptr element)
{
	

	switch (tree_mamanger_get_node_type(element))
	{
		case NODE_BITCORE_ADDRT:
		{
			unsigned int	time;
			uint64_t		services;
			ipv4_t			ip;
			unsigned short	port;
			mem_zone_ref	log = { PTR_NULL };

			tree_manager_get_child_value_i32(element, NODE_HASH("time"), &time);
			tree_manager_get_child_value_i64(element, NODE_HASH("services"), &services);

			tree_manager_get_child_value_ipv4(element, NODE_HASH("addr"), ip);
			tree_manager_get_child_value_i16(element, NODE_HASH("port"), &port);


			tree_manager_create_node("log", NODE_LOG_PARAMS, &log);
			tree_manager_set_child_value_ipv4(&log, "ip", ip);
			tree_manager_set_child_value_i32(&log, "port", port);
			tree_manager_set_child_value_str(&log, "services", services ? "network" : "no services");
			tree_manager_set_child_value_i32(&log, "time", time);
			log_message("new address %ip%:%port% %time% %services%\n", &log);
			release_zone_ref(&log);
			return 1;
		}
		break;
		case NODE_BITCORE_BLK_HDR:
		{


			node_add_block_header(node, element);
			return 1;
		}
		break;
	}


	return 0;
}

OS_API_C_FUNC(int) scan_addresses()
{
	mem_zone_ref scan_list = { PTR_NULL };

	if (tree_manager_find_child_node(&self_node, NODE_HASH("addr scan list"), NODE_BITCORE_WALLET_ADDR_LIST, &scan_list))
	{
		mem_zone_ref_ptr	addr = PTR_NULL;
		mem_zone_ref		my_list = { PTR_NULL };
		for (tree_manager_get_first_child(&scan_list, &my_list, &addr); ((addr != NULL) && (addr->zone != NULL)); tree_manager_get_next_child(&my_list, &addr))
		{

			mem_zone_ref new_addr = { PTR_NULL };
			if (tree_manager_find_child_node(addr, NODE_HASH("addr"), NODE_BITCORE_WALLET_ADDR, &new_addr))
			{
				//background_func(scanaddr_func, &new_addr);
				release_zone_ref(&new_addr);
			}
			tree_manager_set_child_value_i32(addr, "done", 1);
		}
		tree_remove_child_by_member_value_dword(&scan_list, NODE_BITCORE_WALLET_ADDR, "done", 1);
		release_zone_ref(&scan_list);
	}

	return 1;
}

int process_node_messages(mem_zone_ref_ptr node)
{
	mem_zone_ref		msg_list = { PTR_NULL };
	mem_zone_ref_ptr	msg = PTR_NULL;
	mem_zone_ref		my_list = { PTR_NULL };
	unsigned int		nc;


	if (!tree_manager_find_child_node(node, NODE_HASH("emitted queue"), NODE_BITCORE_MSG_LIST, &msg_list))return 0;


	for (tree_manager_get_first_child(&msg_list, &my_list, &msg); ((msg != NULL) && (msg->zone != NULL)); tree_manager_get_next_child(&my_list, &msg))
	{
		char			cmd[16];
		mem_zone_ref	payload_node = { PTR_NULL };
		int				ret;

		if (!tree_manager_get_child_value_str(msg, NODE_HASH("cmd"), cmd, 12, 16))continue;

		tree_manager_find_child_node(msg, NODE_HASH("payload"), NODE_BITCORE_PAYLOAD, &payload_node);

		ret = handle_message(node, cmd, &payload_node);
		tree_manager_set_child_value_i32(msg, "handled", ret);
		release_zone_ref(&payload_node);
	}
	
	//tree_remove_child_by_member_value_dword(&msg_list, NODE_BITCORE_MSG, "handled", 1);
	tree_remove_children(&msg_list);
	nc = tree_manager_get_node_num_children(&msg_list);
	release_zone_ref(&msg_list);
	return 1;
}

int process_node_elements(mem_zone_ref_ptr node)
{
	mem_zone_ref		list = { PTR_NULL };
	mem_zone_ref_ptr	el = PTR_NULL;
	mem_zone_ref		my_list = { PTR_NULL };
	int					ret;

	if (!tree_manager_find_child_node(node, NODE_HASH("emitted elements"), NODE_BITCORE_MSG_LIST, &list))return 0;

	for (tree_manager_get_first_child(&list, &my_list, &el); ((el != NULL) && (el->zone != NULL)); tree_manager_get_next_child(&my_list, &el))
	{
		ret=handle_element				(node, el);
		tree_manager_set_child_value_i32(el, "handled", ret);
	}
	tree_remove_child_by_member_value_dword(&list, 0, "handled", 1);
	release_zone_ref(&list);
	return 1;
}

int update_nodes()
{
	mem_zone_ref_ptr	node	=   PTR_NULL;
	mem_zone_ref		my_list = { PTR_NULL };
	
	for (tree_manager_get_first_child(&peer_nodes, &my_list, &node); ((node != PTR_NULL) && (node->zone != PTR_NULL)); tree_manager_get_next_child(&my_list, &node))
	{
		send_node_messages	(node);
		read_node_msg		(node);
		check_rpc_request	();
	}
	return 1;
}



int process_nodes()
{
	mem_zone_ref_ptr	node = PTR_NULL;
	mem_zone_ref		my_list = { PTR_NULL };

	for (tree_manager_get_first_child(&peer_nodes, &my_list, &node); ((node != NULL) && (node->zone != NULL)); tree_manager_get_next_child(&my_list, &node))
	{
		ctime_t next_check;
		ctime_t		 curtime;
		process_node_messages(node);
		process_node_elements(node);

		scan_addresses();

		if (synching == 1)
		{
			curtime = get_time_c();
			if (tree_manager_get_child_value_i64(node, NODE_HASH("next_check"), &next_check))
			{
				if (curtime >= next_check)
				{
					queue_getblocks_message(node);
					tree_manager_set_child_value_i32(node, "next_check", curtime + 5);
				}
			}
		}
	}
	return 1;
}



int load_pos_module(const char *staking_kernel,tpo_mod_file *tpomod)
{
	char str[64];
	
	strcpy_c (str, "modz/");
	strcat_cs(str, 64, staking_kernel);
	strcat_cs(str, 64, ".tpo");

	log_output("loading pos module ");
	log_output(str);
	log_output("\n");

	if (!load_module(str, staking_kernel, tpomod))return 0;

	log_output("loaded\n");


#ifndef _DEBUG
	init_pos					= (init_pos_func_ptr)get_tpo_mod_exp_addr_name(tpomod, "init_pos", 0);
	store_blk_staking			= (store_blk_staking_func_ptr)get_tpo_mod_exp_addr_name(tpomod, "store_blk_staking", 0);
	compute_last_pos_diff		= (compute_last_pos_diff_func_ptr)get_tpo_mod_exp_addr_name(tpomod, "compute_last_pos_diff", 0);
	store_tx_staking			= (store_tx_staking_func_ptr)get_tpo_mod_exp_addr_name(tpomod, "store_tx_staking", 0);
	compute_blk_staking			= (compute_blk_staking_func_ptr)get_tpo_mod_exp_addr_name(tpomod, "compute_blk_staking", 0);
	get_current_pos_difficulty	= (get_current_pos_difficulty_func_ptr)get_tpo_mod_exp_addr_name(tpomod, "get_current_pos_difficulty", 0);
	load_last_pos_blk			= (load_last_pos_blk_func_ptr)get_tpo_mod_exp_addr_name(tpomod, "load_last_pos_blk", 0);
	store_last_pos_hash			= (store_last_pos_hash_func_ptr)get_tpo_mod_exp_addr_name(tpomod, "store_last_pos_hash", 0);
	find_last_pos_block			= (find_last_pos_block_func_ptr)get_tpo_mod_exp_addr_name(tpomod, "find_last_pos_block", 0);
#endif
	return 1;
}

void load_node_module(mem_zone_ref_ptr node_config)
{
	load_module("modz/node_adx.tpo", "node_adx", &node_mod);
	
#ifndef _DEBUG
	node_init_self				=(mem_ptr) get_tpo_mod_exp_addr_name(&node_mod, "node_init_self", 0);
	node_set_last_block			=(mem_ptr) get_tpo_mod_exp_addr_name(&node_mod, "node_set_last_block", 0);
	node_find_last_pow_block	=(mem_ptr) get_tpo_mod_exp_addr_name(&node_mod, "node_find_last_pow_block", 0);
	node_load_last_blks			=(mem_ptr) get_tpo_mod_exp_addr_name(&node_mod, "node_load_last_blks", 0);
	node_add_block_index		=(mem_ptr) get_tpo_mod_exp_addr_name(&node_mod, "node_add_block_index", 0);
	node_is_next_block			=(mem_ptr) get_tpo_mod_exp_addr_name(&node_mod, "node_is_next_block", 0);
	node_init_rpc				=(mem_ptr) get_tpo_mod_exp_addr_name(&node_mod, "node_init_rpc", 0);
	node_init_block_explorer	=(mem_ptr) get_tpo_mod_exp_addr_name(&node_mod, "node_init_block_explorer", 0);
	check_rpc_request			=(mem_ptr) get_tpo_mod_exp_addr_name(&node_mod, "check_rpc_request", 0);
	new_peer_node				=(mem_ptr) get_tpo_mod_exp_addr_name(&node_mod, "new_peer_node", 0);
	node_add_block				=(mem_ptr) get_tpo_mod_exp_addr_name(&node_mod, "node_add_block", 0);
	read_node_msg				=(mem_ptr) get_tpo_mod_exp_addr_name(&node_mod, "read_node_msg", 0);
	send_node_messages			=(mem_ptr) get_tpo_mod_exp_addr_name(&node_mod, "send_node_messages", 0);
	node_add_block_header		=(mem_ptr) get_tpo_mod_exp_addr_name(&node_mod, "node_add_block_header", 0);
	queue_version_message		=(mem_ptr) get_tpo_mod_exp_addr_name(&node_mod, "queue_version_message", 0);
	queue_verack_message		=(mem_ptr) get_tpo_mod_exp_addr_name(&node_mod, "queue_verack_message", 0);
	queue_ping_message			=(mem_ptr) get_tpo_mod_exp_addr_name(&node_mod, "queue_ping_message", 0);
	queue_pong_message			=(mem_ptr) get_tpo_mod_exp_addr_name(&node_mod, "queue_pong_message", 0);
	queue_getaddr_message		=(mem_ptr) get_tpo_mod_exp_addr_name(&node_mod, "queue_getaddr_message", 0);
	queue_getdata_message		=(mem_ptr) get_tpo_mod_exp_addr_name(&node_mod, "queue_getdata_message",0);
	queue_getblocks_message		=(mem_ptr) get_tpo_mod_exp_addr_name(&node_mod, "queue_getblocks_message", 0);
	queue_getblock_hdrs_message =(mem_ptr) get_tpo_mod_exp_addr_name(&node_mod, "queue_getblock_hdrs_message", 0);
	queue_send_message			=(mem_ptr) get_tpo_mod_exp_addr_name(&node_mod, "queue_send_message", 0);
	queue_emitted_element		=(mem_ptr) get_tpo_mod_exp_addr_name(&node_mod, "queue_emitted_element", 0);
	queue_emitted_message		=(mem_ptr) get_tpo_mod_exp_addr_name(&node_mod, "queue_emitted_message", 0);
	queue_inv_message			=(mem_ptr) get_tpo_mod_exp_addr_name(&node_mod, "queue_inv_message", 0);
	queue_block_message			=(mem_ptr) get_tpo_mod_exp_addr_name(&node_mod, "queue_block_message", 0);
#endif
}


OS_API_C_FUNC(int) app_init(mem_zone_ref_ptr params)
{
	mem_zone_ref		log = { PTR_NULL };
	unsigned char		*data;

	size_t				data_len;
	tree_manager_init(8*1024*1024);
	
	node_port_str.str = PTR_NULL;
	node_port_str.len = 0;
	node_port_str.size = 0;

	node_hostname.str = PTR_NULL;
	node_hostname.len = 0;
	node_hostname.size = 0;
	self_node.zone = PTR_NULL;
	node_config.zone = PTR_NULL;
	init_string(&user_agent);
	peer_nodes.zone = PTR_NULL;
	memset_c(null_hash, 0, 32);


	if (get_file("iadix.conf", &data, &data_len)<=0)
	{
		log_message("unable to file iadix.conf\n", PTR_NULL);
		return 0;
	}

	if (!tree_manager_json_loadb(data, data_len, &node_config))
	{
		free_c(data);
		log_message("unable to parse node config\n", PTR_NULL);
		return 0;
	}
	free_c(data);

	create_dir("txs");
	if (stat_file("txs") != 0)
	{
		log_message("unable to create tx dir \n", PTR_NULL);
		return 0;
	}
	create_dir("blks");
	if (stat_file("blks") != 0)
	{
		log_message("unable to create blks dir \n", PTR_NULL);
		return 0;
	}
	
	tree_manager_get_child_value_istr	(&node_config, NODE_HASH("seed_node_host"), &node_hostname, 0);
	tree_manager_get_child_value_i32	(&node_config, NODE_HASH("seed_node_port"), &seed_port);
	tree_manager_get_child_value_i32	(&node_config, NODE_HASH("p2p_port"), &node_port);
	tree_manager_get_child_value_istr	(&node_config, NODE_HASH("name"), &user_agent, 0);
	
	load_node_module					(&node_config);

	if (!node_init_self(&self_node, &node_config))
	{
		console_print("unable to init self node \n");
		return 0;
	}
	if (stat_file("adrs") != 0)
	{
		create_dir("adrs");
		rebuild_block_index();
	}




	tree_manager_create_node("log", NODE_LOG_PARAMS, &log);
	tree_manager_set_child_value_i32(&log, "port", node_port);
	tree_manager_set_child_value_str(&log, "hostname", node_hostname.str);
	log_message("node port %port% open @ '%hostname%'", &log);
	release_zone_ref(&log);

	return 1;
}



OS_API_C_FUNC(int) app_start(mem_zone_ref_ptr params)
{
	mem_zone_ref		genesis = { PTR_NULL };
	mem_zone_ref		log = { PTR_NULL };
	mem_zone_ref		seed_node = { PTR_NULL }, rpc_wallet_conf = { PTR_NULL }, block_explorer_conf = { PTR_NULL }, genesis_conf = { PTR_NULL }, stake_conf = { PTR_NULL };
	struct host_def		*seed_host;
	int					nc;
	
	log_output("app start\n");
		

	if (!tree_manager_find_child_node(&node_config, NODE_HASH("genesis"), 0xFFFFFFFF, &genesis_conf))
	{
		log_message("no genesis block in node config\n", PTR_NULL);
		return 0;
	}

	
	make_genesis_block(&genesis_conf, &genesis);

	
	if (tree_manager_find_child_node(&node_config, NODE_HASH("staking"), 0xFFFFFFFF, &stake_conf))
	{
		char			staking_kernel[33];
		tree_manager_get_child_value_str(&stake_conf, NODE_HASH("staking_kernel"), staking_kernel, 33, 0);

	
		if (load_pos_module(staking_kernel, &pos_kernel))
		{
			init_pos(&stake_conf);
			store_blk_staking(&genesis, PTR_NULL);
		}
		release_zone_ref(&stake_conf);
	}
	else
		memset_c(&pos_kernel, 0, sizeof(tpo_mod_file));

	nc = get_last_block_height();
	if (nc < 1)
	{
		hash_t h;
		unsigned int t;
		tree_manager_get_child_value_hash	(&genesis, NODE_HASH("blk hash"), h);
		tree_manager_get_child_value_i32	(&genesis, NODE_HASH("time"), &t);


		tree_manager_create_node			("log", NODE_LOG_PARAMS, &log);
		tree_manager_set_child_value_hash	(&log, "hash", h);
		tree_manager_set_child_value_i32	(&log, "time", t);
		log_message							("initial block : %hash%, time : %time% \n", &log);
		release_zone_ref					(&log);

		node_set_last_block					(&genesis);
		node_add_block_index				(h,t);
	}
	release_zone_ref(&genesis_conf);
	release_zone_ref(&genesis);

	if (!tree_manager_create_node("peer nodes", NODE_BITCORE_NODE_LIST, &peer_nodes))
	{
		log_output("unable to create peer node list\n");
		return 0;
	}


	tree_manager_create_node			("log", NODE_LOG_PARAMS, &log);
	tree_manager_set_child_value_str	(&log, "host", node_hostname.str);
	tree_manager_set_child_value_i32	(&log, "port", seed_port);
	log_message							("initializing seed node: %host%:%port%\n", &log);
	release_zone_ref					(&log);

	seed_host = make_host_def(node_hostname.str, seed_port);
	if (!new_peer_node(seed_host, &peer_nodes))
	{
		tree_manager_create_node		("log", NODE_LOG_PARAMS, &log);
		tree_manager_set_child_value_str(&log, "host", node_hostname.str);
		tree_manager_set_child_value_i32(&log, "port", seed_port);
		log_message						("could not initialize seed node\n", &log);
		release_zone_ref				(&log);

		free_string(&node_port_str);
		free_string(&node_hostname);
		free_host_def(seed_host);
		return 0;
	}
	free_host_def(seed_host);

	//reset_addr_scan();
		

	if (tree_manager_find_child_node(&node_config, NODE_HASH("rpc_wallet"), 0xFFFFFFFF, &rpc_wallet_conf))
	{
		log_output		("initializing rpc server \n");
		node_init_rpc	(&rpc_wallet_conf,&pos_kernel);
		release_zone_ref(&rpc_wallet_conf);
	}

	if (tree_manager_find_child_node(&node_config, NODE_HASH("block_explorer"), 0xFFFFFFFF, &block_explorer_conf))
	{
		log_output				("initializing block explorer \n");
		node_init_block_explorer(&block_explorer_conf, &pos_kernel);
		release_zone_ref		(&block_explorer_conf);
	}

	
	if (nc > 1)
	{
		mem_zone_ref		last_blk = { PTR_NULL };
		mem_zone_ref		lastPOSBlk = { PTR_NULL }, lastPOWBlk = { PTR_NULL };
		unsigned int		nBits;

		node_load_last_blks();


		tree_manager_find_child_node(&self_node, NODE_HASH("last block"), NODE_BITCORE_BLK_HDR, &last_blk);

		//compute current block difficulty
		if (tree_manager_find_child_node(&self_node, NODE_HASH("last pow block"), NODE_BITCORE_BLK_HDR, &lastPOWBlk))
		{
			
			if (compute_last_pow_diff(&lastPOWBlk, &nBits))
				tree_manager_set_child_value_i32(&self_node, "current pow diff", nBits);
			else
			{
				tree_manager_get_child_value_i32(&last_blk, NODE_HASH("bits"), &nBits);
				tree_manager_set_child_value_i32(&self_node, "current pow diff", nBits);
			}
			release_zone_ref(&lastPOWBlk);
		}

		if (strlen_c(pos_kernel.name) > 0)
		{
			unsigned int	time, nBits;

			if (tree_manager_create_node("last pos block", NODE_BITCORE_BLK_HDR, &lastPOSBlk))
			{
				if (load_last_pos_blk(&lastPOSBlk))
					tree_manager_node_add_child(&self_node, &lastPOSBlk);
				else if (last_blk.zone != PTR_NULL)
				{
					copy_zone_ref(&lastPOSBlk, &last_blk);
					if (find_last_pos_block(&lastPOSBlk, &time))
					{
						hash_t			h;
						tree_manager_get_child_value_hash(&lastPOSBlk, NODE_HASH("blk hash"), h);
						store_last_pos_hash(h);
						tree_manager_node_add_child(&self_node, &lastPOSBlk);
					}
					else
						copy_zone_ref(&lastPOSBlk, &last_blk);
				}

				if (compute_last_pos_diff(&lastPOSBlk, &nBits))
					tree_manager_set_child_value_i32(&self_node, "current pos diff", nBits);
				else
				{
					tree_manager_get_child_value_i32(&self_node, NODE_HASH("limit"), &nBits);
					tree_manager_set_child_value_i32(&self_node, "current pos diff", nBits);
				}
				log_message("loaded last block pos %blk hash%", &lastPOSBlk);
				release_zone_ref(&lastPOSBlk);
			}
		}
		release_zone_ref(&last_blk);
	}

	//remove_last_block();

	log_output("version\n");
	tree_manager_get_child_at(&peer_nodes, 0, &seed_node);
	queue_version_message(&seed_node, &user_agent);
	release_zone_ref(&seed_node);

	synching = 0;
	return 1;

}



OS_API_C_FUNC(int) app_loop(mem_zone_ref_ptr params)
{
	mem_zone_ref		blk_list = { PTR_NULL };
	mem_zone_ref		my_list = { PTR_NULL };
	mem_zone_ref		hash_list = { PTR_NULL };
	mem_zone_ref_ptr	blk = PTR_NULL;
	unsigned int		new_block = 0;

	update_nodes();
	process_nodes();

	tree_manager_create_node("hashes", NODE_BITCORE_HASH_LIST, &hash_list);

	if (tree_manager_find_child_node(&self_node, NODE_HASH("submitted blocks"), NODE_BITCORE_BLK_HDR_LIST, &blk_list))
	{
		for (tree_manager_get_first_child(&blk_list, &my_list, &blk); ((blk != NULL) && (blk->zone != NULL)); tree_manager_get_next_child(&my_list, &blk))
		{
			hash_t blk_hash = { 0 };
			struct string signature = { PTR_NULL };
			mem_zone_ref tx_list = { PTR_NULL };
			int			 ret;
			if (!tree_manager_find_child_node(blk, NODE_HASH("txs"), NODE_BITCORE_TX_LIST, &tx_list))continue;
			if (!tree_manager_get_child_value_istr(blk, NODE_HASH("signature"), &signature, 0))continue;
			
			ret=accept_block					(blk, &tx_list,&signature);
			if (ret)
			{
				mem_zone_ref		new_hash = { PTR_NULL };

				tree_manager_get_child_value_hash(blk, NODE_HASH("blk hash"), blk_hash);
				if (tree_manager_add_child_node(&hash_list, "hash", NODE_BITCORE_BLOCK_HASH, &new_hash))
				{
					tree_manager_write_node_hash(&new_hash, 0, blk_hash);
					release_zone_ref(&new_hash);
				}
				new_block = 1;
			}
			release_zone_ref					(&tx_list);
			free_string							(&signature);
			tree_manager_set_child_value_bool	(blk, "done", 1);
		}
		tree_remove_child_by_member_value_dword(&blk_list, NODE_BITCORE_BLK_HDR, "done", 1);
		release_zone_ref(&blk_list);
	}
	if (new_block)
	{
		mem_zone_ref_ptr	node = PTR_NULL;
		for (tree_manager_get_first_child(&peer_nodes, &my_list, &node); ((node != NULL) && (node->zone != NULL)); tree_manager_get_next_child(&my_list, &node))
		{
			queue_inv_message(node, &hash_list);
		}
	}
	release_zone_ref(&hash_list);

	return 1;
}

OS_API_C_FUNC(int) app_stop(mem_zone_ref_ptr params)
{
	release_zone_ref(&node_config);
	return 1;
}


unsigned int C_API_FUNC _DllMainCRTStartup(unsigned int *prev, unsigned int *cur, unsigned int *xx)
{

	return 1;
}
