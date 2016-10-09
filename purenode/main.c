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
unsigned int		TargetSpacing = 0xCDCDCDCD;
unsigned int		nTargetTimespan = 0xCDCDCDCD;
hash_t				Difflimit = { 0xFF };
unsigned int		Di = 0xFFFFFF;
mem_zone_ref		lastBlk = { PTR_INVALID };


C_IMPORT int C_API_FUNC compute_block_hash(mem_zone_ref_ptr block, hash_t hash);
C_IMPORT int C_API_FUNC find_hash(hash_t hash);
C_IMPORT int  C_API_FUNC load_blk_hdr(mem_zone_ref_ptr hdr, const char *blk_hash);
C_IMPORT int  C_API_FUNC make_genesis_block(mem_zone_ref_ptr genesis_conf, mem_zone_ref_ptr genesis);
C_IMPORT int  C_API_FUNC get_last_block_height();
C_IMPORT int  C_API_FUNC remove_block(hash_t blk_hash);
C_IMPORT int	C_API_FUNC add_moneysupply(uint64_t amount);
C_IMPORT int  C_API_FUNC get_tx_output(mem_zone_ref_const_ptr tx, unsigned int idx, mem_zone_ref_ptr vout);
C_IMPORT int  C_API_FUNC get_tx_input(mem_zone_ref_const_ptr tx, unsigned int idx, mem_zone_ref_ptr vin);
C_IMPORT int  C_API_FUNC is_tx_null(mem_zone_ref_const_ptr tx);
C_IMPORT int  C_API_FUNC is_vout_null(mem_zone_ref_const_ptr tx, unsigned int idx);
C_IMPORT int  C_API_FUNC load_tx_input(mem_zone_ref_const_ptr tx, unsigned int idx, mem_zone_ref_ptr	vin, mem_zone_ref_ptr tx_out);
C_IMPORT int  C_API_FUNC load_tx(mem_zone_ref_ptr tx, hash_t blk_hash, const char *tx_hash);
C_IMPORT int  C_API_FUNC get_tx_output_amount(const hash_t tx_hash, unsigned int idx, uint64_t *amount);
C_IMPORT uint64_t C_API_FUNC  get_blockreward(uint64_t block);

C_IMPORT int			C_API_FUNC		SetCompact(unsigned int bits, hash_t out);
C_IMPORT int			C_API_FUNC		is_pow_block(const char *blk_hash);
C_IMPORT unsigned int	C_API_FUNC		calc_new_target(unsigned int nActualSpacing, unsigned int TargetSpacing, unsigned int nTargetTimespan, unsigned int pBits);
C_IMPORT int			C_API_FUNC		compute_block_pow(mem_zone_ref_ptr block, hash_t hash);
C_IMPORT int			C_API_FUNC		check_block_pow(mem_zone_ref_ptr hdr, hash_t diff_hash);
C_IMPORT int			C_API_FUNC		 get_out_script_address(struct string *script, btc_addr_t addr);
C_IMPORT int			C_API_FUNC		 add_unspent(btc_addr_t	addr, const char *tx_hash, unsigned int oidx, uint64_t amount, btc_addr_t *src_addrs, unsigned int n_addrs);
C_IMPORT int			C_API_FUNC		 spend_tx_addr(btc_addr_t addr, const char *tx_hash, unsigned int vin, const char *ptx_hash, unsigned int oidx, btc_addr_t *addrs_to, unsigned int n_addrs_to);
C_IMPORT int			C_API_FUNC		  get_tx_output_addr(const hash_t tx_hash, unsigned int idx, btc_addr_t addr);

typedef int	C_API_FUNC node_init_self_func(mem_zone_ref_ptr out_self_node, mem_zone_ref_ptr node_config);
typedef int	C_API_FUNC new_peer_node_func(struct host_def *host, mem_zone_ref_ptr peer_nodes);
typedef int	C_API_FUNC node_add_block_func(mem_zone_ref_ptr lastBlk, mem_zone_ref_ptr header, mem_zone_ref_ptr txs, uint64_t staking_reward);
typedef int	C_API_FUNC read_node_msg_func(mem_zone_ref_ptr node);
typedef int	C_API_FUNC send_node_messages_func(mem_zone_ref_ptr node);
typedef int	C_API_FUNC node_add_block_header_func(mem_zone_ref_ptr node, mem_zone_ref_ptr hdr);
typedef int	C_API_FUNC queue_version_message_func(mem_zone_ref_ptr node, struct string *user_agent);
typedef int	C_API_FUNC queue_verack_message_func(mem_zone_ref_ptr node);
typedef int	C_API_FUNC queue_ping_message_func(mem_zone_ref_ptr node, uint64_t nonce);
typedef int	C_API_FUNC queue_pong_message_func(mem_zone_ref_ptr node, uint64_t nonce);
typedef int	C_API_FUNC queue_getaddr_message_func(mem_zone_ref_ptr node);
typedef int	C_API_FUNC queue_getdata_message_func(mem_zone_ref_ptr node, mem_zone_ref_ptr hash_list);
typedef int	C_API_FUNC queue_getblocks_message_func(mem_zone_ref_ptr node);
typedef int	C_API_FUNC queue_getblock_hdrs_message_func(mem_zone_ref_ptr node);
typedef int	C_API_FUNC queue_send_message_func(mem_zone_ref_ptr node, mem_zone_ref_ptr msg);
typedef int	C_API_FUNC queue_emitted_element_func(mem_zone_ref_ptr node, mem_zone_ref_ptr element);
typedef int	C_API_FUNC queue_emitted_message_func(mem_zone_ref_ptr node, mem_zone_ref_ptr msg);
typedef int	C_API_FUNC node_init_rpc_func(mem_zone_ref_ptr in_config);
typedef int	C_API_FUNC check_rpc_request_func();



typedef int	C_API_FUNC	init_pos_func(mem_zone_ref_ptr stake_conf);
typedef int	C_API_FUNC	store_blk_staking_func(mem_zone_ref_ptr header,mem_zone_ref_ptr tx_list);
typedef int	C_API_FUNC	store_tx_staking_func(mem_zone_ref_ptr tx, const char *tx_hash, btc_addr_t stake_addr, uint64_t	stake_in);
typedef int	C_API_FUNC	compute_blk_staking_func(mem_zone_ref_ptr prev, mem_zone_ref_ptr hdr, mem_zone_ref_ptr tx_list, uint64_t *staking_reward);



typedef node_init_self_func					 *node_init_self_func_ptr;
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
typedef queue_getblocks_message_func		 *queue_getblocks_message_func_ptr;
typedef queue_getblock_hdrs_message_func	 *queue_getblock_hdrs_message_func_ptr;
typedef queue_send_message_func				 *queue_send_message_func_ptr;
typedef queue_emitted_element_func			 *queue_emitted_element_func_ptr;
typedef queue_emitted_message_func			 *queue_emitted_message_func_ptr;
typedef node_init_rpc_func					 *node_init_rpc_func_ptr;
typedef check_rpc_request_func				 *check_rpc_request_func_ptr;


typedef init_pos_func						*init_pos_func_ptr;
typedef store_blk_staking_func				*store_blk_staking_func_ptr;
typedef store_tx_staking_func				*store_tx_staking_func_ptr;
typedef compute_blk_staking_func			*compute_blk_staking_func_ptr;


#ifdef _DEBUG
C_IMPORT int			C_API_FUNC		node_init_self(mem_zone_ref_ptr out_self_node, mem_zone_ref_ptr node_config);
C_IMPORT int			C_API_FUNC		new_peer_node(struct host_def *host, mem_zone_ref_ptr peer_nodes);
C_IMPORT int			C_API_FUNC		node_add_block(mem_zone_ref_ptr LastBlk, mem_zone_ref_ptr header, mem_zone_ref_ptr txs, uint64_t staking_reward);
C_IMPORT int			C_API_FUNC		read_node_msg(mem_zone_ref_ptr node);
C_IMPORT int			C_API_FUNC		send_node_messages(mem_zone_ref_ptr node);
C_IMPORT int			C_API_FUNC		node_add_block_header(mem_zone_ref_ptr node, mem_zone_ref_ptr hdr);
C_IMPORT int			C_API_FUNC		queue_version_message(mem_zone_ref_ptr node, struct string *user_agent);
C_IMPORT int			C_API_FUNC		queue_verack_message(mem_zone_ref_ptr node);
C_IMPORT int			C_API_FUNC		queue_ping_message(mem_zone_ref_ptr node, uint64_t nonce);
C_IMPORT int			C_API_FUNC		queue_pong_message(mem_zone_ref_ptr node, uint64_t nonce);
C_IMPORT int			C_API_FUNC		queue_getaddr_message(mem_zone_ref_ptr node);
C_IMPORT int			C_API_FUNC		queue_getdata_message(mem_zone_ref_ptr node, mem_zone_ref_ptr hash_list);
C_IMPORT int			C_API_FUNC		queue_getblocks_message(mem_zone_ref_ptr node);
C_IMPORT int			C_API_FUNC		queue_getblock_hdrs_message(mem_zone_ref_ptr node);
C_IMPORT int			C_API_FUNC		queue_send_message(mem_zone_ref_ptr node, mem_zone_ref_ptr msg);
C_IMPORT int			C_API_FUNC		queue_emitted_element(mem_zone_ref_ptr node, mem_zone_ref_ptr element);
C_IMPORT int			C_API_FUNC		queue_emitted_message(mem_zone_ref_ptr node, mem_zone_ref_ptr msg);

C_IMPORT int			C_API_FUNC		node_init_rpc(mem_zone_ref_ptr in_config);
C_IMPORT int			C_API_FUNC		check_rpc_request();

C_IMPORT int	C_API_FUNC	init_pos(mem_zone_ref_ptr stake_conf);
C_IMPORT int	C_API_FUNC	store_blk_staking(mem_zone_ref_ptr header, mem_zone_ref_ptr tx_list);
C_IMPORT int	C_API_FUNC	compute_blk_staking(mem_zone_ref_ptr prev, mem_zone_ref_ptr hdr, mem_zone_ref_ptr tx_list, uint64_t *staking_reward);
C_IMPORT int	C_API_FUNC	store_tx_staking(mem_zone_ref_ptr tx, const char *tx_hash, btc_addr_t stake_addr, uint64_t	stake_in);

node_init_self_func_ptr						_node_init_self=PTR_INVALID;
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
queue_getblocks_message_func_ptr			_queue_getblocks_message=PTR_INVALID;
queue_getblock_hdrs_message_func_ptr		_queue_getblock_hdrs_message=PTR_INVALID;
queue_send_message_func_ptr					_queue_send_message=PTR_INVALID;
queue_emitted_element_func_ptr				_queue_emitted_element=PTR_INVALID;
queue_emitted_message_func_ptr				_queue_emitted_message=PTR_INVALID;
node_init_rpc_func_ptr						_node_init_rpc = PTR_INVALID;
check_rpc_request_func_ptr					_check_rpc_request = PTR_INVALID;
init_pos_func_ptr							_init_pos = PTR_INVALID;
store_blk_staking_func_ptr					_store_blk_staking = PTR_INVALID;
store_tx_staking_func_ptr					_store_tx_staking = PTR_INVALID;
compute_blk_staking_func_ptr				_compute_blk_staking = PTR_INVALID;


#else
node_init_self_func_ptr						node_init_self = PTR_INVALID;
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
queue_getblocks_message_func_ptr			queue_getblocks_message = PTR_INVALID;
queue_getblock_hdrs_message_func_ptr		queue_getblock_hdrs_message = PTR_INVALID;
queue_send_message_func_ptr					queue_send_message = PTR_INVALID;
queue_emitted_element_func_ptr				queue_emitted_element = PTR_INVALID;
queue_emitted_message_func_ptr				queue_emitted_message = PTR_INVALID;

init_pos_func_ptr							init_pos= PTR_INVALID;
store_blk_staking_func_ptr					store_blk_staking= PTR_INVALID;
store_tx_staking_func_ptr					store_tx_staking = PTR_INVALID;
compute_blk_staking_func_ptr				compute_blk_staking= PTR_INVALID;
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

OS_API_C_FUNC(int) store_tx_wallet(btc_addr_t addr, hash_t tx_hash)
{
	char			 tchash[65];
	hash_t			 blk_hash;
	btc_addr_t	 	 to_addr_list[16];
	btc_addr_t		 src_addr_list[16];
	struct string	 tx_path = { 0 };
	mem_zone_ref	 txin_list = { PTR_NULL }, txout_list = { PTR_NULL }, my_list = { PTR_NULL }, tx = { PTR_NULL };
	mem_zone_ref_ptr input = PTR_NULL, out = PTR_NULL;
	unsigned int	 n, oidx, iidx;
	unsigned int	 n_to_addrs;
	unsigned int	 n_in_addr;

	if (!load_tx(&tx, blk_hash, tx_hash))return 0;
	if (is_tx_null(&tx))
	{
		release_zone_ref(&tx);
		return 0;
	}
	if (!tree_manager_find_child_node(&tx, NODE_HASH("txsin"), NODE_BITCORE_VINLIST, &txin_list))return 0;
	if (!tree_manager_find_child_node(&tx, NODE_HASH("txsout"), NODE_BITCORE_VOUTLIST, &txout_list)){ release_zone_ref(&txin_list); return 0; }

	n = 0;
	while (n < 32)
	{
		tchash[n * 2 + 0] = hex_chars[tx_hash[n] >> 4];
		tchash[n * 2 + 1] = hex_chars[tx_hash[n] & 0x0F];
		n++;
	}
	tchash[64] = 0;

	n_to_addrs = 0;
	for (tree_manager_get_first_child(&txout_list, &my_list, &out); ((out != NULL) && (out->zone != NULL)); tree_manager_get_next_child(&my_list, &out))
	{
		struct string script = { 0 };
		if (!tree_manager_get_child_value_istr(out, NODE_HASH("script"), &script, 16))continue;
		if (script.len == 0){ free_string(&script); continue; }
		if (get_out_script_address(&script, to_addr_list[n_to_addrs]))
		{
			unsigned int n, f;
			f = 0;
			for (n = 0; n < n_to_addrs; n++)
			{
				if (!memcmp_c(to_addr_list[n_to_addrs], to_addr_list[n], sizeof(btc_addr_t)))
				{
					f = 1;
					break;
				}
			}
			if (f == 0)
				n_to_addrs++;
		}
		free_string(&script);
	}


	n_in_addr = 0;
	for (iidx = 0, tree_manager_get_first_child(&txin_list, &my_list, &input); ((input != NULL) && (input->zone != NULL)); tree_manager_get_next_child(&my_list, &input), iidx++)
	{
		char			ptchash[65];
		hash_t			prev_hash = { 0xFF };
		struct string	out_path = { 0 };
		int				n, my_addr;
		uint64_t		amount;

		tree_manager_get_child_value_hash(input, NODE_HASH("tx hash"), prev_hash);
		tree_manager_get_child_value_i32(input, NODE_HASH("idx"), &oidx);

		my_addr = 0;

		//coin base
		if (!memcmp_c(prev_hash, null_hash, sizeof(hash_t)))
		{
			memset_c(src_addr_list[0], '0', sizeof(btc_addr_t));
			n_in_addr = 1;
			continue;
		}


		if (get_tx_output_addr(prev_hash, oidx, src_addr_list[n_in_addr]))
		{
			unsigned int nn, f;
			f = 0;
			for (nn = 0; nn < n_in_addr; nn++)
			{
				if (!memcmp_c(src_addr_list[n_in_addr], src_addr_list[nn], sizeof(btc_addr_t)))
				{
					f = 1;
					break;
				}
			}

			if (!memcmp_c(addr, src_addr_list[n_in_addr], sizeof(btc_addr_t)))
				my_addr = 1;

			if (f == 0)
				n_in_addr++;

		}

		if (my_addr)
		{
			n = 0;
			while (n < 32)
			{
				ptchash[n * 2 + 0] = hex_chars[prev_hash[n] >> 4];
				ptchash[n * 2 + 1] = hex_chars[prev_hash[n] & 0x0F];
				n++;
			}
			ptchash[64] = 0;
			spend_tx_addr(addr, tchash, iidx, ptchash, oidx, to_addr_list, n_to_addrs);

			if (get_tx_output_amount(prev_hash, oidx, &amount))
				tree_manager_set_child_value_i64(input, "amount", amount);
			tree_manager_set_child_value_btcaddr(input, "src addr", addr);
		}
	}


	out = PTR_NULL;
	release_zone_ref(&my_list);

	for (oidx = 0, tree_manager_get_first_child(&txout_list, &my_list, &out); ((out != NULL) && (out->zone != NULL)); oidx++, tree_manager_get_next_child(&my_list, &out))
	{
		btc_addr_t		out_addr = { 0 };
		struct string	out_path = { 0 }, script = { 0 };
		uint64_t		amount = 0;
		int				ret;

		tree_manager_get_child_value_istr(out, NODE_HASH("script"), &script, 0);
		ret = get_out_script_address(&script, out_addr);
		free_string(&script);

		if (ret)
		{
			make_string(&out_path, "adrs");
			cat_ncstring_p(&out_path, out_addr, 34);

			/*
			if (is_coinbase(&tx))
			create_dir(out_path.str);
			*/
			if ((stat_file(out_path.str) == 0) && (!memcmp_c(addr, out_addr, sizeof(btc_addr_t))))
			{
				tree_manager_get_child_value_i64(out, NODE_HASH("value"), &amount);
				add_unspent(out_addr, tchash, oidx, amount, src_addr_list, n_in_addr);
			}
			free_string(&out_path);
		}
	}
	if (is_vout_null(&tx, 0))
	{
		mem_zone_ref	vin = { PTR_NULL };
		btc_addr_t		stake_addr = { 0 };
		uint64_t		stake_in = 0;

		if (tree_manager_get_child_at(&txin_list, 0, &vin))
		{
			tree_manager_get_child_value_btcaddr(&vin, NODE_HASH("src addr"), stake_addr);
			tree_manager_get_child_value_i64(&vin, NODE_HASH("amount"), &stake_in);
			release_zone_ref(&vin);
		}
		release_zone_ref(&txin_list);

		if (!memcmp_c(stake_addr, addr, sizeof(btc_addr_t)))
			store_tx_staking(&tx, tchash, stake_addr, stake_in);
	}

	release_zone_ref(&txin_list);
	release_zone_ref(&txout_list);
	release_zone_ref(&tx);

	return 1;

}
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
			cat_cstring_p(&adr_path, "scan");
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
	}

	if (!get_file("./blk_indexes", &data, &data_len))
	{
		free_string(&scan_path);
		free_string(&adr_path);
		return 0;
	}


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
	free_string(&adr_path);

	return 1;
}



int handle_version(mem_zone_ref_ptr node, mem_zone_ref_ptr payload)
{
	char		 user_agent[32];
	mem_zone_ref log = { PTR_NULL };
	unsigned int proto_ver, last_blk, node_port,my_port;
	mem_zone_ref addrs[2] = { PTR_NULL };
	uint64_t	 time, services, timestamp;
	int			 index = 0;
	ipv4_t		 node_ip,my_ip;

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

/*
//fProofOfStake ?GetProofOfStakeLimit(pindexLast->nHeight) : Params().ProofOfWorkLimit()
unsigned int GetNextTargetRequired(mem_zone_ref_ptr pindexLast, unsigned int bnTargetLimit)
{
	hash_t bnNew;
	ctime_t pprev_time, prev_time;
	int64_t	quotient, dividend;
	unsigned int blk_time, nBits;
	if (pindexLast == NULL)
		return 1;
	
	tree_manager_get_child_value_i32(pindexLast, NODE_HASH("time"), &blk_time);
	tree_manager_get_child_value_i32(pindexLast, NODE_HASH("nBits"), &nBits);


	get_prev_block_time				(pindexLast,&pprev_time);

	prev_time = blk_time;
		
	int64_t nTargetSpacing	= GetTargetSpacing(pindexLast->nHeight);
	int64_t nActualSpacing	= prev_time - pprev_time;
	int64_t nInterval		= nTargetTimespan / nTargetSpacing;
	quotient = ((nInterval - 1) * nTargetSpacing + nActualSpacing + nActualSpacing);
	dividend = ((nInterval + 1) * nTargetSpacing);


	if (IsProtocolV1RetargetingFixed(pindexLast->nHeight)) {
		if (nActualSpacing < 0)
			nActualSpacing = nTargetSpacing;
	}
	if (IsProtocolV3(pindexLast->nTime)) {
		if (nActualSpacing > nTargetSpacing * 10)
			nActualSpacing = nTargetSpacing * 10;
	}
	
	// ppcoin: target change every block
	// ppcoin: retarget with exponential moving toward target spacing
	
	bnNew.SetCompact(pindexPrev->nBits);
	
	bnNew *= ((nInterval - 1) * nTargetSpacing + nActualSpacing + nActualSpacing);
	bnNew /= ((nInterval + 1) * nTargetSpacing);

	if (bnNew <= 0 || bnNew > bnTargetLimit)
		bnNew = bnTargetLimit;

	return bnNew.GetCompact();
}*/

// Get the last pow block and its generation time from a given block



int get_last_pow_block(mem_zone_ref_ptr pindex, unsigned int *block_time)
{
	char			chash[65];
	int				ret = 0;
	tree_manager_get_child_value_str(pindex, NODE_HASH("blk hash"), chash, 65, 16);
	while (!is_pow_block(chash))
	{
		tree_manager_get_child_value_str(pindex, NODE_HASH("prev"), chash, 65, 16);
		if (!load_blk_hdr(pindex, chash))
			return 0;
	}
	if (is_pow_block(chash))
	{
		tree_manager_get_child_value_i32(pindex, NODE_HASH("time"), block_time);
		return 1;
	}
	return 0;
}
int get_last_pow_diff(mem_zone_ref_ptr lastBlk, unsigned int	*pBits, int64_t *spacing)
{
	hash_t				null_hash;
	mem_zone_ref		prevPOW = { PTR_NULL };
	unsigned int		prevTime, pprevTime;
	int					ret;
	//get last two pos blocks


	memset_c(null_hash, 0, sizeof(hash_t));
	copy_zone_ref(&prevPOW, lastBlk);
	ret = get_last_pow_block(&prevPOW, &prevTime);
	if (ret)
	{
		char			cpphash[65];
		mem_zone_ref	pprev = { PTR_NULL };

		tree_manager_get_child_value_i32(&prevPOW, NODE_HASH("bits"), pBits);
		tree_manager_get_child_value_str(&prevPOW, NODE_HASH("prev"), cpphash, 65, 16);
		release_zone_ref(&prevPOW);
		ret = load_blk_hdr(&pprev, cpphash);
		if (ret)
		{
			hash_t pppp;
			tree_manager_get_child_value_hash(&pprev, NODE_HASH("prev"), pppp);

			if (!memcmp_c(pppp, null_hash, sizeof(hash_t)))
				ret = 0;

			if (ret)
				ret = get_last_pow_block(&pprev, &pprevTime);

			if (ret)
				*spacing = prevTime - pprevTime;

			release_zone_ref(&pprev);
		}
	}
	return ret;
}

int handle_block(mem_zone_ref_ptr node, mem_zone_ref_ptr payload)
{
	size_t				nblks;
	hash_t				prevHash, lastHash, blk_hash;
	mem_zone_ref		header = { PTR_NULL }, tx_list = { PTR_NULL };
	int					ret;
	uint64_t			staking_reward;
	
	if (!tree_manager_find_child_node(payload, NODE_HASH("header"), NODE_BITCORE_BLK_HDR, &header))return 0;
	tree_manager_get_child_value_hash(&header, NODE_HASH("prev"), prevHash);

	if (lastBlk.zone != PTR_NULL)
	{
		tree_manager_get_child_value_hash(&lastBlk, NODE_HASH("blk hash"), lastHash);
		if (memcmp_c(lastHash, prevHash, sizeof(hash_t)))
		{
			release_zone_ref(&header);
			return 0;
		}
	}
	compute_block_hash					(&header, blk_hash);
	tree_manager_set_child_value_bhash	(&header, "blk hash", blk_hash);
	if (find_hash(blk_hash))
		remove_block(blk_hash);

	if (!tree_manager_find_child_node(payload, NODE_HASH("txs"), NODE_BITCORE_TX_LIST, &tx_list)){ release_zone_ref(&header); return 0; }
	ret = compute_blk_staking		(&lastBlk, &header, &tx_list, &staking_reward);

	if (staking_reward == 0)
	{
		int64_t				nActualSpacing;
		unsigned int		pBits;
		//compute current block difficulty
		if (get_last_pow_diff(&lastBlk, &pBits, &nActualSpacing))
		{
			hash_t			out_diff;
			unsigned int	bits;

			memset_c(out_diff, 0, sizeof(hash_t));
			if (nActualSpacing > TargetSpacing * 10)
				nActualSpacing = TargetSpacing * 10;

			bits = calc_new_target(nActualSpacing, TargetSpacing, nTargetTimespan, pBits);

			SetCompact(bits, out_diff);

			if (memcmp_c(out_diff, Difflimit, sizeof(hash_t)) < 0)
				SetCompact(Di, out_diff);

			ret = check_block_pow(&header, out_diff);
		}
		else
		{
			hash_t blk_pow;
			ret=compute_block_pow(&header, blk_pow);
			if (ret)
				tree_manager_set_child_value_hash(&header, "blk pow", blk_pow);
		}
	}
	
	if (ret)
		ret = node_add_block(&lastBlk,&header, &tx_list, staking_reward);

	if (ret)
	{
		mem_zone_ref	log = { PTR_NULL };
		size_t nz=0;

		if (strlen_c(pos_kernel.name) > 0)
			store_blk_staking(&header,&tx_list);
#ifdef _DEBUG
		nz = find_zones_used(3);
#endif
		nblks = get_last_block_height();
		tree_manager_create_node("log", NODE_LOG_PARAMS, &log);
		tree_manager_set_child_value_i32(&log, "nblocks", nblks);
		tree_manager_set_child_value_i32(&log, "zones", nz);
		log_message("block height : %nblocks% , %zones%\n", &log);
		release_zone_ref(&log);
		tree_manager_set_child_value_i64(node, "next_check", get_time_c() + 10);
	}
	
	if (ret)
	{
		if (staking_reward == 0)
			add_moneysupply	(get_blockreward(nblks));
		else
			add_moneysupply	(staking_reward);

		copy_zone_ref(&lastBlk, &header);
	}

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




	return 0;
}


int handle_element(mem_zone_ref_ptr node, mem_zone_ref_ptr element)
{
	mem_zone_ref log = { PTR_NULL };

	switch (tree_mamanger_get_node_type(element))
	{
		case NODE_BITCORE_ADDRT:
		{
			unsigned int	time;
			uint64_t		services;
			ipv4_t			ip;
			unsigned short	port;

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
	
	tree_remove_child_by_member_value_dword(&msg_list, NODE_BITCORE_MSG, "handled", 1);
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


int C_API_FUNC scanaddr_func(mem_zone_ref_ptr p, unsigned int *status)
{
	btc_addr_t			new_addr;
	tree_manager_init(1024 * 1024);
	tree_manager_get_node_btcaddr(p, 0, new_addr);
	*status = 1;
	rescan_addr(new_addr);
	tree_manager_free();

	return 1;
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
				background_func(scanaddr_func, &new_addr);
			}
			tree_manager_set_child_value_i32(addr, "done", 1);
		}
		tree_remove_child_by_member_value_dword(&scan_list, NODE_BITCORE_WALLET_ADDR, "done", 1);
		release_zone_ref(&scan_list);
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
	int ret;
	
	strcpy_c(str, "modz/");
	strcat_cs(str, 64, staking_kernel);
	strcat_cs(str, 64, ".tpo");

	ret=load_module(str, staking_kernel, tpomod);
#ifdef _DEBUG
	_init_pos = get_tpo_mod_exp_addr_name(tpomod, "init_pos", 0);
	_store_blk_staking = get_tpo_mod_exp_addr_name(tpomod, "store_blk_staking", 0);
	_store_tx_staking  = get_tpo_mod_exp_addr_name(tpomod, "store_tx_staking", 0);
	
	_compute_blk_staking = get_tpo_mod_exp_addr_name(tpomod, "compute_blk_staking", 0);
#else
	init_pos = get_tpo_mod_exp_addr_name(tpomod, "init_pos", 0);
	store_blk_staking = get_tpo_mod_exp_addr_name(tpomod, "store_blk_staking", 0);
	store_tx_staking = get_tpo_mod_exp_addr_name(tpomod, "store_tx_staking", 0);
	compute_blk_staking = get_tpo_mod_exp_addr_name(tpomod, "compute_blk_staking", 0);
#endif
	return ret;
}

void load_node_module(mem_zone_ref_ptr node_config)
{



	load_module("modz/node_adx.tpo", "node_adx", &node_mod);
#ifdef _DEBUG
	_node_init_self = get_tpo_mod_exp_addr_name(&node_mod, "node_init_self", 0);
	_node_init_rpc = get_tpo_mod_exp_addr_name(&node_mod, "node_init_rpc", 0);
	_check_rpc_request = get_tpo_mod_exp_addr_name(&node_mod, "check_rpc_request", 0);
	_new_peer_node = get_tpo_mod_exp_addr_name(&node_mod, "new_peer_node", 0);
	_node_add_block = get_tpo_mod_exp_addr_name(&node_mod, "node_add_block", 0);
	_read_node_msg = get_tpo_mod_exp_addr_name(&node_mod, "read_node_msg", 0);
	_send_node_messages = get_tpo_mod_exp_addr_name(&node_mod, "send_node_messages", 0);
	_node_add_block_header = get_tpo_mod_exp_addr_name(&node_mod, "node_add_block_header", 0);
	_queue_version_message = get_tpo_mod_exp_addr_name(&node_mod, "queue_version_message", 0);
	_queue_verack_message = get_tpo_mod_exp_addr_name(&node_mod, "queue_verack_message", 0);
	_queue_ping_message = get_tpo_mod_exp_addr_name(&node_mod, "queue_ping_message", 0);
	_queue_pong_message = get_tpo_mod_exp_addr_name(&node_mod, "queue_pong_message", 0);
	_queue_getaddr_message = get_tpo_mod_exp_addr_name(&node_mod, "queue_getaddr_message", 0);
	_queue_getdata_message = get_tpo_mod_exp_addr_name(&node_mod, "queue_getdata_message",0);
	_queue_getblocks_message = get_tpo_mod_exp_addr_name(&node_mod, "queue_getblocks_message", 0);
	_queue_getblock_hdrs_message = get_tpo_mod_exp_addr_name(&node_mod, "queue_getblock_hdrs_message", 0);
	_queue_send_message = get_tpo_mod_exp_addr_name(&node_mod, "queue_send_message", 0);
	_queue_emitted_element = get_tpo_mod_exp_addr_name(&node_mod, "queue_emitted_element", 0);
	_queue_emitted_message = get_tpo_mod_exp_addr_name(&node_mod, "queue_emitted_message", 0);

#else
	node_init_self = get_tpo_mod_exp_addr_name(&node_mod, "node_init_self", 0);
	node_init_rpc = get_tpo_mod_exp_addr_name(&node_mod, "node_init_rpc", 0);
	check_rpc_request = get_tpo_mod_exp_addr_name(&node_mod, "check_rpc_request", 0);
	new_peer_node = get_tpo_mod_exp_addr_name(&node_mod, "new_peer_node", 0);
	node_add_block = get_tpo_mod_exp_addr_name(&node_mod, "node_add_block", 0);
	read_node_msg = get_tpo_mod_exp_addr_name(&node_mod, "read_node_msg", 0);
	send_node_messages = get_tpo_mod_exp_addr_name(&node_mod, "send_node_messages", 0);
	node_add_block_header = get_tpo_mod_exp_addr_name(&node_mod, "node_add_block_header", 0);
	queue_version_message = get_tpo_mod_exp_addr_name(&node_mod, "queue_version_message", 0);
	queue_verack_message = get_tpo_mod_exp_addr_name(&node_mod, "queue_verack_message", 0);
	queue_ping_message = get_tpo_mod_exp_addr_name(&node_mod, "queue_ping_message", 0);
	queue_pong_message = get_tpo_mod_exp_addr_name(&node_mod, "queue_pong_message", 0);
	queue_getaddr_message = get_tpo_mod_exp_addr_name(&node_mod, "queue_getaddr_message", 0);
	queue_getdata_message = get_tpo_mod_exp_addr_name(&node_mod, "queue_getdata_message",0);
	queue_getblocks_message = get_tpo_mod_exp_addr_name(&node_mod, "queue_getblocks_message", 0);
	queue_getblock_hdrs_message = get_tpo_mod_exp_addr_name(&node_mod, "queue_getblock_hdrs_message", 0);
	queue_send_message = get_tpo_mod_exp_addr_name(&node_mod, "queue_send_message", 0);
	queue_emitted_element = get_tpo_mod_exp_addr_name(&node_mod, "queue_emitted_element", 0);
	queue_emitted_message = get_tpo_mod_exp_addr_name(&node_mod, "queue_emitted_message", 0);
#endif
}


OS_API_C_FUNC(int) app_init(mem_zone_ref_ptr params)
{
	mem_zone_ref		log = { PTR_NULL };
	unsigned char		*data;

	size_t				data_len;
	tree_manager_init(4*1024*1024);
	
	lastBlk.zone = PTR_NULL;
	node_port_str.str = PTR_NULL;
	node_port_str.len = 0;
	node_port_str.size = 0;

	node_hostname.str = PTR_NULL;
	node_hostname.len = 0;
	node_hostname.size = 0;

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
	
	
	tree_manager_get_child_value_istr(&node_config, NODE_HASH("seed_node_host"), &node_hostname, 0);
	tree_manager_get_child_value_i32(&node_config, NODE_HASH("seed_node_port"), &seed_port);
	tree_manager_get_child_value_istr(&node_config, NODE_HASH("name"), &user_agent, 0);
	
	self_node.zone = PTR_NULL;
		
	create_dir("adrs");
	create_dir("txs");
	create_dir("blks");

	load_node_module(&node_config);
	if (!node_init_self(&self_node, &node_config))
	{
		console_print("unable to init self node \n");
		return 0;
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
	hash_t				last_hash;
	mem_zone_ref		genesis = { PTR_NULL };
	mem_zone_ref		log = { PTR_NULL };
	mem_zone_ref		seed_node = { PTR_NULL }, rpc_wallet_conf = { PTR_NULL },genesis_conf = { PTR_NULL }, stake_conf = { PTR_NULL };
	struct host_def		*seed_host;
	int					nc;

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
			store_blk_staking(&genesis,PTR_NULL);
		}
		release_zone_ref(&stake_conf);
	}
	else
		memset_c(&pos_kernel, 0, sizeof(tpo_mod_file));
	
	nc =get_last_block_height();
	if ((nc > 1) && (get_hash_idx("blk_indexes", nc - 1, last_hash)))
	{
		char chash[65];
		int	 n;

		n = 0;
		while (n<32)
		{
			chash[n * 2 + 0] = hex_chars[last_hash[n] >> 4];
			chash[n * 2 + 1] = hex_chars[last_hash[n] & 0x0F];
			n++;
		}
		chash[64] = 0;
		load_blk_hdr(&lastBlk, chash);
	}
	else
	{
		copy_zone_ref(&lastBlk, &genesis);
	}
	release_zone_ref(&genesis_conf);
	release_zone_ref(&genesis);

	seed_host = make_host_def(node_hostname.str, seed_port);
	tree_manager_create_node("peer nodes", NODE_BITCORE_NODE_LIST, &peer_nodes);
	if (!new_peer_node(seed_host, &peer_nodes))
	{
		free_string(&node_port_str);
		free_string(&node_hostname);
		free_host_def(seed_host);
		return 0;
	}
	free_host_def(seed_host);

	reset_addr_scan();
		
	if (tree_manager_find_child_node(&node_config, NODE_HASH("rpc_wallet"), 0xFFFFFFFF, &rpc_wallet_conf))
	{
		node_init_rpc(&rpc_wallet_conf);
		release_zone_ref(&rpc_wallet_conf);
	}

	if (!tree_manager_get_child_value_i32(&node_config, NODE_HASH("target spacing"), &TargetSpacing))
		TargetSpacing = 64;

	if (!tree_manager_get_child_value_i32(&node_config, NODE_HASH("target timespan"), &nTargetTimespan))
		nTargetTimespan = 16 * 60;  // 16 mins

	if (!tree_manager_get_child_value_i32(&node_config, NODE_HASH("limit"), &Di))
		Di = 0x1E0FFFFF;

	SetCompact(Di, Difflimit);
	
	tree_manager_get_child_at(&peer_nodes, 0, &seed_node);
	queue_version_message(&seed_node, &user_agent);
	release_zone_ref(&seed_node);

	synching = 0;
	return 1;

}



OS_API_C_FUNC(int) app_loop(mem_zone_ref_ptr params)
{
	update_nodes();
	process_nodes();

	return 1;
}

OS_API_C_FUNC(int) app_stop(mem_zone_ref_ptr params)
{
	release_zone_ref(&node_config);
	return 1;
}

C_EXPORT int _fltused = 0;
C_EXPORT mod_name_decoration_t	 mod_name_deco_type = MOD_NAME_DECO;
unsigned int C_API_FUNC _DllMainCRTStartup(unsigned int *prev, unsigned int *cur, unsigned int *xx)
{

	return 1;
}

/*
int main(int argc, char **argv)
{
	tpo_mod_file		protocol_mod = { 0 }, block_mod = { 0 }, node_mod = { 0 }, libbase_mod = { 0 };
	unsigned int		done = 0;
	mem_zone_ref		node_addr = { PTR_NULL },log = { PTR_NULL };
	mem_zone_ref		tx = { PTR_NULL };

	unsigned char		*data;
	size_t				data_len;
	unsigned int		*tree_area_ptr;



	load_module		("modz/libbase.tpo", "libbase",&libbase_mod);
	load_module		("modz/protocol_adx.tpo", "protocol_adx", &protocol_mod);
	load_module		("modz/block_adx.tpo", "block_adx", &block_mod);
	load_module		("modz/node_adx.tpo", "node_adx", &node_mod);
	load_node_module(&node_mod);

	tree_area_ptr = (unsigned int *)get_tpo_mod_exp_addr_name(&libbase_mod, "tree_mem_area_id",0);
	*tree_area_ptr = tree_mem_area_id;
	
	daemonize						(user_agent.str);


	//load_tx(&tx,"C535E440C35184E7EBD13D686F0DE23EADC84D4C6C241E0685EDA456454C7FB2");
	//check_txs();
	//load_block_indexes(&self_node);
	//get_addr_amounts("BPkMQCc6sjmbDpwpMNvyzMY7RuEQMAetHM", &total);
	while (!done)
	{


	}

	return 0;
}

void mainCRTStartup(void)
{
	main(0, PTR_NULL);
}
*/