#include <stdio.h>

#include <base/std_def.h>
#include <base/std_mem.h>
#include <base/mem_base.h>
#include <base/std_str.h>

#include <strs.h>
#include <tree.h>
#include <connect.h>
#include <http.h>
#include <upnp.h>
#include <mem_stream.h>
#include <tpo_mod.h>



mem_zone_ref		self_node  = { PTR_INVALID };
mem_zone_ref		peer_nodes = { PTR_INVALID };
hash_t				null_hash = { PTR_INVALID };
unsigned int		synching = { PTR_INVALID };
mem_zone_ref		node_config = { PTR_INVALID };
struct string		user_agent = { PTR_INVALID };;
unsigned int		node_port = PTR_INVALID, seed_port = PTR_INVALID;
struct string		node_port_str = { PTR_INVALID };
struct string		node_hostname = { PTR_INVALID };
tpo_mod_file		node_mod = { PTR_INVALID };

typedef int	C_API_FUNC node_init_self_func(mem_zone_ref_ptr out_self_node, unsigned short node_port, mem_zone_ref_ptr node_config);
typedef int	C_API_FUNC new_peer_node_func(struct host_def *host, mem_zone_ref_ptr peer_nodes);
typedef int	C_API_FUNC node_add_block_func(mem_zone_ref_ptr header, mem_zone_ref_ptr txs);
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

typedef node_init_self_func					 *_node_init_self_func_ptr;
typedef new_peer_node_func					 *_new_peer_node_func_ptr;
typedef node_add_block_func					 *_node_add_block_func_ptr;
typedef read_node_msg_func					 *_read_node_msg_func_ptr;
typedef send_node_messages_func				 *_send_node_messages_func_ptr;
typedef node_add_block_header_func			 *_node_add_block_header_func_ptr;
typedef queue_version_message_func			 *_queue_version_message_func_ptr;
typedef queue_verack_message_func			 *_queue_verack_message_func_ptr;
typedef queue_ping_message_func				 *_queue_ping_message_func_ptr;
typedef queue_pong_message_func				 *_queue_pong_message_func_ptr;
typedef queue_getaddr_message_func			 *_queue_getaddr_message_func_ptr;
typedef queue_getdata_message_func			 *_queue_getdata_message_func_ptr;
typedef queue_getblocks_message_func		 *_queue_getblocks_message_func_ptr;
typedef queue_getblock_hdrs_message_func	 *_queue_getblock_hdrs_message_func_ptr;
typedef queue_send_message_func				 *_queue_send_message_func_ptr;
typedef queue_emitted_element_func			 *_queue_emitted_element_func_ptr;
typedef queue_emitted_message_func			 *_queue_emitted_message_func_ptr;

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

#ifdef _DEBUG
C_IMPORT int			C_API_FUNC		node_init_self(mem_zone_ref_ptr out_self_node, unsigned short node_port, mem_zone_ref_ptr node_config);
C_IMPORT int			C_API_FUNC		new_peer_node(struct host_def *host, mem_zone_ref_ptr peer_nodes);
C_IMPORT int			C_API_FUNC		node_add_block(mem_zone_ref_ptr header, mem_zone_ref_ptr txs);
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
#else
node_init_self_func_ptr						node_init_self = PTR_INVALID;
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
#endif



C_IMPORT int			C_API_FUNC		get_hash_list(mem_zone_ref_ptr hdr_list, mem_zone_ref_ptr hash_list);
C_IMPORT int			C_API_FUNC		last_block_locator_index(mem_zone_ref_ptr node, mem_zone_ref_ptr hash_list);
C_IMPORT int			C_API_FUNC		block_locator_indexes(mem_zone_ref_ptr node, size_t top_height, mem_zone_ref_ptr hash_list);
C_IMPORT size_t		    C_API_FUNC		file_size(const char *path);

unsigned int			ping_nonce;

C_IMPORT 	int		C_API_FUNC append_file(const char *path, void *data, size_t data_len);
C_IMPORT		ctime_t	C_API_FUNC get_time_c();
C_IMPORT		ctime_t	C_API_FUNC daemonize();
C_IMPORT		int		C_API_FUNC get_file(const char *path, unsigned char **data, size_t *data_len);

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
	//queue_getblock_hdrs_message	(node);
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
int handle_block(mem_zone_ref_ptr node, mem_zone_ref_ptr payload)
{
	mem_zone_ref		header = { PTR_NULL }, tx_list = { PTR_NULL };
	int					ret;
	
	if (!tree_manager_find_child_node(payload, NODE_HASH("header"), NODE_BITCORE_BLK_HDR, &header))return 0;
	if (!tree_manager_find_child_node(payload, NODE_HASH("txs"), NODE_BITCORE_TX_LIST, &tx_list))return 0;

	ret=node_add_block	(&header, &tx_list);


	if (ret)
	{
		mem_zone_ref	log = { PTR_NULL };
		size_t			size;

		size = file_size("./blk_indexes") / 32;
		tree_manager_create_node("log", NODE_LOG_PARAMS, &log);
		tree_manager_set_child_value_i32(&log, "nblocks", size);
		log_message("block height : %nblocks%\n", &log);
		release_zone_ref(&log);
		tree_manager_set_child_value_i64(node, "next_check", get_time_c() + 10);
	}
	/*
	else
	{
		tree_manager_dump_node_rec(&header,0,5);
	}
	*/
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

int load_module(const char *file, const char *mod_name, tpo_mod_file *mod)
{
	mem_stream			mod_file;
	mem_zone_ref		tpo_file_data = { PTR_NULL };
	unsigned char		*data;
	size_t				data_len;

	if (get_file(file, &data, &data_len) <= 0)return 0;

	allocate_new_zone(0, data_len, &tpo_file_data);
	memcpy_c(get_zone_ptr(&tpo_file_data, 0), data, data_len);
	memset_c(&mod_file, 0, sizeof(mem_stream));
	mem_stream_init(&mod_file, &tpo_file_data, 0);
	tpo_mod_init(mod);
	tpo_mod_load_tpo(&mod_file, mod, 0);
	register_tpo_exports(mod, mod_name);
	release_zone_ref(&tpo_file_data);
	free_c(data);

	return 1;

}
void load_node_module()
{
	load_module("modz/node_adx.tpo", "node_adx", &node_mod);
#ifdef _DEBUG
	_node_init_self = get_tpo_mod_exp_addr_name(&node_mod, "node_init_self", 0);
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
	unsigned char		*data;
	struct host_def		*seed_host;
	size_t				data_len;

	tree_manager_init();

	load_node_module(&node_mod);

	node_port_str.str = PTR_NULL;
	node_port_str.len = 0;
	node_port_str.size = 0;

	node_hostname.str = PTR_NULL;
	node_hostname.len = 0;
	node_hostname.size = 0;

	node_config.zone = PTR_NULL;

	if (!read_config("config.json", &node_port_str, &node_hostname))
	{
		log_message("unable to load config\n", PTR_NULL);
		return 0;
	}

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



	memset_c(null_hash, 0, 32);

	self_node.zone = PTR_NULL;

	node_port = strtoul_c(node_port_str.str, PTR_NULL, 10);
	node_init_self(&self_node, node_port, &node_config);

	tree_manager_get_child_value_istr(&node_config, NODE_HASH("seed_node_host"), &node_hostname, 0);
	tree_manager_get_child_value_i32(&node_config, NODE_HASH("seed_node_port"), &seed_port);

	user_agent.str = PTR_NULL;
	tree_manager_get_child_value_istr(&node_config, NODE_HASH("name"), &user_agent, 0);

	peer_nodes.zone = PTR_NULL;
	tree_manager_create_node("peer nodes", NODE_BITCORE_NODE_LIST, &peer_nodes);
	seed_host = make_host_def(node_hostname.str, seed_port);
	if (!new_peer_node(seed_host, &peer_nodes))
	{
		free_string(&node_port_str);
		free_string(&node_hostname);
		free_host_def(seed_host);
		return 0;
	}
	free_host_def(seed_host);
	return 1;
}


OS_API_C_FUNC(int) app_start(mem_zone_ref_ptr params)
{
	mem_zone_ref		log = { PTR_NULL };
	mem_zone_ref		seed_node = { PTR_NULL };

	tree_manager_create_node("log", NODE_LOG_PARAMS, &log);
	tree_manager_set_child_value_i32(&log, "port", node_port);
	tree_manager_set_child_value_str(&log, "hostname", node_hostname.str);
	log_message("node port %port% open @ '%hostname%'", &log);
	release_zone_ref(&log);
	
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