//copyright iadix 2016
#include <base/std_def.h>
#include <base/std_mem.h>
#include <base/mem_base.h>
#include <base/std_str.h>

#include <sha256.h>
#include <strs.h>
#include <tree.h>

C_IMPORT ctime_t C_API_FUNC  get_time_c();

unsigned int		GETDATA_BLOCK		= 2;
unsigned int		magic				= 0xCDCDCDCD;
unsigned int		PROTOCOL_VERSION	= 0xCDCDCDCD;

hash_t				null_hash			= { 0xFF };
struct string		def_vstr			= { "empty" };
unsigned char		def_vint[5]			= { 0xFF };
unsigned char		null_vint			= 0xAB;
unsigned int		ping_nonce			= 1;

unsigned int NODE_HASH_txsout = 0xCDCDCDCD, NODE_HASH_script = 0xCDCDCDCD, NODE_HASH_txsin = 0xCDCDCDCD, NODE_HASH_version = 0xCDCDCDCD, NODE_HASH_prev = 0xCDCDCDCD, NODE_HASH_merkle_root = 0xCDCDCDCD, NODE_HASH_time = 0xCDCDCDCD, NODE_HASH_bits, NODE_HASH_nonce = 0xCDCDCDCD, NODE_HASH_services = 0xCDCDCDCD, NODE_HASH_addr = 0xCDCDCDCD, NODE_HASH_port = 0xCDCDCDCD, NODE_HASH_p2p_addr = 0xCDCDCDCD, NODE_HASH_locktime = 0xCDCDCDCD, NODE_HASH_tx_hash = 0xCDCDCDCD, NODE_HASH_value = 0xCDCDCDCD, NODE_HASH_sequence = 0xCDCDCDCD, NODE_HASH_idx = 0xCDCDCDCD, NODE_HASH_size = 0xCDCDCDCD, NODE_HASH_cmd = 0xCDCDCDCD, NODE_HASH_payload = 0xCDCDCDCD;
OS_API_C_FUNC(void) set_version(unsigned int inmagic, unsigned int version)
{
	memset_c(null_hash, 0, sizeof(hash_t));
	def_vstr.str = malloc_c(33);
	def_vstr.len = 32;
	def_vstr.size = 33;
	null_vint = 0;
	def_vint[0] = 0xFE;
	def_vint[1] = 0;
	def_vint[2] = 0;
	def_vint[3] = 0;
	def_vint[4] = 0;

	
	NODE_HASH_script = NODE_HASH("script");
	NODE_HASH_txsin = NODE_HASH("txsin");
	NODE_HASH_txsout = NODE_HASH("txsout");
	NODE_HASH_version = NODE_HASH("version");
	NODE_HASH_prev = NODE_HASH("prev");
	NODE_HASH_merkle_root = NODE_HASH("merkle_root");
	NODE_HASH_time = NODE_HASH("time");
	NODE_HASH_bits = NODE_HASH("bits");
	NODE_HASH_nonce = NODE_HASH("nonce");
	NODE_HASH_services = NODE_HASH("services");
	NODE_HASH_addr = NODE_HASH("addr");
	NODE_HASH_port = NODE_HASH("port");
	NODE_HASH_p2p_addr = NODE_HASH("p2p_addr");
	NODE_HASH_locktime = NODE_HASH("locktime");
	NODE_HASH_tx_hash = NODE_HASH("tx hash");
	NODE_HASH_value = NODE_HASH("value");
	NODE_HASH_sequence = NODE_HASH("sequence");
	NODE_HASH_idx = NODE_HASH("idx");
	NODE_HASH_size	= NODE_HASH("size");
	NODE_HASH_cmd	= NODE_HASH("cmd");
	NODE_HASH_payload = NODE_HASH("payload");
	magic			 = inmagic;
	PROTOCOL_VERSION = version;
}
OS_API_C_FUNC(void) get_version(unsigned int *inmagic, unsigned int *version)
{
	*inmagic=magic ;
	*version=PROTOCOL_VERSION;
}
OS_API_C_FUNC(int) add_bitcore_addr(mem_zone_ref_ptr node, ipv4_t ip, unsigned short port)
{
	uint64_t		services;
	mem_zone_ref	addr_node = { PTR_NULL };
	tree_manager_get_child_value_i64(node, NODE_HASH_services, &services);

	if (!tree_manager_find_child_node(node, NODE_HASH_p2p_addr, NODE_BITCORE_ADDR, &addr_node))
		tree_manager_add_child_node(node, "p2p_addr", NODE_BITCORE_ADDR, &addr_node);

	tree_manager_set_child_value_i64(&addr_node, "services", services);
	tree_manager_set_child_value_ipv4(&addr_node, "addr", ip);
	tree_manager_set_child_value_i16(&addr_node, "port", port);
	release_zone_ref(&addr_node);
	return 1;
}
OS_API_C_FUNC(size_t) init_node(mem_zone_ref_ptr key)
{
	mem_zone_ref my_list = { PTR_NULL };
	mem_zone_ref_ptr sub = PTR_NULL;
	unsigned short  port = 0xFFFF;
	ipv4_t			ip = { 0xFF };
	mem_zone_ref	vin = { PTR_NULL },	txin_list = { PTR_NULL };
	switch (tree_mamanger_get_node_type(key))
	{

	case NODE_GFX_INT:
		tree_manager_write_node_dword(key, 0, 0);
		break;
	case NODE_GFX_INT64:
		tree_manager_write_node_qword(key, 0, 0);
		break;
	case NODE_BITCORE_BLOCK_HASH:
	case NODE_BITCORE_HASH:
		tree_manager_write_node_hash(key, 0, null_hash);
		break;
	case NODE_BITCORE_VSTR:
		tree_manager_write_node_vstr(key, 0, &def_vstr);
		break;
	case NODE_BITCORE_VINT:
		tree_manager_write_node_vint(key, 0, &def_vint);
		break;
	case NODE_BITCORE_BLK_HDR:
		tree_manager_set_child_value_i32(key, "version", 0);
		tree_manager_set_child_value_hash(key, "prev", null_hash);
		tree_manager_set_child_value_hash(key, "merkle_root", null_hash);
		tree_manager_set_child_value_i32(key, "time", 0);
		tree_manager_set_child_value_i32(key, "bits", 0);
		tree_manager_set_child_value_i32(key, "nonce", 0);
	break;
	case NODE_BITCORE_ECDSA_SIG:
		tree_manager_write_node_byte(key, 0, 70);
		tree_manager_write_node_byte(key, 1, 0x30);
		tree_manager_write_node_byte(key, 2, 68);
		tree_manager_write_node_byte(key, 3, 0x02);
		tree_manager_write_node_byte(key, 4, 32);
		tree_manager_write_node_data(key, null_hash, 5, 32);
		tree_manager_write_node_byte(key, 37, 0x02);
		tree_manager_write_node_byte(key, 38, 32);
		tree_manager_write_node_data(key, null_hash, 39, 32);
	break;
	case NODE_BITCORE_TXIN:
		tree_manager_set_child_value_hash(key, "tx hash", null_hash);
		tree_manager_set_child_value_i32(key, "idx", 0xFFFFFFFF);
		tree_manager_set_child_value_vstr(key, "script", &def_vstr);
	break;
	case NODE_BITCORE_TXOUT:
		tree_manager_set_child_value_i64(key, "value", 0);
		tree_manager_set_child_value_vstr(key, "script", &def_vstr);
		break;
	case NODE_BITCORE_TX:
		tree_manager_set_child_value_i32(key, "version", 0);
		tree_manager_set_child_value_i32(key, "time", 0);
		
		if (!tree_manager_find_child_node(key, NODE_HASH_txsin, NODE_BITCORE_VINLIST, &txin_list))
			tree_manager_add_child_node(key, "txsin", NODE_BITCORE_VINLIST, &txin_list);
		
		tree_manager_add_child_node	(&txin_list, "txin", NODE_BITCORE_TXIN, &vin);
		init_node					(&vin);
		release_zone_ref			(&vin);
		release_zone_ref			(&txin_list);

		if (!tree_manager_find_child_node(key, NODE_HASH_txsout, NODE_BITCORE_VOUTLIST, &txin_list))
			tree_manager_add_child_node(key, "txsout", NODE_BITCORE_VOUTLIST, &txin_list);

		tree_manager_add_child_node (&txin_list, "txout", NODE_BITCORE_TXOUT, &vin);
		init_node					(&vin);
		release_zone_ref			(&vin);
		release_zone_ref			(&txin_list);


		tree_manager_set_child_value_i32(key, "locktime", 0);

		break;
	case NODE_BITCORE_TX_LIST:
		for (tree_manager_get_first_child(key, &my_list, &sub); ((sub != NULL) && (sub->zone != NULL)); tree_manager_get_next_child(&my_list, &sub))
		{
			init_node(sub);
		}
	break;
	case NODE_BITCORE_ADDR:
		tree_manager_set_child_value_i64(key, "services", 0);
		tree_manager_set_child_value_ipv4(key, "addr", ip);
		tree_manager_set_child_value_i16(key, "port", port);
		break;
	case NODE_BITCORE_ADDRT:
		tree_manager_set_child_value_i32(key, "time", 0);
		tree_manager_set_child_value_i64(key, "services", 0);
		tree_manager_set_child_value_ipv4(key, "addr", ip);
		tree_manager_set_child_value_i16(key, "port", port);
		break;


	}
	return 1;
}

OS_API_C_FUNC(size_t)	get_node_size(mem_zone_ref_ptr key)
{
	mem_zone_ref my_list = { PTR_NULL };
	mem_zone_ref_ptr sub = PTR_NULL;
	mem_zone_ref		txin_list = { PTR_NULL };
	size_t				szData, nc;
	unsigned char		*data;
	szData = 0;
	switch (tree_mamanger_get_node_type(key))
	{
	case NODE_GFX_INT:
		szData += 4;
		break;
	case NODE_GFX_INT64:
		szData += 8;
		break;
	case NODE_BITCORE_BLOCK_HASH:
	case NODE_BITCORE_HASH:
		szData += 32;
		break;
	case NODE_BITCORE_HASH_LIST:
		nc = tree_manager_get_node_num_children(key);
		if (nc < 0xFD)
			szData += 1;
		else if (nc < 0xFFFF)
			szData += 3;
		else
			szData += 5;

		szData += nc * 36;
	break;
	case NODE_BITCORE_ECDSA_SIG:
	{
		unsigned char sig_check,sig_len;
		tree_mamanger_get_node_byte (key, 1 , &sig_check);
		if (sig_check == 0x30)
		{
			tree_mamanger_get_node_byte(key, 0, &sig_len);
			szData += sig_len;
		}
	}
	break;
	case NODE_BITCORE_LOCATOR:

		nc = tree_manager_get_node_num_children(key);
		if (nc < 0xFD)
			szData += 1;
		else if (nc < 0xFFFF)
			szData += 3;
		else
			szData += 5;

		szData += nc * 32;
		break;
	case NODE_BITCORE_VSTR:
		data = tree_mamanger_get_node_data_ptr(key, 0);
		if (*data < 0xFD)
			szData += 1 + *data;
		else if ((*data) == 0xFD)
			szData += 3 + (*((unsigned short *)(data + 1)));
		else if ((*data) == 0xFE)
			szData += 5 + (*((unsigned int *)(data + 1)));
		else if ((*data) == 0xFF)
			szData += 9 + (*((uint64_t *)(data + 1)));
		break;
	case NODE_BITCORE_VINT:
		data = tree_mamanger_get_node_data_ptr(key, 0);
		if (*data < 0xFD)
			szData += 1;
		else if ((*data) == 0xFD)
			szData += 3;
		else if ((*data) == 0xFE)
			szData += 5;
		else if ((*data) == 0xFF)
			szData += 9;
		break;
	case NODE_BITCORE_BLK_HDR:
		szData += 82;
		break;
	case NODE_BITCORE_ADDR:
		szData += 26;
		break;
	case NODE_BITCORE_ADDRT:
		szData += 30;
		break;
	case NODE_BITCORE_TXIN:
		szData += 32;
		szData += 4;
		data = tree_manager_get_child_data(key, NODE_HASH_script, 0);

		if (data != PTR_NULL)
		{
			if (*data < 0xFD)
				szData += 1 + *data;
			else if ((*data) == 0xFD)
				szData += 3 + (*((unsigned short *)(data + 1)));
			else if ((*data) == 0xFE)
				szData += 5 + (*((unsigned int *)(data + 1)));
			else if ((*data) == 0xFF)
				szData += 9 + (*((uint64_t *)(data + 1)));
		}
		szData += 4;
		break;
	case NODE_BITCORE_TXOUT:
		szData += 8;
		data = tree_manager_get_child_data(key, NODE_HASH_script, 0);
		if (data==PTR_NULL)
			szData += 0;
		else if (*data < 0xFD)
			szData += 1 + *data;
		else if ((*data) == 0xFD)
			szData += 3 + (*((unsigned short *)(data + 1)));
		else if ((*data) == 0xFE)
			szData += 5 + (*((unsigned int *)(data + 1)));
		else if ((*data) == 0xFF)
			szData += 9 + (*((uint64_t *)(data + 1)));
		break;
	case NODE_BITCORE_VINLIST:
		nc = tree_manager_get_node_num_children(key);
		if (nc < 0xFD)
			szData += 1;
		else if (nc < 0xFFFF)
			szData += 3;
		else
			szData += 5;
		for (tree_manager_get_first_child(key, &my_list, &sub); ((sub != NULL) && (sub->zone != NULL)); tree_manager_get_next_child(&my_list, &sub))
		{
			szData += get_node_size(sub);
		}
		break;
	case NODE_BITCORE_VOUTLIST:
		nc = tree_manager_get_node_num_children(key);
		if (nc < 0xFD)
			szData += 1;
		else if (nc < 0xFFFF)
			szData += 3;
		else
			szData += 5;
		for (tree_manager_get_first_child(key, &my_list, &sub); ((sub != NULL) && (sub->zone != NULL)); tree_manager_get_next_child(&my_list, &sub))
		{
			szData += get_node_size(sub);
		}
		break;
	case NODE_BITCORE_TX:
		szData += 4;//version
		szData += 4;//time

		tree_manager_find_child_node(key, NODE_HASH_txsin, NODE_BITCORE_VINLIST, &txin_list);
		szData += get_node_size(&txin_list);
		release_zone_ref(&txin_list);

		tree_manager_find_child_node(key, NODE_HASH_txsout, NODE_BITCORE_VOUTLIST, &txin_list);
		szData += get_node_size(&txin_list);
		release_zone_ref(&txin_list);

		szData += 4;//lock time

	break;

	case NODE_BITCORE_TX_LIST:
		nc = tree_manager_get_node_num_children(key);
		if (nc < 0xFD)
			szData += 1;
		else if (nc < 0xFFFF)
			szData += 3;
		else
			szData += 5;
		for (tree_manager_get_first_child(key, &my_list, &sub); ((sub != NULL) && (sub->zone != NULL)); tree_manager_get_next_child(&my_list, &sub))
		{
			szData += get_node_size(sub);
		}
		
		break;
	}

	return szData;
}
OS_API_C_FUNC(size_t) compute_payload_size(mem_zone_ref_ptr payload_node)
{
	size_t				szData;
	mem_zone_ref_ptr	key = PTR_NULL;
	mem_zone_ref		my_list = { PTR_NULL };
	szData = 0;

	for (tree_manager_get_first_child(payload_node, &my_list, &key); ((key != NULL) && (key->zone != NULL)); tree_manager_get_next_child(&my_list, &key))
	{
		szData += get_node_size(key);
	}
	return szData;
}

OS_API_C_FUNC(char *) write_node(mem_zone_ref_const_ptr key, unsigned char *payload)
{
	mem_zone_ref txin_list = { PTR_NULL }, my_list = { PTR_NULL };
	mem_zone_ref_ptr sub = PTR_NULL;
	unsigned char *data;
	unsigned short port;
	ipv4_t			ip;
	unsigned int	nc;

	switch (tree_mamanger_get_node_type(key))
	{
	case NODE_GFX_INT:
		tree_mamanger_get_node_dword(key, 0, (unsigned int *)payload);
		payload += 4;
		break;
	case NODE_GFX_INT64:
		tree_mamanger_get_node_qword(key, 0, (uint64_t *)payload);
		payload += 8;
		break;
	case NODE_BITCORE_BLOCK_HASH:
	case NODE_BITCORE_HASH:
		tree_manager_get_node_hash(key, 0, (unsigned char *)payload);
		payload += 32;
		break;
	case NODE_BITCORE_HASH_LIST:
		nc = tree_manager_get_node_num_children(key);

		if (nc < 0xFD)
			*((unsigned char*)(payload++)) = nc;
		else if (nc < 0xFFFF)
		{
			*((unsigned char*)(payload++))  = 0xFD;
			*((unsigned short*)(payload))	= nc;
			payload += 2;
		}
		for (tree_manager_get_first_child(key, &my_list, &sub); ((sub != NULL) && (sub->zone != NULL)); tree_manager_get_next_child(&my_list, &sub))
		{
			if (tree_mamanger_get_node_type(sub) == NODE_BITCORE_BLOCK_HASH)
			{
				*((unsigned int *)(payload)) = GETDATA_BLOCK;
				payload += 4;
			}
			tree_manager_get_node_hash(sub, 0, (unsigned char *)(payload));
			payload += 32;
		}
		break;
	case NODE_BITCORE_LOCATOR:
		nc = tree_manager_get_node_num_children(key);

		if (nc < 0xFD)
			*((unsigned char*)(payload++)) = nc;
		else if (nc < 0xFFFF)
		{
			*((unsigned char*)(payload++)) = 0xFD;
			*((unsigned short*)(payload)) = nc;
			payload += 2;
		}
		else
		{
			*((unsigned char*)(payload++)) = 0xFE;
			*((unsigned int*)(payload)) = nc;
			payload += 4;
		}

		for (tree_manager_get_first_child(key, &my_list, &sub); ((sub != NULL) && (sub->zone != NULL)); tree_manager_get_next_child(&my_list, &sub))
		{
			tree_manager_get_node_hash(sub, 0, (unsigned char *)(payload));
			payload += 32;
		}
		break;
	case NODE_BITCORE_VSTR:
		payload += tree_manager_get_node_vstr(key, 0, payload);
		break;
	case NODE_BITCORE_VINT:
		data = tree_mamanger_get_node_data_ptr(key, 0);
		if (*data < 0xFD)
		{
			*(payload++) = *data;
		}
		else if (*data == 0xFD)
		{
			*(payload++) = *data;
			(*((unsigned short *)(payload))) = (*((unsigned short *)(data + 1)));
			payload += 2;
		}
		else if (*data == 0xFE)
		{
			*(payload++) = *data;
			(*((unsigned int *)(payload))) = (*((unsigned int *)(data + 1)));
			payload += 4;
		}
		else if (*data == 0xFF)
		{
			*(payload++) = *data;
			(*((uint64_t *)(payload))) = (*((uint64_t *)(data + 1)));
			payload += 8;
		}
	break;
	case NODE_BITCORE_BLK_HDR:


		tree_manager_get_child_value_i32(key, NODE_HASH_version		, (unsigned int *)(payload));
		payload = mem_add(payload, 4);
		tree_manager_get_child_value_hash(key, NODE_HASH_prev		, (unsigned char *)(payload));
		payload = mem_add(payload, 32);
		tree_manager_get_child_value_hash(key, NODE_HASH_merkle_root	, ((unsigned char *)(payload)));
		payload = mem_add(payload, 32);
		tree_manager_get_child_value_i32(key, NODE_HASH_time			, ((unsigned int *)(payload)));
		payload = mem_add(payload, 4);
		tree_manager_get_child_value_i32(key, NODE_HASH_bits			, ((unsigned int *)(payload)));
		payload = mem_add(payload, 4);
		tree_manager_get_child_value_i32(key, NODE_HASH_nonce		, ((unsigned int *)(payload)));
		payload = mem_add(payload, 4);
	break;
	case NODE_BITCORE_ADDR:
		tree_manager_get_child_value_i64(key, NODE_HASH_services, (uint64_t *)payload);
		tree_manager_get_child_value_ipv4(key, NODE_HASH_addr, ip);
		tree_manager_get_child_value_i16(key, NODE_HASH_port, &port);
		payload += 8;

		*((uint64_t	*)(payload)) = 0x0;		//(12 bytes 00 00 00 00 00 00 00 00 00 00 FF FF, followed by the 4 bytes of the IPv4 address).
		payload += 8;
		*((unsigned int	*)(payload)) = 0xFFFF0000;
		payload += 4;
		*((unsigned char*)(payload + 0)) = ip[0];
		*((unsigned char*)(payload + 1)) = ip[1];
		*((unsigned char*)(payload + 2)) = ip[2];
		*((unsigned char*)(payload + 3)) = ip[3];
		payload += 4;
		*((unsigned char*)(payload + 0)) = (unsigned char)(port >> 8);
		*((unsigned char*)(payload + 1)) = (unsigned char)(port & 0xFF);
		payload += 2;
	break;
	case NODE_BITCORE_ADDRT:
		tree_manager_get_child_value_i32(key, NODE_HASH_time, (unsigned int*)payload);
		payload += 4;
		tree_manager_get_child_value_i64(key, NODE_HASH_services, (uint64_t *)payload);
		payload += 8;

		tree_manager_get_child_value_ipv4(key, NODE_HASH_addr, ip);
		tree_manager_get_child_value_i16(key, NODE_HASH_port, &port);

		*((uint64_t	*)(payload)) = 0x0;		//(12 bytes 00 00 00 00 00 00 00 00 00 00 FF FF, followed by the 4 bytes of the IPv4 address).
		payload += 8;
		*((unsigned int	*)(payload)) = 0xFFFF0000;
		payload += 4;
		*((unsigned char*)(payload + 0)) = ip[0];
		*((unsigned char*)(payload + 1)) = ip[1];
		*((unsigned char*)(payload + 2)) = ip[2];
		*((unsigned char*)(payload + 3)) = ip[3];
		payload += 4;
		*((unsigned char*)(payload + 0)) = (unsigned char)(port >> 8);
		*((unsigned char*)(payload + 1)) = (unsigned char)(port & 0xFF);
		payload += 2;
		break;
	case NODE_BITCORE_TXIN:
		tree_manager_get_child_value_hash			(key, NODE_HASH_tx_hash		, payload);
		payload += 32;
		tree_manager_get_child_value_i32			(key, NODE_HASH_idx			, (unsigned int *)payload);
		payload += 4;
		payload += tree_manager_get_child_value_vstr(key, NODE_HASH_script		, payload);
		tree_manager_get_child_value_i32			(key, NODE_HASH_sequence		, (unsigned int *)payload);
		payload += 4;
	break;
	case NODE_BITCORE_TXOUT:
		tree_manager_get_child_value_i64			(key, NODE_HASH_value, (uint64_t *)payload);
		payload += 8;
		payload += tree_manager_get_child_value_vstr(key, NODE_HASH_script, payload);
	break;
	case NODE_BITCORE_VINLIST:
		nc = tree_manager_get_node_num_children(key);

		if (nc < 0xFD)
			*((unsigned char*)(payload++)) = nc;
		else if (nc < 0xFFFF)
		{
			*((unsigned char*)(payload++)) = 0xFD;
			*((unsigned short*)(payload)) = nc;
			payload += 2;
		}
		else
		{
			*((unsigned char*)(payload++)) = 0xFE;
			*((unsigned int*)(payload)) = nc;
			payload += 4;
		}

		for (tree_manager_get_first_child(key, &my_list, &sub); ((sub != NULL) && (sub->zone != NULL)); tree_manager_get_next_child(&my_list, &sub))
		{
			payload = write_node(sub, payload);
		}
	break;
	case NODE_BITCORE_VOUTLIST:
		nc = tree_manager_get_node_num_children(key);

		if (nc < 0xFD)
			*((unsigned char*)(payload++)) = nc;
		else if (nc < 0xFFFF)
		{
			*((unsigned char*)(payload++)) = 0xFD;
			*((unsigned short*)(payload)) = nc;
			payload += 2;
		}
		else
		{
			*((unsigned char*)(payload++)) = 0xFE;
			*((unsigned int*)(payload)) = nc;
			payload += 4;
		}


		for (tree_manager_get_first_child(key, &my_list, &sub); ((sub != NULL) && (sub->zone != NULL)); tree_manager_get_next_child(&my_list, &sub))
		{
			payload = write_node(sub, payload);
		}
	break;
		case NODE_BITCORE_TX:
		tree_manager_get_child_value_i32(key, NODE_HASH_version, (unsigned int*)payload);
		payload += 4;
		tree_manager_get_child_value_i32(key, NODE_HASH_time, (unsigned int *)payload);
		payload += 4;

		tree_manager_find_child_node	(key, NODE_HASH_txsin, NODE_BITCORE_VINLIST, &txin_list);
		payload = write_node(&txin_list,payload);
		release_zone_ref(&txin_list);

		tree_manager_find_child_node(key, NODE_HASH_txsout, NODE_BITCORE_VOUTLIST, &txin_list);
		payload = write_node(&txin_list, payload);
		release_zone_ref(&txin_list);

		tree_manager_get_child_value_i32(key, NODE_HASH_locktime, (unsigned int *)payload);
		payload += 4;

	break;
	case NODE_BITCORE_TX_LIST:
		nc = tree_manager_get_node_num_children(key);

		if (nc < 0xFD)
			*((unsigned char*)(payload++)) = nc;
		else if (nc < 0xFFFF)
		{
			*((unsigned char*)(payload++)) = 0xFD;
			*((unsigned short*)(payload)) = nc;
			payload += 2;
		}
		else
		{
			*((unsigned char*)(payload++)) = 0xFE;
			*((unsigned int*)(payload)) = nc;
			payload += 4;
		}
		for (tree_manager_get_first_child(key, &my_list, &sub); ((sub != NULL) && (sub->zone != NULL)); tree_manager_get_next_child(&my_list, &sub))
		{
			payload = write_node(sub, payload);
		}
		
		break;
	}
	
	return payload;
}


OS_API_C_FUNC(const unsigned char *)read_node(mem_zone_ref_ptr key, const unsigned char *payload)
{
	unsigned int		n, nc;
	mem_zone_ref		txin_list = { PTR_NULL }, my_list = { PTR_NULL };
	mem_zone_ref_ptr	sub = PTR_NULL;
	struct string		str;
	unsigned short		port;
	size_t				sz;
	ipv4_t				ip;

	switch (tree_mamanger_get_node_type(key))
	{
	case NODE_GFX_INT:
		tree_manager_write_node_dword(key, 0, *((unsigned int *)(payload)));
		payload = mem_add(payload, 4);
		break;
	case NODE_GFX_INT64:
		tree_manager_write_node_qword(key, 0, *((uint64_t *)(payload)));
		payload = mem_add(payload, 8);
		break;
	case NODE_BITCORE_BLOCK_HASH:
	case NODE_BITCORE_HASH:
		tree_manager_write_node_hash(key, 0, ((unsigned char *)(payload)));
		payload = mem_add(payload, 32);
		break;
	case NODE_BITCORE_LOCATOR:
		if (*payload < 0xFD)
			nc = *(payload++);
		else if (*payload == 0xFD)
		{
			payload++;
			nc = *((unsigned short *)(payload));
			payload += 2;
		}
		else if (*payload < 0xFE)
		{
			payload++;
			nc = *((unsigned int *)(payload));
			payload += 4;
		}
		else if (*payload < 0xFF)
		{
			payload++;
			nc = *((uint64_t *)(payload));
			payload += 8;
		}
		n = 0;
		while (n<nc)
		{
			mem_zone_ref ssub = { PTR_NULL };

			if (!tree_manager_get_child_at(key, n, &ssub))
				tree_manager_add_child_node(key, "hash", NODE_BITCORE_HASH, &ssub);

			tree_manager_write_node_hash(&ssub, 0, (unsigned char *)(payload));
			release_zone_ref(&ssub);
			payload += 32;
		}
		break;
	case NODE_BITCORE_HASH_LIST:
		if (*payload < 0xFD)
			nc = *(payload++);
		else if (*payload == 0xFD)
		{
			payload++;
			nc = *((unsigned short *)(payload));
			payload += 2;
		}
		else if (*payload < 0xFE)
		{
			payload++;
			nc = *((unsigned int *)(payload));
			payload += 4;
		}
		else if (*payload < 0xFF)
		{
			payload++;
			nc = *((uint64_t *)(payload));
			payload += 8;
		}
		n = 0;
		while (n<nc)
		{
			mem_zone_ref ssub = { PTR_NULL };
			unsigned int type = NODE_BITCORE_HASH;

			if (*((unsigned int *)(payload)) == GETDATA_BLOCK)
			{
				type	= NODE_BITCORE_BLOCK_HASH;
				payload += 4;
			}

			if (!tree_manager_get_child_at(key, n, &ssub))
				tree_manager_add_child_node(key, "hash", type, &ssub);

			tree_manager_write_node_hash(&ssub, 0, (unsigned char *)(payload));
			release_zone_ref(&ssub);
			payload += 32;
			n++;
		}
		break;
	case NODE_BITCORE_VSTR:
		if (*((unsigned char *)(payload))< 0xFD)
			sz = (*((unsigned char *)(payload))) + 1;

		else if (*((unsigned char *)(payload)) == 0xFD)
			sz = (*((unsigned short *)(mem_add(payload, 1)))) + 3;

		else if (*((unsigned char *)(payload)) == 0xFE)
			sz = (*((unsigned int *)(mem_add(payload, 1)))) + 5;

		else if (*((unsigned char *)(payload)) == 0xFF)
			sz = (*((uint64_t *)(mem_add(payload, 1)))) + 9;

		tree_manager_write_node_data(key, payload, 0, sz);
		payload = mem_add(payload, sz);
		break;
	case NODE_BITCORE_VINT:
		if (*((unsigned char *)(payload))< 0xFD)
			sz = 1;
		else if (*((unsigned char *)(payload)) == 0xFD)
			sz = 3;
		else if (*((unsigned char *)(payload)) == 0xFE)
			sz = 5;
		else if (*((unsigned char *)(payload)) == 0xFF)
			sz =  9;
		tree_manager_write_node_data(key, payload, 0, sz);
		payload = mem_add(payload, sz);
		break;
	case NODE_BITCORE_ECDSA_SIG:
		if (*((unsigned char *)(mem_add(payload,1))) == 0x30)
		{
			unsigned char rlen, slen;
			payload = mem_add(payload, 1);
			tree_manager_write_node_byte(key, 0, *((unsigned char *)(payload)));payload = mem_add(payload, 1);
			tree_manager_write_node_byte(key, 1, *((unsigned char *)(payload)));payload = mem_add(payload, 1);
			tree_manager_write_node_byte(key, 2, *((unsigned char *)(payload)));payload = mem_add(payload, 1);
			rlen	= *((unsigned char *)(payload));
			tree_manager_write_node_byte(key, 3, rlen); payload = mem_add(payload, 1);
			tree_manager_write_node_data(key, payload, 4, rlen);
			payload = mem_add(payload, rlen);
			tree_manager_write_node_byte(key, rlen + 4, *((unsigned char *)(payload)));payload = mem_add(payload, 1);
			slen   = *((unsigned char *)(payload));
			tree_manager_write_node_byte(key, rlen + 5, slen); payload = mem_add(payload, 1);
			tree_manager_write_node_data(key, payload, rlen + 6, slen); payload = mem_add(payload, slen);
		}
	break;
	case NODE_BITCORE_BLK_HDR:
		tree_manager_set_child_value_i32(key, "version"		, *((unsigned int *)(payload)));
		payload = mem_add(payload, 4);
		tree_manager_set_child_value_hash(key, "prev", ((unsigned char *)(payload)));
		payload = mem_add(payload, 32);
		tree_manager_set_child_value_hash(key, "merkle_root", ((unsigned char *)(payload)));
		payload = mem_add(payload, 32);
		tree_manager_set_child_value_i32(key, "time"		, *((unsigned int *)(payload)));
		payload = mem_add(payload, 4);
		tree_manager_set_child_value_i32(key, "bits"		, *((unsigned int *)(payload)));
		payload = mem_add(payload, 4);
		tree_manager_set_child_value_i32(key, "nonce"		, *((unsigned int *)(payload)));
		payload = mem_add(payload, 4);
//		*((unsigned char *)(payload++)) = 0;
		//tree_manager_set_child_value_vint(key, "txcnt"		, payload);//1	txn_count	var_int	Number of transaction entries, this value is always 0
		//payload = mem_add(payload, 1);	
		break;
	case NODE_BITCORE_ADDR:
		tree_manager_set_child_value_i64(key, "services", *((uint64_t *)(payload)));
		payload = mem_add(payload, 8);
		//(12 bytes 00 00 00 00 00 00 00 00 00 00 FF FF, followed by the 4 bytes of the IPv4 address).
		ip[0] = *((unsigned char*)(mem_add(payload, 12)));
		ip[1] = *((unsigned char*)(mem_add(payload, 13)));
		ip[2] = *((unsigned char*)(mem_add(payload, 14)));
		ip[3] = *((unsigned char*)(mem_add(payload, 15)));
		payload = mem_add(payload, 16);
		port = ((*((unsigned char*)(payload))) << 8) | (*((unsigned char*)(mem_add(payload, 1))));
		payload = mem_add(payload, 2);

		tree_manager_set_child_value_ipv4(key, "addr", ip);
		tree_manager_set_child_value_i16(key, "port", port);

		break;
	case NODE_BITCORE_ADDRT:
		tree_manager_set_child_value_i32(key, "time"	, *((unsigned int *)(payload)));
		payload = mem_add(payload, 4);
		tree_manager_set_child_value_i64(key, "services", *((uint64_t *)(payload)));
		payload = mem_add(payload, 8);
		//(12 bytes 00 00 00 00 00 00 00 00 00 00 FF FF, followed by the 4 bytes of the IPv4 address).
		ip[0] = *((unsigned char*)(mem_add(payload, 12)));
		ip[1] = *((unsigned char*)(mem_add(payload, 13)));
		ip[2] = *((unsigned char*)(mem_add(payload, 14)));
		ip[3] = *((unsigned char*)(mem_add(payload, 15)));
		payload = mem_add(payload, 16);
		port = ((*((unsigned char*)(payload))) << 8) | (*((unsigned char*)(mem_add(payload, 1))));
		payload = mem_add(payload, 2);

		tree_manager_set_child_value_ipv4(key, "addr", ip);
		tree_manager_set_child_value_i16(key, "port", port);
	break;
	case NODE_BITCORE_TXIN:

		tree_manager_set_child_value_hash(key, "tx hash", payload);
		payload += 32;
		tree_manager_set_child_value_i32(key, "idx", *((unsigned int *)payload));
		payload += 4;

		if (*((unsigned char *)(payload)) < 0xFD)
		{
			str.len = (*((unsigned char *)(payload)));
			sz = 1;
		}
		else if (*((unsigned char *)(payload)) == 0xFD)
		{
			str.len = (*((unsigned short *)(mem_add(payload, 1))));
			sz = 3;
		}
		else if (*((unsigned char *)(payload)) == 0xFE)
		{
			str.len = (*((unsigned int *)(mem_add(payload, 1))));
			sz = 5;
		}
		else if (*((unsigned char *)(payload)) == 0xFF)
		{
			str.len = (*((uint64_t *)(mem_add(payload, 1))));
			sz = 9;
		}
		str.size = str.len + 1;

		if (str.len > 0)
			str.str = mem_add(payload, sz);
		else
			str.str = PTR_NULL;

		tree_manager_set_child_value_vstr(key, "script", &str);
		payload = mem_add(payload, str.len + sz);
		
		tree_manager_set_child_value_i32(key, "sequence", *((unsigned int *)payload));
		payload += 4;
		break;
	case NODE_BITCORE_TXOUT:
		tree_manager_set_child_value_i64(key, "value", *((uint64_t *)payload));
		payload += 8;
		if (*((unsigned char *)(payload)) < 0xFD)
		{
			str.len = (*((unsigned char *)(payload)));
			sz = 1;
		}
		else if (*((unsigned char *)(payload)) == 0xFD)
		{
			str.len = (*((unsigned short *)(mem_add(payload, 1))));
			sz = 3;
		}
		else if (*((unsigned char *)(payload)) == 0xFE)
		{
			str.len = (*((unsigned int *)(mem_add(payload, 1))));
			sz = 5;
		}
		else if (*((unsigned char *)(payload)) == 0xFF)
		{
			str.len = (*((uint64_t *)(mem_add(payload, 1))));
			sz = 9;
		}
		if (str.len > 0)
		{
			str.size = str.len + 1;
			str.str = mem_add(payload, sz);
			tree_manager_set_child_value_vstr(key, "script", &str);
		}
		else
		{
			struct string null_str;
			null_str.str = PTR_NULL;
			null_str.len = 0;
			null_str.size = 0;
			
			tree_manager_set_child_value_vstr(key, "script", &null_str);
		}
		payload = mem_add(payload, str.len + sz);
		break;
	case NODE_BITCORE_VINLIST:
		if (*payload < 0xFD)
			nc = *(payload++);
		else if (*payload == 0xFD)
		{
			payload++;
			nc = *((unsigned short *)(payload));
			payload += 2;
		}
		else if (*payload < 0xFE)
		{
			payload++;
			nc = *((unsigned int *)(payload));
			payload += 4;
		}
		else if (*payload < 0xFF)
		{
			payload++;
			nc = *((uint64_t *)(payload));
			payload += 8;
		}
		n = 0;
		while (n<nc)
		{
			mem_zone_ref ssub = { PTR_NULL };

			if (!tree_manager_get_child_at(key, n, &ssub))
				tree_manager_add_child_node(key, "txin", NODE_BITCORE_TXIN, &ssub);

			payload = read_node(&ssub, payload);
			release_zone_ref(&ssub);
			n++;
		}
	break;
	case NODE_BITCORE_VOUTLIST:
		if (*payload < 0xFD)
			nc = *(payload++);
		else if (*payload == 0xFD)
		{
			payload++;
			nc = *((unsigned short *)(payload));
			payload += 2;
		}
		else if (*payload < 0xFE)
		{
			payload++;
			nc = *((unsigned int *)(payload));
			payload += 4;
		}
		else if (*payload < 0xFF)
		{
			payload++;
			nc = *((uint64_t *)(payload));
			payload += 8;
		}
		n = 0;
		while (n<nc)
		{
			mem_zone_ref ssub = { PTR_NULL };

			if (!tree_manager_get_child_at(key, n, &ssub))
				tree_manager_add_child_node(key, "txout", NODE_BITCORE_TXOUT, &ssub);

			payload = read_node(&ssub, payload);
			release_zone_ref(&ssub);
			n++;
		}
		break;
	case NODE_BITCORE_TX:
		tree_manager_set_child_value_i32(key, "version", *((unsigned int *)payload));
		payload += 4;
		tree_manager_set_child_value_i32(key, "time", *((unsigned int *)payload));
		payload += 4;

		tree_manager_find_child_node(key, NODE_HASH_txsin, NODE_BITCORE_VINLIST, &txin_list);
		payload = read_node( &txin_list,payload);
		release_zone_ref(&txin_list);

		tree_manager_find_child_node(key, NODE_HASH_txsout, NODE_BITCORE_VOUTLIST, &txin_list);
		payload = read_node(&txin_list, payload);
		release_zone_ref(&txin_list);

		tree_manager_set_child_value_i32(key, "locktime", *((unsigned int *)payload));
		payload += 4;

	break;

	case NODE_BITCORE_TX_LIST:

		if (*((unsigned char *)(payload)) < 0xFD)
			sz = 1;
		else if (*((unsigned char *)(payload)) == 0xFD)
			sz = 3;
		else if (*((unsigned char *)(payload)) == 0xFE)
			sz = 5;
		else if (*((unsigned char *)(payload)) == 0xFF)
			sz = 9;

		payload = mem_add(payload, sz);

		for (tree_manager_get_first_child(key, &my_list, &sub); ((sub != NULL) && (sub->zone != NULL)); tree_manager_get_next_child(&my_list, &sub))
		{
			payload =read_node(sub,payload);
		}

		break;
	}
	return payload;
}

OS_API_C_FUNC(int) unserialize_message(mem_zone_ref_ptr msg, const_mem_ptr payload, const char *model)
{
	mem_zone_ref		payload_node = { PTR_NULL };
	mem_zone_ref		my_list = { PTR_NULL };
	mem_zone_ref_ptr	key;
	size_t				szData;
	int					created=0;
	
	if (payload == PTR_NULL)return 0;
	if (!tree_manager_get_child_value_i32(msg, NODE_HASH_size, &szData))return 0;
	if (szData == 0)return 0;

	tree_manager_find_child_node(msg, NODE_HASH_payload, NODE_BITCORE_PAYLOAD, &payload_node);

	if (payload_node.zone == PTR_NULL)
	{
		if (!tree_manager_json_loadb(model, strlen_c(model), &payload_node))return 0;
		created = 1;
	}
	
	for (tree_manager_get_first_child(&payload_node, &my_list, &key); ((key != NULL) && (key->zone != NULL)); tree_manager_get_next_child(&my_list, &key))
	{
		unsigned int type = tree_mamanger_get_node_type(key);
		if (type == NODE_BITCORE_ADDR_LIST)
		{
			mem_zone_ref		addr_list = { PTR_NULL };
			mem_zone_ref_ptr	addr=PTR_NULL;

			for (tree_manager_get_first_child(key, &addr_list, &addr); ((addr != NULL) && (addr->zone != NULL)); tree_manager_get_next_child(&addr_list, &addr))
			{
				payload = read_node(addr, payload);
			}
		}
		else
				payload = read_node(key, payload);
	}
	if (created==1)
		tree_manager_node_add_child		(msg, &payload_node);

	release_zone_ref				(&payload_node);
	return 1;
}

OS_API_C_FUNC(void) serialize_children(mem_zone_ref_ptr node, unsigned char *payload)
{
	mem_zone_ref_ptr	key;
	mem_zone_ref		my_list = { PTR_NULL };

	for (tree_manager_get_first_child(node, &my_list, &key); ((key != NULL) && (key->zone != NULL)); tree_manager_get_next_child(&my_list, &key))
	{
		payload = write_node(key, payload);
	}
}

OS_API_C_FUNC(char *) serialize_message(mem_zone_ref_ptr msg)
{
	mem_zone_ref		payload_node = { PTR_NULL };
	char				cmd_node[12];
	mem_zone_ref		my_list = { PTR_NULL };
	size_t				szData;
	unsigned char		*buffer, *payload;
	unsigned char		checksum1[32];
	unsigned char		checksum[32];

	if (!tree_manager_get_child_value_i32(msg, NODE_HASH_size, &szData))return PTR_NULL;
	if (!tree_manager_get_child_value_str(msg, NODE_HASH_cmd, cmd_node, 12, 16))return PTR_NULL;
	
	buffer = calloc_c(24 + szData, 1);
	if (buffer == PTR_NULL)
		return PTR_NULL;

	memcpy_c(buffer, &magic, 4);
	
	memset_c	(&buffer[4], 0, 12);
	strcpy_cs	(&buffer[4], 12, cmd_node);

	memcpy_c	(&buffer[16], &szData, 4);

	if ((szData > 0) && tree_manager_find_child_node(msg, NODE_HASH_payload, NODE_BITCORE_PAYLOAD, &payload_node))
	{
		payload = buffer + 4 + 12 + 4 + 4;

		serialize_children(&payload_node, payload);
		payload = buffer + 4 + 12 + 4 + 4;
		mbedtls_sha256(payload, szData, checksum1, 0);
		mbedtls_sha256(checksum1, 32, checksum, 0);
		memcpy_c(&buffer[20], checksum, 4);
		release_zone_ref(&payload_node);
	}
	else
	{
		/*mbedtls_sha256(PTR_NULL, 0, checksum1, 0);
		mbedtls_sha256(checksum1, 32, checksum, 0);*/
		buffer[20] = 0x5D;
		buffer[21] = 0xF6;
		buffer[22] = 0xE0;
		buffer[23] = 0xE2; 
	}

	
	
	return buffer;
}

OS_API_C_FUNC(int) create_verack_message(mem_zone_ref_ptr node, mem_zone_ref_ptr ver_pack)
{
	tree_manager_create_node		("message", NODE_BITCORE_MSG, ver_pack);
	tree_manager_set_child_value_str(ver_pack, "cmd", "verack");
	tree_manager_set_child_value_i32(ver_pack, "size", 0);
	tree_manager_set_child_value_i32(ver_pack, "sent", 0);



	return 1;
}

OS_API_C_FUNC(int) create_getdata_message(mem_zone_ref_ptr node, mem_zone_ref_ptr hash_list, mem_zone_ref_ptr blk_hdr_pack)
{
	mem_zone_ref		inv_vec = { PTR_NULL }, payload = { PTR_NULL }, nhashl = { PTR_NULL };
	size_t				pl_size;
	int					cnt;

	tree_manager_create_node("message", NODE_BITCORE_MSG, blk_hdr_pack);
	tree_manager_set_child_value_str(blk_hdr_pack, "cmd", "getdata");

	cnt = tree_manager_get_node_num_children(hash_list);

	tree_manager_add_child_node		(blk_hdr_pack, "payload", NODE_BITCORE_PAYLOAD, &payload);
	tree_manager_add_child_node		(&payload, "hash list", NODE_BITCORE_HASH_LIST, &nhashl);
	tree_manager_copy_children_ref	(&nhashl, hash_list);
	release_zone_ref				(&nhashl);
	pl_size = compute_payload_size  (&payload);
	release_zone_ref				(&payload);
	cnt = tree_manager_get_node_num_children(hash_list);

	tree_manager_set_child_value_i32(blk_hdr_pack, "size", pl_size);
	tree_manager_set_child_value_i32(blk_hdr_pack, "sent", 0);

	return 1;
}
OS_API_C_FUNC(int) create_getheaders_message(mem_zone_ref_ptr node, mem_zone_ref_ptr blk_locator,hash_t hashstop, mem_zone_ref_ptr blk_hdr_pack)
{
	mem_zone_ref		payload = { PTR_NULL };
	size_t				pl_size;
	int					n,cnt;
	
	tree_manager_create_node("message", NODE_BITCORE_MSG, blk_hdr_pack);
	tree_manager_set_child_value_str (blk_hdr_pack, "cmd", "getheaders");

	cnt = tree_manager_get_node_num_children(blk_locator);

	tree_manager_add_child_node				(blk_hdr_pack, "payload", NODE_BITCORE_PAYLOAD, &payload);
	tree_manager_set_child_value_i32		(&payload, "version", PROTOCOL_VERSION);
	tree_manager_set_child_value_vint32		(&payload, "count", cnt);
	for (n = 0; n < cnt;n++)
	{
		mem_zone_ref hash_node = { PTR_NULL }, loc = { PTR_NULL };
		if (tree_manager_get_child_at(blk_locator, n, &hash_node))
		{
			tree_manager_node_dup(&payload, &hash_node, &loc);
			release_zone_ref(&loc);
			release_zone_ref(&hash_node);
		}

	}
	tree_manager_set_child_value_hash(&payload, "hashstop", hashstop);

	pl_size = compute_payload_size(&payload);
	release_zone_ref(&payload);

	tree_manager_set_child_value_i32(blk_hdr_pack, "size", pl_size);
	tree_manager_set_child_value_i32(blk_hdr_pack, "sent", 0);

	return 1;

}
OS_API_C_FUNC(int) create_getblocks_message(mem_zone_ref_ptr node, mem_zone_ref_ptr blk_locator, mem_zone_ref_ptr getblk_pack)
{
	mem_zone_ref		payload = { PTR_NULL };
	size_t				pl_size;
	int					cnt;

	if (!tree_manager_create_node("message", NODE_BITCORE_MSG, getblk_pack))return 0;


	cnt = tree_manager_get_node_num_children(blk_locator);

	tree_manager_set_child_value_str(getblk_pack, "cmd", "getblocks");
	tree_manager_add_child_node(getblk_pack, "payload", NODE_BITCORE_PAYLOAD, &payload);
	tree_manager_set_child_value_i32(&payload, "version", PROTOCOL_VERSION);
	tree_manager_node_add_child(&payload, blk_locator);
	tree_manager_set_child_value_hash(&payload, "hashstop", null_hash);
	pl_size = compute_payload_size(&payload);
	release_zone_ref(&payload);
	tree_manager_get_node_num_children(blk_locator);
	tree_manager_set_child_value_i32(getblk_pack, "size", pl_size);
	tree_manager_set_child_value_i32(getblk_pack, "sent", 0);

	return 1;

}
OS_API_C_FUNC(int) create_inv_message(mem_zone_ref_ptr node, mem_zone_ref_ptr hash_list, mem_zone_ref_ptr inv_pack)
{
	mem_zone_ref		payload = { PTR_NULL };
	size_t				pl_size;
	int					cnt;

	if (!tree_manager_create_node("message", NODE_BITCORE_MSG, inv_pack))return 0;


	cnt = tree_manager_get_node_num_children(hash_list);

	tree_manager_set_child_value_str	(inv_pack, "cmd", "inv");
	tree_manager_add_child_node			(inv_pack, "payload", NODE_BITCORE_PAYLOAD, &payload);
	tree_manager_node_add_child			(&payload, hash_list);
	pl_size = compute_payload_size(&payload);
	release_zone_ref(&payload);
	tree_manager_get_node_num_children(hash_list);
	tree_manager_set_child_value_i32(inv_pack, "size", pl_size);
	tree_manager_set_child_value_i32(inv_pack, "sent", 0);

	return 1;

}

OS_API_C_FUNC(int) create_block_message(mem_zone_ref_ptr node, mem_zone_ref_ptr header, mem_zone_ref_ptr tx_list, struct string *signature, mem_zone_ref_ptr block_pack)
{
	mem_zone_ref		payload = { PTR_NULL };
	size_t				pl_size;
	int					cnt;

	if (!tree_manager_create_node("message", NODE_BITCORE_MSG, block_pack))return 0;

	cnt = tree_manager_get_node_num_children(tx_list);

	tree_manager_set_child_value_str(block_pack, "cmd", "block");
	tree_manager_add_child_node(block_pack, "payload", NODE_BITCORE_PAYLOAD, &payload);
	tree_manager_node_add_child		 (&payload, header);
	tree_manager_node_add_child		 (&payload, tx_list);
	tree_manager_set_child_value_vstr(&payload, "signature", signature);

	pl_size = compute_payload_size(&payload);
	release_zone_ref(&payload);
	tree_manager_get_node_num_children(tx_list);
	tree_manager_set_child_value_i32(block_pack, "size", pl_size);
	tree_manager_set_child_value_i32(block_pack, "sent", 0);

	return 1;

}
OS_API_C_FUNC(int) create_getaddr_message(mem_zone_ref_ptr node, mem_zone_ref_ptr addr_pack)
{
	tree_manager_create_node("message", NODE_BITCORE_MSG, addr_pack);
	tree_manager_set_child_value_str(addr_pack, "cmd", "getaddr");
	tree_manager_set_child_value_i32(addr_pack, "size", 0);
	tree_manager_set_child_value_i32(addr_pack, "sent", 0);
	return 1;
}

OS_API_C_FUNC(int) create_ping_message(mem_zone_ref_ptr node, uint64_t nonce, mem_zone_ref_ptr ver_pack)
{
	mem_zone_ref		payload = { PTR_NULL };
	size_t				pl_size;

	tree_manager_create_node("message", NODE_BITCORE_MSG, ver_pack);
	tree_manager_set_child_value_str(ver_pack, "cmd", "ping");
	tree_manager_add_child_node(ver_pack, "payload", NODE_BITCORE_PAYLOAD, &payload);
	tree_manager_set_child_value_i64(&payload, "nonce", nonce);
	pl_size = compute_payload_size(&payload);
	release_zone_ref(&payload);
	tree_manager_set_child_value_i32(ver_pack, "size", pl_size);
	return 1;
}
OS_API_C_FUNC(int) create_pong_message(mem_zone_ref_ptr node, uint64_t nonce, mem_zone_ref_ptr ver_pack)
{
	mem_zone_ref		payload = { PTR_NULL };
	size_t				pl_size;
	
	tree_manager_create_node("message", NODE_BITCORE_MSG, ver_pack);
	tree_manager_set_child_value_str(ver_pack, "cmd", "pong");
	tree_manager_add_child_node		(ver_pack, "payload", NODE_BITCORE_PAYLOAD, &payload);
	tree_manager_set_child_value_i64(&payload, "nonce", nonce);
	pl_size = compute_payload_size(&payload);
	release_zone_ref(&payload);
	tree_manager_set_child_value_i32(ver_pack, "size", pl_size);
	return 1;
}
OS_API_C_FUNC(int) create_version_message(mem_zone_ref_ptr node, struct string *user_agent, mem_zone_ref_ptr ver_pack)
{
	unsigned int		ver;
	size_t				pl_size;
	uint64_t			nblks;
	uint64_t			services;
	mem_zone_ref		payload = { PTR_NULL };
	mem_zone_ref		self_addr = { PTR_NULL }, node_addr = { PTR_NULL };

	if (!tree_manager_get_child_value_i32	(node, NODE_HASH_version, &ver))return 0;
	if (!tree_manager_get_child_value_i64	(node, NODE_HASH_services, &services))return 0;
	if (!tree_manager_find_child_node		(node, NODE_HASH_p2p_addr, NODE_BITCORE_ADDR, &self_addr))return 0;
	if (!tree_manager_find_child_node		(node, NODE_HASH_p2p_addr, NODE_BITCORE_ADDR, &node_addr)){ release_zone_ref(&self_addr); return 0; }

	
	if (!tree_manager_get_child_value_i64(node, NODE_HASH("block height"), &nblks))
		nblks = 1;


	/*
	4	magic	uint32_t	Magic value indicating message origin network, and used to seek to next message when stream state is unknown
	12	command	char[12]	ASCII string identifying the packet content, NULL padded(non - NULL padding results in packet rejected)
	4	length	uint32_t	Length of payload in number of bytes
	4	checksum	uint32_t	First 4 bytes of sha256(sha256(payload))
	?   payload	uchar[]	The actual data
	*/
	tree_manager_create_node("message", NODE_BITCORE_MSG, ver_pack);
	tree_manager_set_child_value_str(ver_pack, "cmd", "version");

	/*
	4	version	int32_t	Identifies protocol version being used by the node
	8	services	uint64_t	bitfield of features to be enabled for this connection
	8	timestamp	int64_t	standard UNIX timestamp in seconds
	26	addr_recv	net_addr	The network address of the node receiving this message
	Fields below require version >= 106
	26	addr_from	net_addr	The network address of the node emitting this message
	8	nonce	uint64_t	Node random nonce, randomly generated every time a version packet is sent.This nonce is used to detect connections to self.
	?    user_agent	var_str	User Agent(0x00 if string is 0 bytes long)
	4	start_height	int32_t	The last block received by the emitting node
	*/
	tree_manager_add_child_node(ver_pack, "payload", NODE_BITCORE_PAYLOAD, &payload);
	tree_manager_set_child_value_i32(&payload, "proto_ver", ver);
	tree_manager_set_child_value_i64(&payload, "services", services);
	tree_manager_set_child_value_i64(&payload, "timestamp", get_time_c());
	tree_manager_node_add_child(&payload, &node_addr);
	tree_manager_node_add_child(&payload, &self_addr);
	tree_manager_set_child_value_i64(&payload, "nonce", ping_nonce++);
	tree_manager_set_child_value_vstr(&payload, "user_agent", user_agent);
	tree_manager_set_child_value_i32(&payload, "last_blk", nblks-1);
	pl_size = compute_payload_size(&payload);
	release_zone_ref(&payload);
	release_zone_ref(&self_addr);
	release_zone_ref(&node_addr);

	tree_manager_set_child_value_i32(ver_pack, "size", pl_size);

	return 1;
}

OS_API_C_FUNC(int) new_message(const struct string *data, mem_zone_ref_ptr msg)
{
	mem_zone_ref_ptr	key;
	mem_zone_ref		list = { PTR_NULL },my_list = { PTR_NULL };
	mem_zone_ref		payload_node = { PTR_NULL };
	struct string		pack_str = { PTR_NULL };
	size_t				cnt = 0;
	size_t				elSz = 0;
	int					ret,nc;

	if (!strncmp_c(&data->str[4], "version", 7))
		make_string(&pack_str, "{(\"payload\",0x0B000010) (0x02)\"proto_ver\" : 0,\"services\" : 0, \"timestamp\" : 0, (0x0B000040)\"their_addr\":\"\", (0x0B000040)\"my_addr\":\"\",\"nonce\":0,(0x0B000100)\"user_agent\":\"\", (0x02)\"last_blk\":0}");
	else if (!strncmp_c(&data->str[4], "ping", 4))
		make_string(&pack_str, "{(\"payload\",0x0B000010) \"nonce\":0}");
	else if (!strncmp_c(&data->str[4], "pong", 4))
		make_string(&pack_str, "{(\"payload\",0x0B000010) \"nonce\":0}");
	else if (!strncmp_c(&data->str[4], "addr", 4))
	{
		unsigned int    first, n;
		unsigned char	c;

		c = *((unsigned char *)(data->str + 24));

		if (c < 0xFD)
			cnt = c;
		else if (c == 0xFD)
		{
			cnt = *((unsigned short *)(data->str + 24 + 1));
		}
		else if (c == 0xFE)
		{
			cnt = *((unsigned int *)(data->str + 24 + 1));
		}
		else if (c == 0xFF)
		{
			cnt = *((uint64_t *)(data->str + 24 + 1));
		}
		elSz = 30;
		make_string(&pack_str, "{(\"payload\",0x0B000010) (0x0B000020)\"addrs\":[");
		first = 1;
		n = cnt;
		while (n--)
		{
			if (!first){ cat_cstring(&pack_str, ","); }
			first = 0;
			cat_cstring(&pack_str, "{(\"addr\",0x0B000080)}");
		}
		cat_cstring(&pack_str, "]}");
	}
	else if (!strncmp_c(&data->str[4], "headers", 7))
	{
		unsigned int    first, n;
		unsigned char	c;

		c = *((unsigned char *)(data->str + 24));

		if (c < 0xFD)
			cnt = c;
		else if (c == 0xFD)
		{
			cnt = *((unsigned short *)(data->str + 24 + 1));
		}
		else if (c == 0xFE)
		{
			cnt = *((unsigned int *)(data->str + 24 + 1));
		}
		else if (c == 0xFF)
		{
			cnt = *((uint64_t *)(data->str + 24 + 1));
		}
		elSz = 82;

		make_string(&pack_str, "{(\"payload\",0x0B000010) (0x0B000400)\"headers\":[");
		first = 1;
		n = cnt;
		while (n--)
		{
			if (!first){ cat_cstring(&pack_str, ","); }
			cat_cstring(&pack_str, "{(\"header\",0x0B000800)}");
			first = 0;
		}
		cat_cstring(&pack_str, "]}");
	}
	else if (!strncmp_c(&data->str[4], "block", 5))
	{
		unsigned int    first, n;
		unsigned char	c;

		c = *((unsigned char *)(data->str + 24+80));

		if (c < 0xFD)
			cnt = c;
		else if (c == 0xFD)
		{
			cnt = *((unsigned short *)(data->str + 24 + 80 + 1));
		}
		else if (c == 0xFE)
		{
			cnt = *((unsigned int *)(data->str + 24 + 80 + 1));
		}
		else if (c == 0xFF)
		{
			cnt = *((uint64_t *)(data->str + 24 + 80 + 1));
		}

		make_string(&pack_str, "{(\"payload\",0x0B000010)  (0x0B000800)\"header\":\"\", (0x0B004000)\"txs\":[");
		first = 1;
		n = cnt;
		while (n--)
		{
			if (!first){ cat_cstring(&pack_str, ","); }
			cat_cstring(&pack_str, "{(\"tx\",0x0B008000)}");
			first = 0;
		}
		cat_cstring(&pack_str, "], (0x0B800000)\"signature\":\"\"}");
		cnt = 0;
	}
	else if (!strncmp_c(&data->str[4], "getdata", 7))
	{
		unsigned int    first, n;
		unsigned char	c;

		c = *((unsigned char *)(data->str + 24));

		if (c < 0xFD)
			cnt = c;
		else if (c == 0xFD)
		{
			cnt = *((unsigned short *)(data->str + 24 + 1));
		}
		else if (c == 0xFE)
		{
			cnt = *((unsigned int *)(data->str + 24 + 1));
		}
		else if (c == 0xFF)
		{
			cnt = *((uint64_t *)(data->str + 24 + 1));
		}
		make_string(&pack_str, "{(\"payload\",0x0B000010) (0x0B003000)\"hashes\":[");
		first = 1;
		n = cnt;
		while (n--)
		{
			if (!first){ cat_cstring(&pack_str, ","); }
			cat_cstring(&pack_str, "{(\"hash\",0x0B005000)}");
			first = 0;
		}
		cat_cstring(&pack_str, "]}");
		cnt = 0;
		elSz = 0;
	}
	else if (!strncmp_c(&data->str[4], "inv", 3))
	{
		unsigned int    first, n;
		unsigned char	c;

		c = *((unsigned char *)(data->str + 24));

		if (c < 0xFD)
			cnt = c;
		else if (c == 0xFD)
		{
			cnt = *((unsigned short *)(data->str + 24 + 1));
		}
		else if (c == 0xFE)
		{
			cnt = *((unsigned int *)(data->str + 24 + 1));
		}
		else if (c == 0xFF)
		{
			cnt = *((uint64_t *)(data->str + 24 + 1));
		}
		make_string(&pack_str, "{(\"payload\",0x0B000010) (0x0B003000)\"hashes\":[");
		first = 1;
		n = cnt;
		while (n--)
		{
			if (!first){ cat_cstring(&pack_str, ","); }
			cat_cstring(&pack_str, "{(\"hash\",0x0B005000)}");
			first = 0;
		}
		cat_cstring(&pack_str, "]}");
		cnt=0;
		elSz = 0;
	}
	else return 0;

	ret=tree_manager_json_loadb	(pack_str.str, pack_str.len, &payload_node);
	free_string					(&pack_str);
	if (!ret)
		return 0;

	if (elSz>0)
		tree_manager_get_child_at(&payload_node, 0, &list);
	else
		list.zone = payload_node.zone;

	nc = tree_manager_get_node_num_children(&list);

	for (tree_manager_get_first_child(&list, &my_list, &key); ((key != NULL) && (key->zone != NULL)); tree_manager_get_next_child(&my_list, &key))
	{
		init_node(key);
	}

	tree_manager_set_child_value_str(msg, "cmd"	, &data->str[4]);
	tree_manager_set_child_value_i32(msg, "size", (*((unsigned int *)(&data->str[16]))));
	tree_manager_set_child_value_i32(msg, "sum"	, *((unsigned int *)(&data->str[20])));
	tree_manager_set_child_value_i32(msg, "cnt"	, cnt);
	tree_manager_set_child_value_i32(msg, "elSz", elSz);
	tree_manager_node_add_child		(msg, &payload_node);
	
	if (elSz)
		release_zone_ref(&list);

	release_zone_ref(&payload_node);
	

	return 1;
}
 
