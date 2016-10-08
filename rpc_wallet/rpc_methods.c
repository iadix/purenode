#include <base/std_def.h>
#include <base/std_mem.h>
#include <base/mem_base.h>
#include <base/std_str.h>

#include <strs.h>
#include <tree.h>
#include <fsio.h>



C_IMPORT int			C_API_FUNC list_received(btc_addr_t addr, uint64_t *amount);
C_IMPORT int			C_API_FUNC list_unspent(btc_addr_t addr, mem_zone_ref_ptr unspents);
C_IMPORT int			C_API_FUNC list_spent(btc_addr_t addr, mem_zone_ref_ptr spents);
C_IMPORT int			C_API_FUNC list_received(btc_addr_t addr, uint64_t *amount, mem_zone_ref_ptr received);

mem_zone_ref			my_node = { PTR_INVALID };


OS_API_C_FUNC(int) set_node(mem_zone_ref_ptr node)
{
	my_node.zone = PTR_NULL;
	copy_zone_ref(&my_node, node);

	return 1;
}

OS_API_C_FUNC(int) addressscanstatus(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{
	btc_addr_t			new_addr;
	mem_zone_ref		addr = { PTR_NULL };
	struct string		adr_path = { 0 };
	unsigned char		*data;
	size_t				len;
	int					ret;

	if (!tree_manager_get_child_at(params, 0, &addr))return 0;
	if (!tree_manager_get_node_btcaddr(&addr, 0, new_addr))
	{
		release_zone_ref(&addr);
		return 0;
	}
	release_zone_ref(&addr);

	make_string(&adr_path, "adrs");
	cat_ncstring_p(&adr_path, new_addr, 34);
	cat_ncstring_p(&adr_path, "scan", 34);

	if (get_file(adr_path.str, &data, &len)>0)
	{
		unsigned int block;
		block = *((unsigned int *)(data));
		tree_manager_set_child_value_i32(result, "block", block);
		free_c(data);
		ret = 1;
	}
	else
		ret = 0;

	free_string(&adr_path);
	
	return ret;
}




OS_API_C_FUNC(int) importaddress(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{
	btc_addr_t			new_addr;
	mem_zone_ref		addr = { PTR_NULL }, rescan = { PTR_NULL };
	struct string		adr_path = { 0 };
	unsigned int		scan;
	
	tree_manager_get_child_at		(params, 0, &addr);
	if (!tree_manager_get_node_btcaddr(&addr, 0, new_addr))
	{
		release_zone_ref(&addr);
		return 0;
	}

	if (tree_manager_get_child_at(params, 1, &rescan))
		tree_mamanger_get_node_dword(&rescan, 0, &scan);
	else
		scan = 1;


	make_string						(&adr_path, "adrs");
	cat_ncstring_p					(&adr_path, new_addr, 34);
	create_dir						(adr_path.str);
	
	if (scan)
	{
		mem_zone_ref scan_list = { PTR_NULL };
		if (tree_manager_find_child_node(&my_node, NODE_HASH("addr scan list"), NODE_BITCORE_WALLET_ADDR_LIST, &scan_list))
		{
			mem_zone_ref addr_scan = { PTR_NULL };
			if (tree_manager_create_node("scan", NODE_BITCORE_WALLET_ADDR, &addr_scan))
			{
				tree_manager_set_child_value_btcaddr(&addr_scan, "addr", new_addr);
				tree_manager_set_child_value_i32	(&addr_scan, "done", 0);
				tree_manager_node_add_child			(&scan_list, &addr_scan);
				release_zone_ref					(&addr_scan);
			}
			release_zone_ref						(&scan_list);
		}
	}
		

	release_zone_ref				(&addr);
	release_zone_ref				(&rescan);
	free_string						(&adr_path);
		
	return 1;
}
OS_API_C_FUNC(int) listreceived(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{
	mem_zone_ref minconf = { PTR_NULL }, maxconf = { PTR_NULL }, received = { PTR_NULL }, addrs = { PTR_NULL };
	mem_zone_ref  my_list = { PTR_NULL };
	mem_zone_ref_ptr addr;
	uint64_t		amount;

	if (!tree_manager_create_node("received", NODE_JSON_ARRAY, &received))
		return 0;

	tree_manager_get_child_at(params, 0, &minconf);
	tree_manager_get_child_at(params, 1, &maxconf);
	tree_manager_get_child_at(params, 2, &addrs);


	for (tree_manager_get_first_child(&addrs, &my_list, &addr); ((addr != NULL) && (addr->zone != NULL)); tree_manager_get_next_child(&my_list, &addr))
	{
		btc_addr_t my_addr;
		tree_manager_get_node_btcaddr	(addr, 0, my_addr);
		list_received					(my_addr,&amount, &received);
	}
	tree_manager_node_add_child(result, &received);
	release_zone_ref(&received);

	release_zone_ref(&addrs);
	release_zone_ref(&maxconf);
	release_zone_ref(&minconf);

	return 1;
}
OS_API_C_FUNC(int) listspent(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{
	mem_zone_ref minconf = { PTR_NULL }, maxconf = { PTR_NULL }, spents = { PTR_NULL }, addrs = { PTR_NULL };
	mem_zone_ref  my_list = { PTR_NULL };
	mem_zone_ref_ptr addr;

	if (!tree_manager_create_node("spents", NODE_JSON_ARRAY, &spents))
		return 0;

	tree_manager_get_child_at(params, 0, &minconf);
	tree_manager_get_child_at(params, 1, &maxconf);
	tree_manager_get_child_at(params, 2, &addrs);


	for (tree_manager_get_first_child(&addrs, &my_list, &addr); ((addr != NULL) && (addr->zone != NULL)); tree_manager_get_next_child(&my_list, &addr))
	{
		btc_addr_t my_addr;

		tree_manager_get_node_btcaddr(addr, 0, my_addr);
		list_spent(my_addr, &spents);
	}

	tree_manager_node_add_child(result, &spents);
	release_zone_ref(&spents);

	release_zone_ref(&addrs);
	release_zone_ref(&maxconf);
	release_zone_ref(&minconf);

	return 1;
}
OS_API_C_FUNC(int) listunspent(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{
	mem_zone_ref minconf = { PTR_NULL }, maxconf = { PTR_NULL }, unspents = { PTR_NULL }, addrs = { PTR_NULL };
	mem_zone_ref  my_list = { PTR_NULL };
	mem_zone_ref_ptr addr;
	
	if (!tree_manager_create_node("unspents", NODE_JSON_ARRAY, &unspents))
		return 0;

	tree_manager_get_child_at(params, 0, &minconf);
	tree_manager_get_child_at(params, 1, &maxconf);
	tree_manager_get_child_at(params, 2, &addrs);


	for (tree_manager_get_first_child(&addrs, &my_list, &addr); ((addr != NULL) && (addr->zone != NULL)); tree_manager_get_next_child(&my_list, &addr))
	{
		btc_addr_t my_addr;

		tree_manager_get_node_btcaddr	(addr, 0, my_addr);
		list_unspent					(my_addr, &unspents);
	}

	tree_manager_node_add_child	(result, &unspents);
	release_zone_ref			(&unspents);

	release_zone_ref			(&addrs);
	release_zone_ref			(&maxconf);
	release_zone_ref			(&minconf);

	return 1;
}

OS_API_C_FUNC(int) listreceivedbyaddress(mem_zone_ref_const_ptr params, unsigned int rpc_mode, mem_zone_ref_ptr result)
{
	mem_zone_ref	addr_list = { PTR_NULL };
	struct string	dir_list = { PTR_NULL };
	size_t			cur, nfiles;


	if (!tree_manager_create_node("addrs", NODE_JSON_ARRAY, &addr_list))
		return 0;

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
			mem_zone_ref	new_addr = { PTR_NULL };
			size_t			sz;

			ptr = memchr_c(optr, 10, dir_list_len);
			sz = mem_sub(optr, ptr);

			if (tree_manager_add_child_node(&addr_list, "address", NODE_GFX_OBJECT, &new_addr))
			{
				char addr[35];
				uint64_t amount;
				memcpy_c(addr, optr, sz); addr[34] = 0;
				
				list_received					(addr, &amount,PTR_NULL);
				tree_manager_set_child_value_str(&new_addr, "addr", addr);
				tree_manager_set_child_value_i64(&new_addr, "amount", amount);
				release_zone_ref				(&new_addr);
			}
			cur++;
			optr = ptr + 1;
			dir_list_len -= sz;
		}
		free_string(&dir_list);
	}
	tree_manager_node_add_child(result, &addr_list);
	release_zone_ref(&addr_list);
	return 1;
}