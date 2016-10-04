#include <base/std_def.h>
#include <base/std_mem.h>
#include <base/mem_base.h>
#include <base/std_str.h>

#include <strs.h>
#include <tree.h>
#include <fsio.h>


C_IMPORT int			C_API_FUNC load_blk_hdr(mem_zone_ref_ptr hdr, const char *blk_hash);
C_IMPORT int			C_API_FUNC get_tx_output(mem_zone_ref_const_ptr tx, unsigned int idx, mem_zone_ref_ptr vout);
C_IMPORT int			C_API_FUNC get_tx_input(mem_zone_ref_const_ptr tx, unsigned int idx, mem_zone_ref_ptr vin);
C_IMPORT int			C_API_FUNC compute_block_hash(mem_zone_ref_ptr hdr, hash_t blk_hash);
C_IMPORT int			C_API_FUNC compute_block_pow(mem_zone_ref_ptr block, hash_t hash);
C_IMPORT int			C_API_FUNC is_tx_null(mem_zone_ref_const_ptr tx);
C_IMPORT int			C_API_FUNC is_vout_null(mem_zone_ref_const_ptr tx, unsigned int idx);
C_IMPORT int			C_API_FUNC load_tx_input(mem_zone_ref_const_ptr tx, unsigned int idx, mem_zone_ref_ptr	vin, mem_zone_ref_ptr tx_out);
C_IMPORT int			C_API_FUNC load_tx(mem_zone_ref_ptr tx, hash_t blk_hash, const char *tx_hash);
C_IMPORT int			C_API_FUNC SetCompact(unsigned int bits, hash_t out);
C_IMPORT int			C_API_FUNC get_tx_output_amount(const hash_t tx_hash, unsigned int idx, uint64_t *amount);
C_IMPORT void			C_API_FUNC mul_compact(unsigned int nBits, uint64_t op, hash_t hash);
C_IMPORT int			C_API_FUNC cmp_hashle(hash_t hash1, hash_t hash2);
C_IMPORT int			C_API_FUNC get_block_height();
C_IMPORT int			C_API_FUNC  list_received(btc_addr_t addr, uint64_t *amount);

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
				
				list_received					(addr, &amount);
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