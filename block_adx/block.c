
#include <base/std_def.h>
#include <base/std_mem.h>
#include <base/mem_base.h>
#include <base/std_str.h>

#include <strs.h>
#include <tree.h>


C_IMPORT size_t			C_API_FUNC file_size(const char *path);
C_IMPORT int			C_API_FUNC append_file(const char *path, void *data, size_t data_len);
C_IMPORT int			C_API_FUNC stat_file(const char *path);
C_IMPORT int			C_API_FUNC create_dir(const char *path);
C_IMPORT int			C_API_FUNC put_file(const char *path, void *data, size_t data_len);
C_IMPORT int			C_API_FUNC get_sub_dirs(const char *path, struct string *dir_list);
C_IMPORT int			C_API_FUNC get_sub_files(const char *path, struct string *file_list);
C_IMPORT int			C_API_FUNC get_file(const char *path, unsigned char **data, size_t *data_len);
C_IMPORT int			C_API_FUNC get_hash_idx(const char *path, size_t idx, hash_t hash);

C_IMPORT size_t			C_API_FUNC	compute_payload_size(mem_zone_ref_ptr payload_node);
C_IMPORT char*			C_API_FUNC	write_node(mem_zone_ref_const_ptr key, unsigned char *payload);
C_IMPORT size_t			C_API_FUNC	get_node_size(mem_zone_ref_ptr key);
C_IMPORT void			C_API_FUNC	serialize_children(mem_zone_ref_ptr node, unsigned char *payload);
C_IMPORT const char*	C_API_FUNC read_node(mem_zone_ref_ptr key, const unsigned char *payload);
C_IMPORT size_t			C_API_FUNC init_node(mem_zone_ref_ptr key);

static const char		hexs[16]	 = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
hash_t					null_hash	 = { 0xCD };
static unsigned char	pubKeyPrefix = 0xCD;
mem_zone_ref			genesis = { PTR_INVALID };

extern int			scrypt_blockhash	(const void* input, hash_t hash);

OS_API_C_FUNC(void) set_pubkeyprefix(unsigned char c){
	pubKeyPrefix = c;
}

OS_API_C_FUNC(unsigned int) SetCompact(unsigned int bits, hash_t out)
{
	unsigned int  nSize = bits >> 24;
	size_t		  ofset;

	memset_c(out, 0, 32);

	if (nSize < 32)
		ofset = 32 - nSize;

	if (nSize >= 1) out[0 + ofset] = (bits >> 16) & 0xff;
	if (nSize >= 2) out[1 + ofset] = (bits >> 8) & 0xff;
	if (nSize >= 3) out[2 + ofset] = (bits >> 0) & 0xff;

	return 1;
}



int compute_script_size(mem_zone_ref_ptr script_node)
{
	mem_zone_ref_ptr	key;
	mem_zone_ref		my_list = { PTR_NULL };
	size_t				length;
	
	length = 0;

	for (tree_manager_get_first_child(script_node, &my_list, &key); ((key != NULL) && (key->zone != NULL)); tree_manager_get_next_child(&my_list, &key))
	{
		unsigned char	*data;

		switch (tree_mamanger_get_node_type(key))
		{
		case NODE_BITCORE_VSTR:
			data = tree_mamanger_get_node_data_ptr(key, 0);
			if (*data < 0xFD)
				length += 1 + (*data);
			else if (*data == 0xFD)
			{
				length += 3 + (*((unsigned short *)(data + 1)));
			}
			else if (*data == 0xFE)
			{
				length += 5 + (*((unsigned int *)(data + 1)));
			}
			else if (*data == 0xFF)
			{
				length += 9 + (*((uint64_t *)(data + 1)));
			}
		break;
		case NODE_BITCORE_VINT:
			data = tree_mamanger_get_node_data_ptr(key, 0);
			if (*data == 0x00)
			{
				length++;
			}
			else if (*data < 0xFD)
			{
				length	+=2;
			}
			else if (*data == 0xFD)
			{
				length  +=3;
			}
			else if (*data == 0xFE)
			{
				length += 5;
			}
			else if (*data == 0xFF)
			{
				length += 9;
			}
			break;
		}
	}
	return length;
}

int serialize_script(mem_zone_ref_ptr script_node, struct string *script)
{
	mem_zone_ref_ptr	key;
	mem_zone_ref		my_list = { PTR_NULL };
	size_t				length;
	unsigned char		*script_data;

	length = compute_script_size(script_node);
	script->len	 = length;
	script->size = length + 1;
	script->str  = calloc_c(script->size, 1);
	
	script_data  = (unsigned char *)script->str;

	for (tree_manager_get_first_child(script_node, &my_list, &key); ((key != NULL) && (key->zone != NULL)); tree_manager_get_next_child(&my_list, &key))
	{
		unsigned char	*data;

		switch (tree_mamanger_get_node_type(key))
		{
			case NODE_BITCORE_VSTR:
				data = tree_mamanger_get_node_data_ptr(key, 0);
				if (*data < 0xFD)
				{
					*(script_data++) = *data;
					memcpy_c(script_data, &data[1], *data);
					script_data += (*data);
				}
				else if (*data == 0xFD)
				{
					*(script_data++) = 0xFD;
					(*((unsigned short *)(script_data))) = (*((unsigned short *)(data + 1)));
					script_data += 2;
					memcpy_c(script_data, &data[3], (*((unsigned short *)(data + 1))));
					script_data += (*((unsigned short *)(data + 1)));
				}
				else if (*data == 0xFE)
				{
					*(script_data++) = 0xFE;
					(*((unsigned int *)(script_data))) = (*((unsigned int *)(data + 1)));
					script_data += 4;
					memcpy_c(script_data, &data[5], (*((unsigned int *)(data + 1))));
					script_data += (*((unsigned int *)(data + 1)));
				}
				else if (*data == 0xFF)
				{
					*(script_data++) = 0xFF;
					(*((uint64_t *)(script_data))) = (*((uint64_t *)(data + 1)));
					script_data += 8;
					memcpy_c(script_data, &data[9], (*((uint64_t *)(data + 1))));
					script_data += (*((uint64_t *)(data + 1)));
				}
			break;
			case NODE_BITCORE_VINT:
				data = tree_mamanger_get_node_data_ptr(key, 0);
				if (*data == 0x00)
				{
					*(script_data++) = *data;
				}
				else if (*data < 0xFD)
				{
					*(script_data++) = 1;
					*(script_data++) = *data;
				}
				else if (*data == 0xFD)
				{
					*(script_data++) = 2;
					(*((unsigned short *)(script_data))) = (*((unsigned short *)(data + 1)));
					script_data += 2;
				}
				else if (*data == 0xFE)
				{
					*(script_data++) = 4;
					(*((unsigned int *)(script_data))) = (*((unsigned int *)(data + 1)));
					script_data += 4;
				}
				else if (*data == 0xFF)
				{
					*(script_data++) = 8;
					(*((uint64_t *)(script_data))) = (*((uint64_t *)(data + 1)));
					script_data += 8;
				}
			break;
		}
	}
	return 1;
}

OS_API_C_FUNC(int) tx_add_input(mem_zone_ref_ptr tx, const hash_t tx_hash, unsigned int index, mem_zone_ref_ptr script_node)
{
	mem_zone_ref txin_list			= { PTR_NULL },txin = { PTR_NULL }, out_point = { PTR_NULL };
	struct string script			= { PTR_NULL };


	if (!tree_manager_create_node("txin", NODE_BITCORE_TXIN, &txin))return 0;
	
	serialize_script					(script_node, &script);
	
	tree_manager_set_child_value_hash	(&txin, "tx hash", tx_hash);
	tree_manager_set_child_value_i32	(&txin, "idx", index);

	tree_manager_set_child_value_vstr	(&txin, "script"	, &script);
	tree_manager_set_child_value_i32	(&txin, "sequence"	, 0xFFFFFFFF);
		
	tree_manager_find_child_node		(tx, NODE_HASH("txsin"), NODE_BITCORE_VINLIST, &txin_list);
	tree_manager_node_add_child			(&txin_list			, &txin);
	release_zone_ref					(&txin);
	release_zone_ref					(&txin_list);

	free_string							(&script);
	return 1;
}

OS_API_C_FUNC(int) tx_add_output(mem_zone_ref_ptr tx, uint64_t value, const struct string *script)
{
	mem_zone_ref						txout_list = { PTR_NULL },txout = { PTR_NULL };

	if (!tree_manager_find_child_node(tx, NODE_HASH("txsout"), NODE_BITCORE_VOUTLIST, &txout_list))return 0;

	tree_manager_create_node			("txout", NODE_BITCORE_TXOUT, &txout);
	tree_manager_set_child_value_i64	(&txout, "value", value);
	tree_manager_set_child_value_vstr	(&txout, "script", script);
	tree_manager_node_add_child			(&txout_list, &txout);
	release_zone_ref					(&txout);
	release_zone_ref					(&txout_list);
	return 1;
}

OS_API_C_FUNC(int) new_transaction(mem_zone_ref_ptr tx, time_t time)
{
	tree_manager_create_node		("transaction"	, NODE_BITCORE_TX, tx);
	tree_manager_set_child_value_i32(tx, "version"	, 1);
	tree_manager_set_child_value_i32(tx, "time"		, time);
	tree_manager_add_child_node		(tx, "txsin"	, NODE_BITCORE_VINLIST , PTR_NULL);
	tree_manager_add_child_node		(tx, "txsout"	, NODE_BITCORE_VOUTLIST, PTR_NULL);
	tree_manager_set_child_value_i32(tx, "locktime"	, 0);
	return 1;
}

OS_API_C_FUNC(int) compute_tx_hash(mem_zone_ref_ptr tx, hash_t hash)
{
	hash_t		  tx_hash;
	size_t		  length;
	unsigned char *buffer;

	length = compute_payload_size(tx);
	buffer = malloc_c(length);
	serialize_children(tx, buffer);
	mbedtls_sha256(buffer, length, tx_hash, 0);
	mbedtls_sha256(tx_hash, 32, hash, 0);
	free_c(buffer);
	return 1;
}
OS_API_C_FUNC(int) compute_block_pow(mem_zone_ref_ptr block, hash_t hash)
{
	size_t		  length;
	unsigned char *buffer;

	length = get_node_size(block);
	buffer = malloc_c(length);
	write_node(block, buffer);
	scrypt_blockhash(buffer, hash);
	free_c(buffer);
	return 1;
}

OS_API_C_FUNC(int) compute_block_hash(mem_zone_ref_ptr block, hash_t hash)
{
	unsigned int			checksum1[8];
	size_t					length;
	unsigned char			*buffer;

	length = compute_payload_size(block);
	buffer = malloc_c(length);

	write_node			(block, buffer);

	mbedtls_sha256(buffer, 80, (unsigned char*)checksum1, 0);
	mbedtls_sha256((unsigned char*)checksum1, 32, hash, 0);
	free_c(buffer);

	return 1;
}

int build_merkel_tree(mem_zone_ref_ptr txs, hash_t merkleRoot)
{
	mem_zone_ref tx = { PTR_NULL };
	int				n;
	n = tree_manager_get_node_num_children(txs);
	if (n <= 1)
	{
		tree_manager_get_child_at	(txs, 0, &tx);
		compute_tx_hash				(&tx, merkleRoot);
		release_zone_ref			(&tx);
		return 1;
	}
	return 1;
}

OS_API_C_FUNC(int) find_hash(hash_t hash)
{
	char				file_name[65];
	char				dir[2][3];
	struct string		blk_path = { PTR_NULL };
	unsigned int		n;
	int					ret;
	itoa_s(hash[0], dir[0], 3, 16);
	itoa_s(hash[1], dir[1], 3, 16);

	make_string(&blk_path, "./blks/");
	cat_cstring(&blk_path, dir[0]);
	cat_cstring(&blk_path, "/");
	cat_cstring(&blk_path, dir[1]);
	cat_cstring(&blk_path, "/");
	memset_c(file_name, '0', 65);
	n = 0;
	while (n<32)
	{
		file_name[n * 2 + 0] = hexs[hash[n] >> 4];
		file_name[n * 2 + 1] = hexs[hash[n] & 0x0F];
		n++;
	}
	file_name[64] = 0;
	cat_cstring(&blk_path, file_name);

	ret = stat_file(blk_path.str);
	if (ret == 0)
		ret = 1;
	else
		ret = 0;

	free_string(&blk_path);
	return ret;
}

char* base58(unsigned char *s, char *out) {
	static const char *tmpl = "123456789"
		"ABCDEFGHJKLMNPQRSTUVWXYZ"
		"abcdefghijkmnopqrstuvwxyz";
	static char buf[40];

	int c, i, n;
	if (!out) out = buf;

	out[n = 34] = 0;
	while (n--) {
		for (c = i = 0; i < 25; i++) {
			c = c * 256 + s[i];
			s[i] = c / 58;
			c %= 58;
		}
		out[n] = tmpl[c];
	}

	for (n = 0; out[n] == '1'; n++);
	memmove_c(out, out + n, 34 - n);

	return out;
}
OS_API_C_FUNC(int) check_tx_output(mem_zone_ref_ptr tx, const char * tx_hash)
{
	char				path[256];
	hash_t				hash;
	struct string		script = { PTR_NULL };
	mem_zone_ref		txout_list = { PTR_NULL }, my_list = { PTR_NULL };
	mem_zone_ref_ptr	out = PTR_NULL;
	unsigned int		oidx;
	
	if (!tree_manager_find_child_node(tx, NODE_HASH("txsout"), NODE_BITCORE_VOUTLIST, &txout_list))return 0;
	
	strcpy_cs(path, 256, ".\\adrs\\");

	

	for (oidx = 0,tree_manager_get_first_child(&txout_list, &my_list, &out); ((out != NULL) && (out->zone != NULL)); oidx++, tree_manager_get_next_child(&my_list, &out))
	{
		uint64_t		amount=0;
		unsigned char  *p;
		
		if (!tree_manager_get_child_value_istr(out, NODE_HASH("script"), &script, 16))continue;
		if (script.len == 0){free_string(&script); continue;}

		tree_manager_get_child_value_i64(out, NODE_HASH("value"), &amount);

		p = script.str;
		if ((p[0] == 33) && (p[34] == 0xAC))
		{
			/*
			int n;
			printf("tx "%llu out sig to\n", amount);
			memcpy_c(hash, script.str + 1, 32);
			for (n = 0; n < 32; n++)
			{
				printf("%02x", hash[31 - n]);
			}
			printf("\n");
			*/
		}
		else if ((p[0] == 0x76) && (p[1] == 0xA9) && (p[24] == 0xAC))
		{
			
			unsigned char	hin[32];
			hash_t			tmp_hash, fhash;

			hash[0]		= pubKeyPrefix;
			memcpy_c	(&hash[1], script.str + 3, 20);

			mbedtls_sha256(hash, 21, tmp_hash, 0);
			mbedtls_sha256(tmp_hash, 32, fhash, 0);

			memcpy_c	(hin, hash, 21);
			memcpy_c	(&hin[21], fhash, 4);
			base58		(hin, &path[7]);
			path[41] = 0;
			path[42] = 0;
						
			if (stat_file(path)==0)
			{
				int n = 32;
				int l;
				char cidx[8] = { 0 };
				itoa_s(oidx, cidx, 4, 10);
				
				strcat_cs(path, 256, "\\spendable\\");
				create_dir		(path);

				l = strlen_c(path);

				while (n--)
				{
					path[l + n * 2 + 0] = tx_hash[(n * 2) + 0];
					path[l + n * 2 + 1] = tx_hash[(n * 2) + 1];
				}
				path[l + 64] = 0;
				

				strcat_cs	(path, 256, "_");
				strcat_cs	(path, 256, cidx);
				
				put_file		(path,&amount,8);
			}
			
		}
		else
		{
			int ttt;
			ttt = 0;
		}

		free_string(&script);
	}

	release_zone_ref(&txout_list);

	return 1;
}




OS_API_C_FUNC(int) load_tx(mem_zone_ref_ptr tx, const char *tx_hash)
{
	
	char				dir[2][3];
	unsigned char		*tx_data;
	size_t				tx_data_len;
	struct string		blk_path = { PTR_NULL };
	memcpy_c(dir[0], &tx_hash[0], 2);
	memcpy_c(dir[1], &tx_hash[2], 2);

	dir[0][2] = 0;
	dir[1][2] = 0;


	make_string(&blk_path, "./txs/");
	cat_cstring(&blk_path, dir[0]);
	cat_cstring(&blk_path, "/");
	cat_cstring(&blk_path, dir[1]);
	cat_cstring(&blk_path, "/");
	cat_cstring(&blk_path, tx_hash);
	cat_cstring(&blk_path,  "/data");

	if (get_file(blk_path.str, &tx_data, &tx_data_len) > 0)
	{
		if (tree_manager_create_node("tx", NODE_BITCORE_TX, tx))
		{
			init_node(tx);
			if (read_node(tx, tx_data))
				check_tx_output(tx,tx_hash);
		}
		free_c(tx_data);
	}

	free_string(&blk_path);

	return 1;
}



OS_API_C_FUNC(void) check_txs()
{
	const char			*ptr, *optr;
	struct string	dir_list = { PTR_NULL };
	int				n,cur;
	mem_zone_ref tx = { PTR_NULL };

	n = get_sub_dirs("./txs/", &dir_list);
	if (n <= 0)return;
	optr = dir_list.str;
	cur = 0;

	tree_manager_create_node("tx", NODE_BITCORE_TX, &tx);
	init_node(&tx);


	while (cur<n)
	{
		struct string	dir_list2 = { PTR_NULL };
		const char		*ptr2, *optr2;
		char			total[32];
		int				n2,cur2;
		size_t			sz;

		ptr =	memchr_c(optr, 10, dir_list.len);
		sz	=	mem_sub(optr, ptr);

		strcpy_cs(total, 32,"./txs/");
		memcpy_c(&total[6], optr, sz);
		total[6 + sz] = 0;
		strcat_cs(total, 32, "/");
		n2		= get_sub_dirs(total, &dir_list2);
		optr2	= dir_list2.str;
		cur2 = 0;
		while (cur2<n2)
		{
			const char		*ptr3, *optr3;
			int				n3,cur3;
			struct string	tx_dir_list = { PTR_NULL };
			size_t			sz2;

			ptr2 = memchr_c(optr2, 10, dir_list2.len);
			sz2 = mem_sub(optr2, ptr2);

			strcpy_cs(total, 32, "./txs/");
			memcpy_c(&total[6], optr, sz);
			total[6 + sz] = 0;
			strcat_cs(total, 32, "/");
			memcpy_c(&total[6+sz+1], optr2, sz2);
			total[6 + sz + 1 + sz2] = 0;
			strcat_cs(total, 32, "/");

			cur3 = 0;
			n3		= get_sub_dirs(total, &tx_dir_list);

			optr3 = tx_dir_list.str;
			while (cur3<n3)
			{
				char			data_file[128];
				unsigned char	*tx_data;
				size_t			tx_data_len, sz3;

				ptr3 = memchr_c(optr3, 10, tx_dir_list.len);
				if (ptr3 == PTR_INVALID)break;
				sz3  = mem_sub(optr3, ptr3);

				strcpy_cs(data_file, 128, total);
				strcat_cs(data_file, 128, "/");
				memcpy_c(&data_file[6 + sz + 1 + sz2 + 1], optr3, sz3);
				data_file[6 + sz + 1 + sz2+1+sz3] = 0;
				strcat_cs(data_file, 128, "/data");

				if (get_file(data_file, &tx_data, &tx_data_len) > 0)
				{
					read_node			(&tx, tx_data);
					check_tx_output		(&tx, optr3);
					free_c				(tx_data);
				}
				cur3++;
				optr3 = ptr3 + 1;
			}
			free_string(&tx_dir_list);
			cur2++;
			optr2	= ptr2 + 1;
		}
		free_string(&dir_list2);
		cur++;
		optr = ptr + 1;
	}
	free_string(&dir_list);
	release_zone_ref(&tx);
}

OS_API_C_FUNC(int) check_block(mem_zone_ref_ptr hdr)
{
	hash_t				blk_hash, blk_pow, diff_hash, prev_hash;
	unsigned int		bits;
	tree_manager_get_child_value_i32(hdr, NODE_HASH("bits"), &bits);
	tree_manager_get_child_value_hash(hdr, NODE_HASH("prev"), prev_hash);
	
	if (!find_hash(prev_hash))return 0;

	compute_block_pow	(hdr , blk_pow);
	compute_block_hash	(hdr , blk_hash);
	SetCompact			(bits, diff_hash);
	
	//compare pow & diff

	tree_manager_set_child_value_bhash(hdr, "blk hash", blk_hash);
	tree_manager_set_child_value_hash(hdr, "blk pow", blk_pow);

	if (find_hash(blk_hash))
		return 0;

	return 1;
}

OS_API_C_FUNC(int) get_hash_list(mem_zone_ref_ptr hdr_list, mem_zone_ref_ptr hash_list)
{
	mem_zone_ref		my_list = { PTR_NULL };
	mem_zone_ref_ptr	hdr;
	int					n = 0;

	tree_manager_create_node("hash list", NODE_BITCORE_HASH_LIST, hash_list);

	for (n = 0, tree_manager_get_first_child(hdr_list, &my_list, &hdr); ((hdr != NULL) && (hdr->zone != NULL)); n++, tree_manager_get_next_child(&my_list, &hdr))
	{
		hash_t blk_hash;
		char	idx[32] = { 0 };

		itoa_s(n, idx, 32, 16);
		tree_manager_get_child_value_hash(hdr, NODE_HASH("blk hash"), blk_hash);
		tree_manager_set_child_value_bhash(hash_list, idx, blk_hash);


	}
	return n;
}

OS_API_C_FUNC(int) last_block_locator_index(mem_zone_ref_ptr node, mem_zone_ref_ptr hash_list)
{
	hash_t hash;
	mem_zone_ref hash_node = { PTR_NULL };
	size_t nc;

	if (!tree_manager_create_node("locator", NODE_BITCORE_LOCATOR, hash_list))return 0;
	nc = file_size("./blk_indexes") / 32;
	get_hash_idx("./blk_indexes", nc - 1, hash);

	tree_manager_add_child_node(hash_list, "hash", NODE_BITCORE_HASH, &hash_node);
	tree_manager_write_node_hash(&hash_node, 0, hash);
	release_zone_ref(&hash_node);

	return 1;
}

OS_API_C_FUNC(int) block_locator_indexes(mem_zone_ref_ptr node, size_t top_height, mem_zone_ref_ptr hash_list)
{
	hash_t hash;
	mem_zone_ref n = { PTR_NULL };
	mem_zone_ref hash_node = { PTR_NULL };
	int64_t index;
	int64_t cnt = 0;
	// Modify the step in the iteration.
	int64_t step = 1;
	int	cn = 0;

	tree_manager_create_node("locator", NODE_BITCORE_LOCATOR, hash_list);
	// Start at the top of the chain and work backwards.
	for (cn=0,index = (int64_t)top_height; index > 0; cn++, index -= step)
	{
		char idx[32];
		if (!get_hash_idx("./blk_indexes", index, hash))continue;

		strcpy_c(idx, "hash_");
		uitoa_s(cn, &idx[5], 27, 10);


		tree_manager_add_child_node(hash_list, idx, NODE_BITCORE_HASH, &hash_node);
		tree_manager_write_node_hash(&hash_node, 0, hash);
		release_zone_ref(&hash_node);

		// Push top 10 indexes first, then back off exponentially.
		cnt++;
		if (cnt == 10)
		{
			step *= 2;
			cnt = 0;
		}
	}

	log_message("block locator %hash_0% %hash_1%", hash_list);
	//  Push the genesis block index.
	if (get_hash_idx("./blk_indexes", 0, hash))
	{
		tree_manager_add_child_node(hash_list, "hash", NODE_BITCORE_HASH, &hash_node);
		tree_manager_write_node_hash(&hash_node, 0, hash);
		release_zone_ref(&hash_node);
	}
	return 1;
}

OS_API_C_FUNC(int) store_block(mem_zone_ref_ptr header, mem_zone_ref_ptr tx_list)
{
	mem_zone_ref_ptr	tx = PTR_NULL;
	mem_zone_ref		my_list = { PTR_NULL };

	size_t				length;
	unsigned char		*buffer;
	hash_t				blk_hash;
	char				file_name[65];
	struct string		blk_path = { PTR_NULL }, blk_data_path = { PTR_NULL };
	unsigned int		n,nc;
	char				dir[2][3];
	hash_t				*blk_txs;

	if (!tree_manager_get_child_value_hash(header, NODE_HASH("blk hash"), blk_hash))return 0;

	itoa_s(blk_hash[0], dir[0], 3, 16);
	itoa_s(blk_hash[1], dir[1], 3, 16);

	make_string(&blk_path, "./blks/");
	create_dir(blk_path.str);
	cat_cstring(&blk_path, dir[0]);
	cat_cstring(&blk_path, "/");
	create_dir(blk_path.str);
	cat_cstring(&blk_path, dir[1]);
	cat_cstring(&blk_path, "/");
	create_dir(blk_path.str);

	memset_c(file_name, '0', 65);
	n = 0;
	while (n<32)
	{
		file_name[n * 2 + 0] = hexs[blk_hash[n] >> 4];
		file_name[n * 2 + 1] = hexs[blk_hash[n] & 0x0F];
		n++;
	}
	file_name[64] = 0;
	cat_cstring(&blk_path, file_name);
	create_dir(blk_path.str);
		
	length = compute_payload_size(header);
	buffer = malloc_c(length);

	write_node		(header, buffer);
	
	clone_string	(&blk_data_path, &blk_path);
	cat_cstring		(&blk_data_path, "/header");
	put_file		(blk_data_path.str, buffer, length);
	free_c			(buffer);
	free_string		(&blk_data_path);
	append_file("./blk_indexes", blk_hash, 32);

	nc		=	tree_manager_get_node_num_children(tx_list);
	if (nc > 0)
	{
		blk_txs = calloc_c(sizeof(hash_t), nc);
		n = 0;
		for (tree_manager_get_first_child(tx_list, &my_list, &tx); ((tx != NULL) && (tx->zone != NULL)); tree_manager_get_next_child(&my_list, &tx))
		{
			hash_t tx_hash, tmp_hash;
			struct string tx_path = { PTR_NULL };

			length = get_node_size(tx);
			buffer = malloc_c(length);
			write_node(tx, buffer);

			mbedtls_sha256(buffer, length, tmp_hash, 0);
			mbedtls_sha256(tmp_hash, 32, tx_hash, 0);

			memcpy_c(&blk_txs[n++], tx_hash, 32);

			itoa_s(tx_hash[0], dir[0], 3, 16);
			itoa_s(tx_hash[1], dir[1], 3, 16);

			make_string(&tx_path, "./txs/");
			create_dir(tx_path.str);
			cat_cstring(&tx_path, dir[0]);
			cat_cstring(&tx_path, "/");
			create_dir(tx_path.str);
			cat_cstring(&tx_path, dir[1]);
			cat_cstring(&tx_path, "/");
			create_dir(tx_path.str);

			memset_c(file_name, '0', 65);
			n = 0;
			while (n < 32)
			{
				file_name[n * 2 + 0] = hexs[tx_hash[31 - n] >> 4];
				file_name[n * 2 + 1] = hexs[tx_hash[31 - n] & 0x0F];
				n++;
			}
			file_name[64] = 0;

			check_tx_output(tx, file_name);

			cat_cstring(&tx_path, file_name);
			create_dir(tx_path.str);
			cat_cstring(&tx_path, "/data");
			put_file(tx_path.str, buffer, length);
			free_c(buffer);
			free_string(&tx_path);
		}
		clone_string(&blk_data_path, &blk_path);
		cat_cstring(&blk_data_path, "/txs");
		put_file(blk_data_path.str, blk_txs, nc*sizeof(hash_t));

		free_c(blk_txs);
	}
	free_string(&blk_data_path);
	free_string(&blk_path);

	return 1;
}

OS_API_C_FUNC(int) load_block_indexes(mem_zone_ref_ptr hdr_list)
{
	char			idx[16];
	unsigned int	n;

	unsigned char	*data;
	size_t			data_len;

	if (!get_file("./blk_indexes", &data, &data_len))return 0;

	n = (data_len > (32 * 1000)) ? (data_len - 32 * 1000) : 0;
	while (n < data_len)
	{
		mem_zone_ref list = { PTR_NULL }, header = { PTR_NULL };

		memset_c(idx, 0, 16);
		uitoa_s(n / 32, idx, 16, 16);

		if (!tree_manager_add_child_node(hdr_list, idx, NODE_BITCORE_BLK_HDR, &header))
		{
			//printf("error import %d block \n",n);
			break;
		}
		tree_manager_set_child_value_bhash(&header, "blk hash", data + n);
		release_zone_ref(&header);

		n += 32;
	}
	free_c(data);
	return 1;
}

int make_iadix_merkle(mem_zone_ref_ptr genesis,mem_zone_ref_ptr txs,hash_t merkle)
{
	mem_zone_ref	newtx = { PTR_NULL };
	mem_zone_ref	script_node = { PTR_NULL };
	struct string	out_script = { PTR_NULL };
	struct string	timeproof = { PTR_NULL };

	make_string(&timeproof, "1 Sep 2016 Iadix coin");
	tree_manager_create_node("script", NODE_BITCORE_SCRIPT, &script_node);
	tree_manager_set_child_value_vint32(&script_node, "0", 0);
	tree_manager_set_child_value_vint32(&script_node, "1", 42);
	tree_manager_set_child_value_vstr(&script_node, "2", &timeproof);

	new_transaction(&newtx, 1466419086);
	tx_add_input(&newtx, null_hash, 0xFFFFFFFF, &script_node);
	tx_add_output(&newtx, 0, &out_script);
	release_zone_ref(&script_node);
	free_string(&timeproof);

	
	tree_manager_node_add_child(txs, &newtx);
	release_zone_ref			(&newtx);

	build_merkel_tree			(txs, merkle);
	
	return 0;
}
OS_API_C_FUNC(int) make_genesis_block(mem_zone_ref_ptr genesis_conf)
{
	hash_t								blk_pow, merkle;
	mem_zone_ref						txs = { PTR_NULL };
	unsigned int						version, time, bits, nonce;

	memset_c							(null_hash, 0, 32);
	
	genesis.zone = PTR_NULL;

	tree_manager_create_node			("genesis", NODE_BITCORE_BLK_HDR	, &genesis);
	tree_manager_create_node			("txs"	  , NODE_BITCORE_TX_LIST	, &txs);

	

	if (!tree_manager_get_child_value_hash(genesis_conf, NODE_HASH("merkle_root"), merkle))
	{
		make_iadix_merkle					(&genesis, &txs, merkle);

		/*
		printf("genesis merkle:\n");
		for (n = 0; n < 32; n++){printf("%02x", merkle[31 - n]);}
		printf("\n");
		*/
	}
	
	tree_manager_set_child_value_hash	(&genesis, "merkle_root"			, merkle);
	tree_manager_set_child_value_hash	(&genesis, "prev"					, null_hash);

	tree_manager_get_child_value_i32	(genesis_conf, NODE_HASH("version")	, &version);
	tree_manager_get_child_value_i32	(genesis_conf, NODE_HASH("time")	, &time);
	tree_manager_get_child_value_i32	(genesis_conf, NODE_HASH("bits")	, &bits);
	tree_manager_get_child_value_i32	(genesis_conf, NODE_HASH("nonce")	, &nonce);
	
	tree_manager_set_child_value_i32	(&genesis, "version"		, version);
	tree_manager_set_child_value_i32	(&genesis, "time"			, time);
	tree_manager_set_child_value_i32	(&genesis, "bits"			, bits);
	tree_manager_set_child_value_i32	(&genesis, "nonce"			, nonce);
	tree_manager_node_add_child			(&genesis, &txs);

	compute_block_pow					(&genesis, blk_pow);
	tree_manager_set_child_value_bhash	(&genesis, "blk hash", blk_pow);
	tree_manager_set_child_value_hash	(&genesis, "blk pow" , blk_pow);

	/*
	printf("genesis block hash :\n");
	for (n = 0; n < 32; n++){ printf("%02x", blk_pow[31 - n]); }
	printf("\n");
	*/
	
	if (!find_hash(blk_pow))
		store_block(&genesis, &txs);

	release_zone_ref(&txs);
	return 1;

}
