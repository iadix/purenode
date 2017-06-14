//copyright antoine bentue-ferrer 2016
#include <base/std_def.h>
#include <base/std_mem.h>
#include <base/mem_base.h>
#include <base/std_str.h>

#include <sha256.h>
#define FORWARD_CRYPTO
#include <crypto.h>
#include <strs.h>
#include <tree.h>
#include <fsio.h>
#include <mem_stream.h>
#include <tpo_mod.h>


#define BLOCK_API C_EXPORT
#include "block_api.h"


C_IMPORT size_t			C_API_FUNC	compute_payload_size(mem_zone_ref_ptr payload_node);
C_IMPORT char*			C_API_FUNC	write_node(mem_zone_ref_const_ptr key, unsigned char *payload);
C_IMPORT size_t			C_API_FUNC	get_node_size(mem_zone_ref_ptr key);
C_IMPORT void			C_API_FUNC	serialize_children(mem_zone_ref_ptr node, unsigned char *payload);


/* store txout */
extern int				store_tx_vout(struct string *out_path, mem_zone_ref_ptr vout, btc_addr_t out_addr);


/* check signature */
extern int				check_sign(const struct string *sign, const struct string *pubK, const hash_t txh);
/* check public key from tx output */
extern int				check_txout_key(mem_zone_ref_ptr output, unsigned char *pkey,btc_addr_t addr);
/* compute scrypt block hash */
extern int				scrypt_blockhash(const void* input, hash_t hash);



#define ONE_COIN		100000000ULL
#define ONE_CENT		1000000ULL

hash_t					null_hash			= { 0xCD };
const char				*null_hash_str		= "0000000000000000000000000000000000000000000000000000000000000000";
unsigned char			pubKeyPrefix		= 0xFF;
static const uint64_t	one_coin			= ONE_COIN;
tpo_mod_file			sign_tpo_mod		= { 0xCD };


unsigned int			block_version		= 7;
unsigned int			diff_limit			= 0x1E0FFFFF;
unsigned int			TargetTimespan		= 960;
unsigned int			TargetSpacing		= 64;
unsigned int			MaxTargetSpacing	= 640;
unsigned int			checktxsign			= 0;
uint64_t				pow_reward			= 100000*ONE_COIN;

//#undef _DEBUG
#ifdef _DEBUG
LIBEC_API int			C_API_FUNC crypto_extract_key	(dh_key_t pk, const dh_key_t sk);
LIBEC_API int			C_API_FUNC crypto_sign_open		(const struct string *sign, const struct string *msgh, const struct string *pk);
LIBEC_API struct string	C_API_FUNC crypto_sign			(struct string *msg, const dh_key_t sk);
#else

crypto_extract_key_func_ptr crypto_extract_key = PTR_INVALID;
crypto_sign_open_func_ptr	crypto_sign_open   = PTR_INVALID;

#ifdef FORWARD_CRYPTO
crypto_sign_func_ptr		crypto_sign		   = PTR_INVALID;
#endif

#endif



int load_sign_module(mem_zone_ref_ptr mod_def, tpo_mod_file *tpo_mod)
{
	char			file[256];
	char			name[64];
	int				ret=1;

	strcpy_cs							(name, 64, tree_mamanger_get_node_name(mod_def));
	tree_manager_get_child_value_str	(mod_def, NODE_HASH("file"), file, 256, 0);
	ret=load_module(file, name, tpo_mod);
	if(ret)
	{

#ifndef _DEBUG
		crypto_extract_key = (crypto_extract_key_func_ptr)get_tpo_mod_exp_addr_name(tpo_mod, "crypto_extract_key", 0);
		crypto_sign_open = (crypto_sign_open_func_ptr)get_tpo_mod_exp_addr_name(tpo_mod, "crypto_sign_open", 0);
#ifdef FORWARD_CRYPTO
		crypto_sign = (crypto_sign_func_ptr)get_tpo_mod_exp_addr_name(tpo_mod, "crypto_sign", 0);
#endif
#endif
		tree_manager_set_child_value_ptr(mod_def, "mod_ptr", tpo_mod);
	}
	return ret;
}


OS_API_C_FUNC(int) init_blocks(mem_zone_ref_ptr node_config){
	hash_t				msgh;
	dh_key_t			privkey;
	dh_key_t			pubkey;
	mem_zone_ref		mining_conf = { PTR_NULL }, mod_def = { PTR_NULL };
	struct string		sign = { PTR_NULL };
	struct string		msg = { PTR_NULL };
	struct string		pkstr,str = { PTR_NULL }, strh = { PTR_NULL };
	int					i;

	memset_c						(null_hash, 0, 32);
	tree_manager_get_child_value_i32(node_config, NODE_HASH("pubKeyVersion"), &i);
	pubKeyPrefix = i;

	if (!tree_manager_find_child_node(node_config, NODE_HASH("sign_mod"), NODE_MODULE_DEF, &mod_def))
	{
		log_output("no signature module\n");
		return 0;
	}

	load_sign_module(&mod_def, &sign_tpo_mod);
	release_zone_ref(&mod_def);
	

	if (!tree_manager_get_child_value_i32(node_config, NODE_HASH("block_version"), &block_version))
		block_version = 7;


	if (tree_manager_find_child_node(node_config, NODE_HASH("mining"), 0xFFFFFFFF, &mining_conf))
	{
		tree_manager_get_child_value_i32(&mining_conf, NODE_HASH("limit"), &diff_limit);
		tree_manager_get_child_value_i32(&mining_conf, NODE_HASH("targettimespan"), &TargetTimespan);
		tree_manager_get_child_value_i32(&mining_conf, NODE_HASH("targetspacing"), &TargetSpacing);
		tree_manager_get_child_value_i32(&mining_conf, NODE_HASH("maxtargetspacing"), &MaxTargetSpacing);
		tree_manager_get_child_value_i64(&mining_conf, NODE_HASH("reward"), &pow_reward);
		release_zone_ref				(&mining_conf);
	}

#ifdef FORWARD_CRYPTO
	for (i = 0; i < 64; i++)
		privkey[i] = 0;

	crypto_extract_key	(pubkey, privkey);
	make_string			(&str, "abcdef");
	mbedtls_sha256		(str.str, str.len, msgh,0);

	strh.str = msgh;
	strh.len = 32;

	pkstr.str	= pubkey;
	pkstr.len	= 64;
	
	sign = crypto_sign		(&strh, privkey);
	i = crypto_sign_open    (&sign, &strh, &pkstr);

	if (i==1)
	{
		mem_zone_ref log = { PTR_NULL };
		tree_manager_create_node("log", NODE_LOG_PARAMS, &log);
		tree_manager_set_child_value_str(&log, "msg", msg.str);
		log_message("crypto sign ok '%msg%'", &log);
		release_zone_ref(&log);
	}
	else
		log_message("crypto sign error", PTR_NULL);
#endif	
	return 1;
}


OS_API_C_FUNC(int) get_block_version(unsigned int *v)
{
	*v = block_version;
	return 1;
}

OS_API_C_FUNC(void) set_tx_sign_chk(unsigned int v)
{
	checktxsign = v;
}



OS_API_C_FUNC(int) get_blockreward(uint64_t block, uint64_t *block_reward)
{
	*block_reward = pow_reward;
	return 1;
}

OS_API_C_FUNC(int) get_pow_reward(mem_zone_ref_ptr height, mem_zone_ref_ptr Reward)
{
	uint64_t	 reward;
	unsigned int nHeight;
	
	tree_mamanger_get_node_dword	(height, 0, &nHeight);
	get_blockreward					(nHeight, &reward);
	tree_manager_write_node_qword	(Reward, 0, reward);
	return 1;
}


OS_API_C_FUNC(int) tx_add_input(mem_zone_ref_ptr tx, const hash_t tx_hash, unsigned int index, struct string *script)
{
	mem_zone_ref txin_list			= { PTR_NULL },txin = { PTR_NULL }, out_point = { PTR_NULL };

	if (!tree_manager_create_node("txin", NODE_BITCORE_TXIN, &txin))return 0;
	
	tree_manager_set_child_value_hash	(&txin, "txid", tx_hash);
	tree_manager_set_child_value_i32	(&txin, "idx", index);

	if (script!=PTR_NULL)
		tree_manager_set_child_value_vstr	(&txin, "script"	, script);

	tree_manager_set_child_value_i32	(&txin, "sequence"	, 0xFFFFFFFF);
		
	tree_manager_find_child_node		(tx, NODE_HASH("txsin"), NODE_BITCORE_VINLIST, &txin_list);
	tree_manager_node_add_child			(&txin_list			, &txin);
	release_zone_ref					(&txin);
	release_zone_ref					(&txin_list);

	
	return 1;
}

OS_API_C_FUNC(int) tx_add_output(mem_zone_ref_ptr tx, uint64_t value, const struct string *script)
{
	btc_addr_t		dstaddr;
	mem_zone_ref	txout_list = { PTR_NULL },txout = { PTR_NULL };

	if (!tree_manager_find_child_node(tx, NODE_HASH("txsout"), NODE_BITCORE_VOUTLIST, &txout_list))return 0;

	tree_manager_create_node			("txout", NODE_BITCORE_TXOUT, &txout);
	tree_manager_set_child_value_i64	(&txout, "value", value);
	tree_manager_set_child_value_vstr	(&txout, "script", script);

	if (get_out_script_address(script, PTR_NULL, dstaddr))
	{
		tree_manager_set_child_value_btcaddr(&txout, "addr", dstaddr);
	}


	tree_manager_node_add_child			(&txout_list, &txout);
	release_zone_ref					(&txout);
	release_zone_ref					(&txout_list);
	return 1;
}

OS_API_C_FUNC(int) new_transaction(mem_zone_ref_ptr tx, ctime_t time)
{
	if (tx->zone==PTR_NULL)
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

	length = get_node_size(tx);
	buffer = (unsigned char *)malloc_c(length);
	write_node		(tx, buffer);
	mbedtls_sha256	(buffer, length, tx_hash, 0);
	mbedtls_sha256	(tx_hash, 32, hash, 0);
	free_c(buffer);
	tree_manager_set_child_value_i32(tx, "size", length);
	return 1;
}

/*
int SignatureHash(struct string scriptCode, mem_zone_ref txTo, unsigned int nIn, int nHashType)
{
	if (nIn >= txTo.vin.size())
	{
		LogPrintf("ERROR: SignatureHash() : nIn=%d out of range\n", nIn);
		return 1;
	}
	CTransaction txTmp(txTo);

	// In case concatenating two scripts ends up with two codeseparators,
	// or an extra one at the end, this prevents all those possible incompatibilities.
	scriptCode.FindAndDelete(CScript(OP_CODESEPARATOR));

	// Blank out other inputs' signatures
	for (unsigned int i = 0; i < txTmp.vin.size(); i++)
		txTmp.vin[i].scriptSig = CScript();
	txTmp.vin[nIn].scriptSig = scriptCode;

	// Blank out some of the outputs
	if ((nHashType & 0x1f) == SIGHASH_NONE)
	{
		// Wildcard payee
		txTmp.vout.clear();

		// Let the others update at will
		for (unsigned int i = 0; i < txTmp.vin.size(); i++)
			if (i != nIn)
				txTmp.vin[i].nSequence = 0;
	}
	else if ((nHashType & 0x1f) == SIGHASH_SINGLE)
	{
		// Only lock-in the txout payee at same index as txin
		unsigned int nOut = nIn;
		if (nOut >= txTmp.vout.size())
		{
			LogPrintf("ERROR: SignatureHash() : nOut=%d out of range\n", nOut);
			return 1;
		}
		txTmp.vout.resize(nOut + 1);
		for (unsigned int i = 0; i < nOut; i++)
			txTmp.vout[i].SetNull();

		// Let the others update at will
		for (unsigned int i = 0; i < txTmp.vin.size(); i++)
			if (i != nIn)
				txTmp.vin[i].nSequence = 0;
	}

	// Blank out other inputs completely, not recommended for open transactions
	if (nHashType & SIGHASH_ANYONECANPAY)
	{
		txTmp.vin[0] = txTmp.vin[nIn];
		txTmp.vin.resize(1);
	}

	// Serialize and hash
	CHashWriter ss(SER_GETHASH, 0);
	ss << txTmp << nHashType;
	return ss.GetHash();
}
*/


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

	length = get_node_size(block);
	buffer = malloc_c(length);
	write_node	(block, buffer);

	mbedtls_sha256(buffer, 80, (unsigned char*)checksum1, 0);
	mbedtls_sha256((unsigned char*)checksum1, 32, hash, 0);
	free_c(buffer);

	return 1;
}

OS_API_C_FUNC(int) set_block_hash(mem_zone_ref_ptr block)
{
	hash_t hash;
	compute_block_hash					(block, hash);
	tree_manager_set_child_value_bhash	(block, "blkHash", hash);
	return 1;
}

OS_API_C_FUNC(int) get_hash_list_from_tx(mem_zone_ref_ptr txs, mem_zone_ref_ptr hashes)
{
	mem_zone_ref		my_list = { PTR_NULL };
	mem_zone_ref_ptr	tx =  PTR_NULL ;
	int					n;

	for (n = 0, tree_manager_get_first_child(txs, &my_list, &tx); ((tx != NULL) && (tx->zone != NULL)); n++, tree_manager_get_next_child(&my_list, &tx))
	{
		hash_t h;
		compute_tx_hash						(tx, h);
		tree_manager_set_child_value_hash	(tx, "txid", h);
		tree_manager_write_node_hash		(hashes, n*sizeof(hash_t), h);
	}

	return n;
}

unsigned int compute_merkle_round(mem_zone_ref_ptr hashes,int cnt)
{
	int						i, newN;
	hash_t					tx_hash, tmp;
	mbedtls_sha256_context	ctx;

	newN = 0;
	for (i = 0; i < cnt; i += 2)
	{
		hash_t branch;
		mbedtls_sha256_init			(&ctx);
		mbedtls_sha256_starts		(&ctx, 0);

		tree_manager_get_node_hash	(hashes, i*sizeof(hash_t), tx_hash);
		mbedtls_sha256_update		(&ctx, tx_hash, sizeof(hash_t));

		if ((i + 1)<cnt)
			tree_manager_get_node_hash(hashes, (i + 1)*sizeof(hash_t), tx_hash);

		mbedtls_sha256_update	(&ctx, tx_hash, sizeof(hash_t));
		mbedtls_sha256_finish	(&ctx, tmp);
		mbedtls_sha256_free		(&ctx);

		mbedtls_sha256			(tmp, 32, branch, 0);

		tree_manager_write_node_hash(hashes, (newN++)*sizeof(hash_t), branch);
	}

	return newN;
}
OS_API_C_FUNC(int) build_merkel_tree(mem_zone_ref_ptr txs, hash_t merkleRoot)
{
	hash_t					tx_hash, tmp;
	mbedtls_sha256_context	ctx;
	mem_zone_ref			hashes = { PTR_NULL };
	int						n, i, newLen;

	if (!tree_manager_create_node("hashes", NODE_BITCORE_TX_HASH, &hashes))return 0;

	n	=	get_hash_list_from_tx(txs, &hashes);

	if (n == 0)
	{
		release_zone_ref(&hashes);
		return 0;
	}
	
	if (n == 1)
	{
		tree_manager_get_node_hash	(&hashes, 0, merkleRoot);
		release_zone_ref(&hashes);
		return 1;
	}
	if (n == 2)
	{
		mbedtls_sha256_init			(&ctx);
		mbedtls_sha256_starts		(&ctx, 0);
		

		tree_manager_get_node_hash	(&hashes, 0, tx_hash);
		mbedtls_sha256_update		(&ctx, tx_hash, sizeof(hash_t));

		tree_manager_get_node_hash	(&hashes, sizeof(hash_t), tx_hash);
		mbedtls_sha256_update		(&ctx, tx_hash, sizeof(hash_t));

		mbedtls_sha256_finish		(&ctx, tmp);
		mbedtls_sha256_free			(&ctx);
		mbedtls_sha256				(tmp, 32, merkleRoot, 0);
		release_zone_ref(&hashes);
		return 1;
	}


	while ((newLen=compute_merkle_round(&hashes, n))>1)
	{
		n = newLen;
	}
	
	tree_manager_get_node_hash	(&hashes, 0, merkleRoot);


	release_zone_ref			(&hashes);
	
	

	return 1;
}



OS_API_C_FUNC(unsigned int) SetCompact(unsigned int bits, hash_t out)
{
	unsigned int  nSize = bits >> 24;
	size_t		  ofset;

	memset_c(out, 0, 32);

	if (nSize < 32)
		ofset = 32 - nSize;
	else
		return 0;

	if (nSize >= 1) out[0 + ofset] = (bits >> 16) & 0xff;
	if (nSize >= 2) out[1 + ofset] = (bits >> 8) & 0xff;
	if (nSize >= 3) out[2 + ofset] = (bits >> 0) & 0xff;

	return 1;
}

OS_API_C_FUNC(int) cmp_hashle(hash_t hash1, hash_t hash2)
{
	int n = 32;
	while (n--)
	{
		if (hash1[n] < hash2[n])
			return 1;
		if (hash1[n] > hash2[n])
			return -1;
	}
	return 1;
}



OS_API_C_FUNC(void) mul_compact(unsigned int nBits, uint64_t op, hash_t hash)
{
	char dd[16];
	mem_zone_ref log = { PTR_NULL };
	unsigned int size,d;
	unsigned char *pdata;
	struct big64 bop;
	struct big128 data;
	int			n;
	size	= (nBits >> 24)-3;
	d		= (nBits & 0xFFFFFF);

	uitoa_s(nBits, dd, 16, 16);
	/*
	tree_manager_create_node("log", NODE_LOG_PARAMS, &log);
	tree_manager_set_child_value_str(&log, "nBits", dd);
	tree_manager_set_child_value_i64(&log, "op", op);
	log_message("mul compact %op% %nBits%", &log);
	release_zone_ref(&log);
	*/

	bop.m.v64 = op;
	big128_mul(d, bop, &data);

	//data	= mul64(d , op);

	memset_c(hash, 0, 32);

	pdata = (unsigned char *)data.v;

	n = 0;
	while ((n<16) && ((size+n)<32))
	{
		hash[size + n] = pdata[n];
		n++;
	}
}

unsigned int scale_compact(unsigned int nBits, uint64_t mop, uint64_t dop)
{
	unsigned int size;
	unsigned int ret;
	unsigned int bdata;
	uint64_t	data;
	size = (nBits >> 24);
	data = muldiv64(nBits & 0xFFFFFF, mop, dop);
	
	while (data&(~0xFFFFFFUL))
	{
		data=shr64(data, 8);
		size++;
	}
	bdata = data & 0x00FFFFFF;
	ret = ((size & 0xFF) << 24) | bdata;

	return ret;
}


OS_API_C_FUNC(unsigned int) calc_new_target(unsigned int nActualSpacing, unsigned int TargetSpacing, unsigned int nTargetTimespan,unsigned int pBits)
{
	unsigned int		nInterval;
	uint64_t			mulop , dividend;
	nInterval = nTargetTimespan / TargetSpacing;
	mulop  = ((nInterval - 1) * TargetSpacing + nActualSpacing + nActualSpacing);
	dividend  = ((nInterval + 1) * TargetSpacing);
	return scale_compact(pBits, mulop, dividend);
}

OS_API_C_FUNC(int) block_compute_pow_target(mem_zone_ref_ptr ActualSpacing, mem_zone_ref_ptr nBits)
{
	hash_t				out_diff, Difflimit;
	unsigned int		nActualSpacing;
	unsigned int		pNBits, pBits;

	tree_mamanger_get_node_dword(ActualSpacing, 0, &nActualSpacing);
	tree_mamanger_get_node_dword(nBits, 0, &pBits);

	if (nActualSpacing == 0)
	{
		tree_manager_write_node_dword(nBits, 0, diff_limit);
		return 1;
	}

	if (nActualSpacing > MaxTargetSpacing )
		nActualSpacing = MaxTargetSpacing;

	pNBits = calc_new_target(nActualSpacing, TargetSpacing, TargetTimespan, pBits);

	SetCompact(pNBits, out_diff);
	SetCompact(diff_limit, Difflimit);
	if (memcmp_c(out_diff, Difflimit, sizeof(hash_t)) > 0)
		pNBits = diff_limit;

	tree_manager_write_node_dword(nBits, 0, pNBits);
	return 1;
}



OS_API_C_FUNC(int) get_tx_input(mem_zone_ref_const_ptr tx, unsigned int idx, mem_zone_ref_ptr vin)
{
	int ret;
	mem_zone_ref txin_list = { PTR_NULL };

	if (!tree_manager_find_child_node(tx, NODE_HASH("txsin"), NODE_BITCORE_VINLIST, &txin_list))return 0;
	ret = tree_manager_get_child_at(&txin_list, idx, vin);
	release_zone_ref(&txin_list);
	return ret;

}
OS_API_C_FUNC(int) get_tx_output(mem_zone_ref_const_ptr tx, unsigned int idx, mem_zone_ref_ptr vout)
{
	int ret;
	mem_zone_ref txout_list = { PTR_NULL };

	if (!tree_manager_find_child_node(tx, NODE_HASH("txsout"), NODE_BITCORE_VOUTLIST, &txout_list))return 0;
	ret = tree_manager_get_child_at(&txout_list, idx, vout);
	release_zone_ref(&txout_list);
	return ret;

}


OS_API_C_FUNC(int) load_tx_input(mem_zone_ref_const_ptr tx, unsigned int idx, mem_zone_ref_ptr	in, mem_zone_ref_ptr tx_out)
{
	hash_t			prev_hash, blk_hash;
	int				ret=0;

	if (!get_tx_input(tx, idx, in))return 0;

	ret = tree_manager_get_child_value_hash(in, NODE_HASH("txid"), prev_hash);
	if(ret)ret = load_tx(tx_out, blk_hash, prev_hash);
	if (!ret)release_zone_ref(in);

	/*
	ret = tree_manager_find_child_node(vin, NODE_HASH("prev tx"), NODE_BITCORE_TX, tx_out);
	if (!ret)
	{
	if(tree_manager_add_child_node(vin, "prev tx", NODE_BITCORE_TX, tx_out))
	ret=load_tx(tx_out, prev_hash);
	}
	*/
	return ret;

}
OS_API_C_FUNC(int) load_blk_tx_input(const char *blk_hash, unsigned int tx_idx, unsigned int vin_idx, mem_zone_ref_ptr vout)
{
	int				ret=0;
	mem_zone_ref vin = { PTR_NULL };
	mem_zone_ref tx = { PTR_NULL }, prev_tx = { PTR_NULL };

	if (!load_blk_tx(&tx, blk_hash, tx_idx))return 0;

	if (load_tx_input(&tx, vin_idx, &vin, &prev_tx))
	{
		hash_t prevOutHash;
		unsigned int prevOutIdx;
		tree_manager_get_child_value_hash(&vin, NODE_HASH("txid"), prevOutHash);
		tree_manager_get_child_value_i32(&vin, NODE_HASH("idx"), &prevOutIdx);
		ret = get_tx_output(&prev_tx, prevOutIdx, vout);
		release_zone_ref(&prev_tx);
		release_zone_ref(&vin);
	}
	release_zone_ref(&tx);

	return ret;
}
OS_API_C_FUNC(int) load_tx_input_vout(mem_zone_ref_const_ptr tx, unsigned int vin_idx, mem_zone_ref_ptr vout)
{
	hash_t			prevOutHash;
	mem_zone_ref	vin = { PTR_NULL };
	mem_zone_ref	prev_tx = { PTR_NULL };
	unsigned int	prevOutIdx;
	int				ret = 0;

	if (!load_tx_input(tx, vin_idx, &vin, &prev_tx))return 0;
	
	tree_manager_get_child_value_hash(&vin, NODE_HASH("txid"), prevOutHash);
	tree_manager_get_child_value_i32(&vin, NODE_HASH("idx"), &prevOutIdx);
	ret = get_tx_output(&prev_tx, prevOutIdx, vout);
	release_zone_ref(&prev_tx);
	release_zone_ref(&vin);
	
	return ret;
}
int is_coinbase(mem_zone_ref_const_ptr tx)
{
	hash_t prev_hash;
	mem_zone_ref txin_list = { PTR_NULL }, input = { PTR_NULL };
	unsigned int oidx;
	int ret;

	if (!tree_manager_find_child_node(tx, NODE_HASH("txsin"), NODE_BITCORE_VINLIST, &txin_list))return 0;
	ret = tree_manager_get_child_at(&txin_list, 0, &input);
	release_zone_ref(&txin_list);
	if (!ret)return 0;

	ret = tree_manager_get_child_value_hash(&input, NODE_HASH("txid"), prev_hash);
	if (ret)ret = tree_manager_get_child_value_i32(&input, NODE_HASH("idx"), &oidx);
	release_zone_ref(&input);
	if (!ret)return 0;
	if ((!memcmp_c(prev_hash, null_hash, 32)) && (oidx >= 0xFFFF))
		return 1;

	return 0;
}



OS_API_C_FUNC(int) get_tx_input_hash(mem_zone_ref_ptr tx,unsigned int idx, hash_t hash)
{
	mem_zone_ref txin_list = { PTR_NULL }, input = { PTR_NULL};
	int			 ret;

	if (!tree_manager_find_child_node	(tx, NODE_HASH("txsin"), NODE_BITCORE_VINLIST, &txin_list))return 0;
	
	ret = tree_manager_get_child_at(&txin_list, idx, &input);
	if (ret)
		tree_manager_get_child_value_hash(&input, NODE_HASH("txid"), hash);

	release_zone_ref(&txin_list);
	release_zone_ref(&input);

	return ret;
}

OS_API_C_FUNC(int) get_tx_output_script(const hash_t tx_hash, unsigned int idx, struct string *script,uint64_t *amount)
{
	hash_t			blkhash;
	mem_zone_ref	tx = { PTR_NULL }, vout = { PTR_NULL };
	int				ret;

	if (!load_tx(&tx, blkhash, tx_hash))return 0;
	ret = get_tx_output(&tx, idx, &vout);
	if (ret)
	{
		ret = tree_manager_get_child_value_istr(&vout, NODE_HASH("script"), script,0);
		ret = tree_manager_get_child_value_i64 (&vout, NODE_HASH("value"), amount);
		release_zone_ref(&vout);
	}
	release_zone_ref(&tx);
	return ret;
}

OS_API_C_FUNC(int) get_tx_output_amount(mem_zone_ref_ptr tx, unsigned int idx, uint64_t *amount)
{
	mem_zone_ref	vout = { PTR_NULL };
	int				ret;

	if (!get_tx_output(tx, idx, &vout))return 0;

	ret = tree_manager_get_child_value_i64(&vout, NODE_HASH("value"), amount);
	release_zone_ref(&vout);
	return ret;
}

OS_API_C_FUNC(int) load_tx_output_amount(const hash_t tx_hash, unsigned int idx, uint64_t *amount)
{
	hash_t			blkhash;
	mem_zone_ref	tx = { PTR_NULL }, vout = { PTR_NULL };
	int				ret;
	if (!load_tx(&tx, blkhash, tx_hash))return 0;
	ret=get_tx_output_amount(&tx, idx, amount);
	release_zone_ref(&tx);
	return ret;
}

OS_API_C_FUNC(int) get_tx_output_addr(const hash_t tx_hash, unsigned int idx, btc_addr_t addr)
{
	hash_t			blkhash;
	mem_zone_ref	tx = { PTR_NULL }, vout = { PTR_NULL };
	int				ret;

	if (!load_tx(&tx, blkhash, tx_hash))return 0;
	ret = get_tx_output(&tx, idx, &vout);
	if (ret)
	{
		struct string  script;
		ret = tree_manager_get_child_value_istr(&vout, NODE_HASH("script"), &script,0);
		if (ret)
		{
			get_out_script_address(&script, PTR_NULL,addr);
			free_string(&script);
		}
		release_zone_ref(&vout);
	}
	release_zone_ref(&tx);
	return ret;
}


OS_API_C_FUNC(int) is_vout_null(mem_zone_ref_const_ptr tx, unsigned int idx)
{
	uint64_t		amount;
	struct string	script = { PTR_NULL };
	mem_zone_ref vout = { PTR_NULL };
	int			ret;
	if (!get_tx_output(tx, idx, &vout))return 0;

	ret = tree_manager_get_child_value_i64(&vout, NODE_HASH("value"), &amount);
	if ((ret) && (amount > 0))
		ret = 0;

	if (ret)
		ret = tree_manager_get_child_value_istr(&vout, NODE_HASH("script"), &script, 0);

	if ((ret) && (script.str[0] != 0))
		ret = 0;

	free_string(&script);
	release_zone_ref(&vout);

	return ret;
}

OS_API_C_FUNC(int) create_null_tx(mem_zone_ref_ptr tx,unsigned int time,unsigned int block_height)
{
	mem_zone_ref	script_node = { PTR_NULL };
	struct string	nullscript = { PTR_NULL };
	struct string	coinbasescript = { PTR_NULL };
	char			null = 0;
	char			script[8];

	
	nullscript.str = &null;
	nullscript.len = 0;
	nullscript.size = 1;

	coinbasescript.str  = script;
	coinbasescript.len  = 4;
	coinbasescript.size = 4;

	script[0]							= 3;
	*((unsigned int *)(script + 1))		= block_height;

	new_transaction (tx, time);
	tx_add_input(tx, null_hash, 0xFFFFFFFF, &coinbasescript);
	tx_add_output	(tx,0, &nullscript);
	return 1;
}

OS_API_C_FUNC(int) is_tx_null(mem_zone_ref_const_ptr tx)
{
	struct string	script = { 0 };
	mem_zone_ref	vout = { PTR_NULL };
	mem_zone_ref	txout_list = { PTR_NULL };
	uint64_t		amount;
	int				ret, nc;


	if (!tree_manager_find_child_node(tx, NODE_HASH("txsout"), NODE_BITCORE_VOUTLIST, &txout_list))return -1;
	nc = tree_manager_get_node_num_children(&txout_list);
	if (nc == 0)
	{
		release_zone_ref(&txout_list);
		return -1;
	}
	ret = tree_manager_get_child_at(&txout_list, 0, &vout);
	release_zone_ref(&txout_list);
	if (!ret)return -1;
	ret = tree_manager_get_child_value_i64(&vout, NODE_HASH("value"), &amount);
	if (ret)ret = tree_manager_get_child_value_istr(&vout, NODE_HASH("script"), &script, 0);
	release_zone_ref(&vout);
	if (!ret)return -1;
	if ((nc == 1) && (amount == 0) && (script.str[0] == 0))
		ret = 1;
	else
		ret = 0;

	free_string(&script);
	return ret;
}
OS_API_C_FUNC(int) hash_equal(hash_t hash, const char *shash)
{
	int n = 0;
	while (n < 32)
	{
		char hex[3] = { shash[n * 2], shash[n * 2 + 1], 0 };
		unsigned char uc;
		uc = strtoul_c(hex, PTR_NULL, 16);
		if (hash[31 - n] != uc)
			return 0;

		n++;
	}
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
		tree_manager_get_child_value_hash(hdr, NODE_HASH("blkHash"), blk_hash);
		tree_manager_set_child_value_bhash(hash_list, idx, blk_hash);
	}
	return n;
}



OS_API_C_FUNC(int) check_tx_outputs(mem_zone_ref_ptr tx, uint64_t *total, unsigned int *is_staking)
{
	mem_zone_ref		txout_list = { PTR_NULL }, my_list = { PTR_NULL };
	mem_zone_ref_ptr	out = PTR_NULL;
	unsigned int		idx;

	*is_staking = 0;
	if (!tree_manager_find_child_node(tx, NODE_HASH("txsout"), NODE_BITCORE_VOUTLIST, &txout_list))return 0;
	for (idx = 0, tree_manager_get_first_child(&txout_list, &my_list, &out); ((out != NULL) && (out->zone != NULL)); idx++,tree_manager_get_next_child(&my_list, &out))
	{
		uint64_t		amount=0;
		if (!tree_manager_get_child_value_i64(out, NODE_HASH("value"), &amount))continue;
		if ((idx == 0) && (amount == 0))
		{
			struct string script = { 0 };
			if (tree_manager_get_child_value_istr(out, NODE_HASH("script"), &script, 16))
			{
				if ((script.str[0] == 0))
					*is_staking = 1;
				free_string(&script);
			}
		}
		else
		{
			struct string script = { 0 };
			if (tree_manager_get_child_value_istr(out, NODE_HASH("script"), &script, 16))
			{
				btc_addr_t		addr;
				struct string	pubk = { PTR_NULL };

				if (get_out_script_address(&script, &pubk, addr))
				{
					tree_manager_set_child_value_btcaddr(out, "dstaddr", addr);
					free_string(&pubk);
				}
				free_string(&script);
			}
			*total += amount;
		}
	}
	release_zone_ref(&txout_list);
	return 1;
}

/*
OS_API_C_FUNC(int) check_tx_sign(mem_zone_ref_ptr tx)
{
	mem_zone_ref		txin_list = { PTR_NULL }, my_list = { PTR_NULL };
	mem_zone_ref_ptr	input = PTR_NULL;
	int					ret=1;

	if (!tree_manager_find_child_node(tx, NODE_HASH("txsin"), NODE_BITCORE_VINLIST, &txin_list))
		return 0;

	for (tree_manager_get_first_child(&txin_list, &my_list, &input); ((input != PTR_NULL) && (input->zone != PTR_NULL)); tree_manager_get_next_child(&my_list, &input))
	{
		char pkey[33];
		hash_t txh;
		struct string t;
		if (ret == 0)continue;

		if (!tree_manager_get_child_value_hash(tx, NODE_HASH("txid"), txh))
			compute_tx_hash(tx, txh);

		if (check_txin_sign(input,pkey,txh) != 0)
			ret = 0;
	}
	release_zone_ref(&txin_list);
	return ret;
}
OS_API_C_FUNC(int) check_tx_hash_sign(hash_t tx_hash)
{
	hash_t blk_hash;
	mem_zone_ref tx = { PTR_NULL };
	int ret;
	if (!load_tx(&tx, blk_hash, tx_hash))return 0;
	ret=check_tx_sign(&tx);
	release_zone_ref(&tx);
	return ret;
}
*/

OS_API_C_FUNC(int) compute_tx_sign_hash(mem_zone_ref_const_ptr tx, unsigned int nIn, const struct string *script, unsigned int hash_type, hash_t txh)
{
	hash_t				tx_hash;
	mem_zone_ref		txin_list = { PTR_NULL }, my_list = { PTR_NULL }, txTmp = { PTR_NULL };
	mem_zone_ref_ptr	input = PTR_NULL;
	size_t				length;
	unsigned char		*buffer;
	unsigned int		iidx;

	tree_manager_node_dup(PTR_NULL, tx, &txTmp);
	if (!tree_manager_find_child_node(&txTmp, NODE_HASH("txsin"), NODE_BITCORE_VINLIST, &txin_list))
		return 0;

	for (iidx = 0, tree_manager_get_first_child(&txin_list, &my_list, &input); ((input != PTR_NULL) && (input->zone != PTR_NULL)); tree_manager_get_next_child(&my_list, &input), iidx++)
	{
		if (nIn == iidx)
			tree_manager_set_child_value_vstr(input, "script", script);
		else
			tree_manager_set_child_value_str(input, "script", "");
	}

	release_zone_ref(&txin_list);

	length = get_node_size(&txTmp);
	buffer = (unsigned char *)malloc_c(length + 4);
	*((unsigned int *)(buffer + length)) = hash_type;

	write_node(&txTmp, buffer);
	mbedtls_sha256(buffer, length + 4, tx_hash, 0);
	mbedtls_sha256(tx_hash, 32, txh, 0);
	free_c(buffer);
	release_zone_ref(&txTmp);

	return 1;

}
OS_API_C_FUNC(int) blk_check_sign(const struct string *sign, const struct string *pubk, const hash_t hash)
{
	return check_sign(sign, pubk, hash);
}

OS_API_C_FUNC(int) check_tx_input_sig(mem_zone_ref_ptr tx, unsigned int nIn, struct string *vpubK)
{
	hash_t			txsh;
	struct string	oscript = { PTR_NULL }, script = { PTR_NULL }, sign = { PTR_NULL }, blksign = { PTR_NULL };
	mem_zone_ref	prev_tx = { PTR_NULL };
	mem_zone_ref	out = { PTR_NULL }, in = { PTR_NULL };
	unsigned int	prevOutIdx;
	unsigned char	hash_type;
	int				ret = 0;

	if (!load_tx_input(tx, nIn, &in, &prev_tx))return 0;
	tree_manager_get_child_value_i32(&in, NODE_HASH("idx"), &prevOutIdx);
	ret = get_tx_output(&prev_tx, prevOutIdx, &out);
	release_zone_ref(&prev_tx);
	
	if (ret)ret = tree_manager_get_child_value_istr		(&in	, NODE_HASH("script"), &script, 0);
	if (ret)ret = get_insig_info						(&script, &sign, vpubK, &hash_type);

	release_zone_ref	(&in);
	free_string			(&script);
	

	if (ret)ret = tree_manager_get_child_value_istr(&out, NODE_HASH("script"), &oscript, 0);
	if (ret)ret = compute_tx_sign_hash(tx, 0, &oscript, hash_type, txsh);
	if (ret)
	{
		if (vpubK->len < 31)
		{
			btc_addr_t addr;
			free_string(vpubK);
			ret = get_out_script_address(&oscript, vpubK, addr);
		}
		if(ret)ret = blk_check_sign(&sign, vpubK, txsh);
	}

	free_string			(&oscript);
	release_zone_ref	(&out);
	free_string			(&sign);
	release_zone_ref	(&out);

	return ret;
}

OS_API_C_FUNC(int) tx_sign(mem_zone_ref_const_ptr tx, unsigned int nIn, unsigned int hashType, const struct string *sign_seq, const struct string *inPubKey)
{
	hash_t				tx_hash;
	struct				string oscript = { PTR_NULL };
	mem_zone_ref		vin = { PTR_NULL }, vout = { PTR_NULL };
	int					ret=0;
	if (load_tx_input_vout(tx, nIn, &vout))
	{
		tree_manager_get_child_value_istr	(&vout	, NODE_HASH("script"), &oscript , 0);
		if (compute_tx_sign_hash(tx, nIn, &oscript, hashType, tx_hash))
		{
			btc_addr_t		addr;
			struct string	pubk = { PTR_NULL };
			get_out_script_address(&oscript, &pubk, addr);
			if (pubk.len > 0)
			{
				struct string			sign = { 0 };
				unsigned char			htype;
				if (parse_sig_seq(sign_seq, &sign, &htype, 1))
				{
					ret = check_sign	(&sign, &pubk, tx_hash);
					free_string			(&sign);
					if (ret)
					{
						if (get_tx_input(tx, nIn, &vin))
						{
							struct string sscript = { PTR_NULL };
							mem_zone_ref script_node = { PTR_NULL };
							tree_manager_create_node			("script", NODE_BITCORE_SCRIPT, &script_node);
							tree_manager_set_child_value_vstr	(&script_node, "var1", sign_seq);
							//tree_manager_set_child_value_vstr	(&script_node, "var2", &pubk);
							serialize_script					(&script_node, &sscript);
							release_zone_ref					(&script_node);
							tree_manager_set_child_value_vstr	(&vin, "script", &sscript);
							free_string							(&sscript);
							release_zone_ref					(&vin);
						}
					}
				}
				free_string(&pubk);
			}
			else if ((inPubKey != PTR_NULL) && (inPubKey->str!=PTR_NULL))
			{
				btc_addr_t				inAddr;
				struct string			sign = { PTR_NULL };
				unsigned char			htype;

				key_to_addr						(inPubKey->str, inAddr);
				ret = (memcmp_c(inAddr, addr, sizeof(btc_addr_t)) == 0) ? 1 : 0;
				if (ret)ret = parse_sig_seq		(sign_seq, &sign, &htype, 1);
				if (ret)ret = check_sign		(&sign, inPubKey, tx_hash);
				if (ret)
				{
					if (get_tx_input(tx, nIn, &vin))
					{
						mem_zone_ref script_node = { PTR_NULL };
						
						if(tree_manager_create_node("script", NODE_BITCORE_SCRIPT, &script_node))
						{
							struct string sscript = { PTR_NULL };

							tree_manager_set_child_value_vstr	(&script_node, "var1", sign_seq);
							tree_manager_set_child_value_vstr	(&script_node, "var2", inPubKey);
							serialize_script					(&script_node, &sscript);
							tree_manager_set_child_value_vstr	(&vin, "script", &sscript);
							release_zone_ref					(&script_node);
							free_string							(&sscript);
						}
						release_zone_ref					(&vin);
					}
				}
				free_string						(&sign);
			}
			else
				ret=0;

			free_string(&oscript);
		}
		release_zone_ref(&vout);
	}
	return ret;
}




OS_API_C_FUNC(int) check_tx_inputs(mem_zone_ref_ptr tx, uint64_t *total_in, unsigned int *is_coinbase)
{
	mem_zone_ref		txin_list = { PTR_NULL }, my_list = { PTR_NULL };
	mem_zone_ref_ptr	input = PTR_NULL;
	unsigned int		iidx;
	int ret;

	if (!tree_manager_find_child_node(tx, NODE_HASH("txsin"), NODE_BITCORE_VINLIST, &txin_list))
		return 0;
	
	*total_in = 0;

	for (iidx = 0, tree_manager_get_first_child(&txin_list, &my_list, &input); ((input != PTR_NULL) && (input->zone != PTR_NULL)); tree_manager_get_next_child(&my_list, &input), iidx++)
	{
		hash_t				pBlock;
		hash_t				prev_hash;
		char				cphash[65], ctphash[65];
		struct string		tx_path = { PTR_NULL };
		uint64_t			amount = 0;
		unsigned int		oidx = 0;
		int					n = 0;

		memset_c(cphash, 0, 65);
		memset_c(ctphash, 0, 65);
		memset_c(prev_hash, 0, sizeof(hash_t));
		memset_c(pBlock, 0, sizeof(hash_t));

		

		tree_manager_get_child_value_hash(input, NODE_HASH("txid"), prev_hash);
		tree_manager_get_child_value_i32(input, NODE_HASH("idx"), &oidx);

		if ((!memcmp_c(prev_hash, null_hash, 32)) && (oidx >= 0xFFFF))
		{
			
			if ((*is_coinbase) == 0)
			{
				*is_coinbase = 1;
				continue;
			}
			release_zone_ref(&my_list);
			dec_zone_ref(input);
			release_zone_ref(&txin_list);
			return 0;
		}
		else
		{

			mem_zone_ref		prevout = { PTR_NULL }, prev_tx = { PTR_NULL };
			struct string		oscript = { 0 };

			ret			= load_tx(&prev_tx, pBlock, prev_hash);

			if (ret)
			{
				n = 0;
				while (n < 32)
				{
					cphash[n * 2 + 0] = hex_chars[prev_hash[n] >> 0x04];
					cphash[n * 2 + 1] = hex_chars[prev_hash[n] & 0x0F];
					n++;
				}
				cphash[64] = 0;
				n = 0;
				while (n < 32)
				{
					ctphash[n * 2 + 0] = hex_chars[pBlock[n] >> 4];
					ctphash[n * 2 + 1] = hex_chars[pBlock[n] & 0x0F];
					n++;
				}
				ctphash[64] = 0;

				

				make_string(&tx_path, "blks");
				cat_ncstring_p(&tx_path, ctphash + 0, 2);
				cat_ncstring_p(&tx_path, ctphash + 2, 2);
				cat_cstring_p(&tx_path, ctphash);
				cat_cstring_p(&tx_path, cphash);
				cat_cstring(&tx_path, "_out_");
				strcat_int(&tx_path, oidx);
				ret = (stat_file(tx_path.str) == 0) ? 1 : 0;
				free_string(&tx_path);
				
				if ((ret)&&(get_tx_output(&prev_tx, oidx, &prevout)))
				{
					struct string	script = { PTR_NULL }, sign = { PTR_NULL }, sigseq = { PTR_NULL }, vpubK = { PTR_NULL };
					mem_zone_ref	txTmp = { PTR_NULL };
					size_t			offset = 0;
					unsigned char	hash_type;

					tree_manager_get_child_value_i64(&prevout, NODE_HASH("value"), &amount);
					tree_manager_get_child_value_istr(&prevout, NODE_HASH("script"), &oscript, 0);
					tree_manager_get_child_value_istr(input, NODE_HASH("script"), &script, 0);
					ret = get_insig_info(&script, &sign, &vpubK, &hash_type);
					if (ret)
					{
						btc_addr_t addr;

						if (vpubK.len == 0)
						{
							free_string						(&vpubK);
							ret = get_out_script_address	(&oscript, &vpubK, addr);

							if (!ret)log_output("unable to parse input addr \n");
						}
						else
						{
							ret = check_txout_key(&prevout, vpubK.str, addr);
							if (!ret)log_output("check input pkey hash failed\n");
						}
						
						if (ret)
						{
							if (checktxsign)
							{
								hash_t txh;

								ret = compute_tx_sign_hash(tx, iidx, &oscript, hash_type, txh);
								if (ret)ret = check_sign(&sign, &vpubK, txh);
							}
						}

						if (ret)tree_manager_set_child_value_btcaddr(input, "srcaddr", addr);
						if (ret)tree_manager_set_child_value_i64(input, "value", amount);
						
						free_string(&vpubK);
						free_string(&sign);
					}

					free_string(&script);
					free_string(&oscript);
					release_zone_ref(&prevout);
				}
				release_zone_ref(&prev_tx);
			}
		}

		if (!ret)
		{
			char iStr[16];

			itoa_s			(iidx, iStr, 16, 10);
			log_output		("check input failed at input #");
			log_output		(iStr);
			log_output		("\n");

			release_zone_ref	(&my_list);
			dec_zone_ref		(input);
			release_zone_ref	(&txin_list);
			return 0;
		}
		(*total_in) += amount;
	}
	release_zone_ref(&txin_list);
	return 1;
}


OS_API_C_FUNC(int) check_tx_list(mem_zone_ref_ptr tx_list,uint64_t block_reward,hash_t merkle)
{
	hash_t				merkleRoot;
	mem_zone_ref		my_list = { PTR_NULL };
	mem_zone_ref_ptr	tx = PTR_NULL;
	uint64_t			list_reward;
	int					ret;
	unsigned int		coinbase, coinstaking, is_staking, is_coinbase;
	uint64_t			txFee, fees;

	build_merkel_tree	(tx_list, merkleRoot);

	if (memcmp_c(merkleRoot, merkle,sizeof(hash_t)))
	{
		log_output("bad merkle root");
		return 0;
	}
	tree_manager_get_first_child	(tx_list, &my_list, &tx);

	if (is_tx_null(tx))
	{
		tree_manager_get_next_child(&my_list, &tx);
		coinbase = 0;
		coinstaking = 1;
	}
	else
	{
		coinbase = 1;
		coinstaking = 0;
	}

	list_reward = 0;
	fees = 0;

	

	ret = 1;
	for (; ((tx != PTR_NULL) && (tx->zone != PTR_NULL)); tree_manager_get_next_child(&my_list, &tx))
	{
		struct string		tx_path = { 0 };
		uint64_t			total_in, total_out;
		mem_zone_ref		txin_list = { PTR_NULL }, my_llist = { PTR_NULL };
		mem_zone_ref_ptr	input = PTR_NULL;

		is_staking = 0;
		is_coinbase = 0;
		total_out = 0;
		total_in = 0;

		if (is_tx_null(tx))
			continue;

		
		if (!check_tx_inputs(tx, &total_in, &is_coinbase))
		{
			dec_zone_ref(tx);
			release_zone_ref(&my_list);
			return 0;
		}
		
		check_tx_outputs(tx, &total_out, &is_staking);
			
		
		if (is_staking)
		{
			if (coinstaking == 0)
			{
				dec_zone_ref(tx);
				release_zone_ref(&my_list);
				return 0;
			}
			coinstaking = 0;
			list_reward = total_out - total_in;
		}
		else if (is_coinbase)
		{
			if (coinbase == 0)
			{
				dec_zone_ref(tx);
				release_zone_ref(&my_list);
				return 0;
			}
			coinbase	= 0;
			list_reward = total_out - total_in;
		}
		else
		{
			txFee = total_in - total_out;
			fees += txFee;
		}
	}

	if (!ret)
	{
		log_output("error tx\n");
		return 0;
	}
	if (list_reward > (block_reward + fees))
	{
		log_output("bad tx reward\n");
		return 0;
	}
	
	return 1;
}



OS_API_C_FUNC(int) check_block_pow(mem_zone_ref_ptr hdr,hash_t diff_hash)
{
	hash_t				blk_pow, rdiff;
	mem_zone_ref		log={PTR_NULL};
	char				rpow[32];
	hash_t				bhash;
	int					n= 32;
	
	//pow block

	if (!tree_manager_get_child_value_hash(hdr, NODE_HASH("blkHash"), bhash))
	{
		compute_block_hash					(hdr, bhash);
		tree_manager_set_child_value_bhash	(hdr, "blkHash", bhash);
	}
	if (!tree_manager_get_child_value_hash(hdr, NODE_HASH("blk pow"), blk_pow))
	{
		compute_block_pow					(hdr, blk_pow);
		tree_manager_set_child_value_hash	(hdr, "blk pow", blk_pow);
	}
	n = 32;
	while (n--)
	{
		rdiff[n] = diff_hash[31 - n];
		rpow[n]  = blk_pow[31 - n];
	}
	//compare pow & diff
	if (cmp_hashle(blk_pow, rdiff) == 1)
	{
		tree_manager_create_node("log", NODE_LOG_PARAMS, &log);
		tree_manager_set_child_value_hash(&log, "diff", diff_hash);
		tree_manager_set_child_value_hash(&log, "pow", rpow);
		tree_manager_set_child_value_hash(&log, "hash", bhash);
		log_message("----------------\nNEW POW BLOCK\n%diff%\n%pow%\n%hash%\n", &log);
		release_zone_ref(&log);
		return 1;
	}
	else
	{
		tree_manager_create_node("log", NODE_LOG_PARAMS, &log);
		tree_manager_set_child_value_hash(&log, "diff", diff_hash);
		tree_manager_set_child_value_hash(&log, "pow" , rpow);
		tree_manager_set_child_value_hash(&log, "hash", bhash);
		log_message("----------------\nBAD POW BLOCK\n%diff%\n%pow%\n%hash%\n", &log);
		release_zone_ref(&log);
		return 0;
	}
	
}


OS_API_C_FUNC(int)  get_prev_block_time(mem_zone_ref_ptr header, ctime_t *time)
{
	char prevHash[65];
	struct string blk_path = { 0 };
	
	if (!tree_manager_get_child_value_str(header, NODE_HASH("prev"), prevHash,65,16))return 0;
	return get_block_time(prevHash, time);
}






OS_API_C_FUNC(int) block_has_pow(mem_zone_ref_ptr blockHash)
{
	char blk_hash[65];
	if (!tree_manager_get_node_str(blockHash, 0, blk_hash, 65, 16))return 0;
	return is_pow_block(blk_hash);
}
int make_iadix_merkle(mem_zone_ref_ptr genesis,mem_zone_ref_ptr txs,hash_t merkle)
{
	mem_zone_ref	newtx = { PTR_NULL };
	mem_zone_ref	script_node = { PTR_NULL };
	struct string	out_script = { PTR_NULL }, script = { PTR_NULL };
	struct string	timeproof = { PTR_NULL };

	make_string(&timeproof, "1 Sep 2016 Iadix coin");
	tree_manager_create_node("script", NODE_BITCORE_SCRIPT, &script_node);
	tree_manager_set_child_value_vint32(&script_node, "0", 0);
	tree_manager_set_child_value_vint32(&script_node, "1", 42);
	tree_manager_set_child_value_vstr(&script_node, "2", &timeproof);
	serialize_script		(&script_node, &script);
	release_zone_ref		(&script_node);

	new_transaction				(&newtx, 1466419086);
	tx_add_input				(&newtx, null_hash, 0xFFFFFFFF, &script);
	tx_add_output				(&newtx, 0, &out_script);
	free_string					(&script);
	free_string					(&timeproof);
	tree_manager_node_add_child (txs, &newtx);
	release_zone_ref			(&newtx);
	build_merkel_tree			(txs, merkle);
	
	return 0;
}


OS_API_C_FUNC(int) make_genesis_block(mem_zone_ref_ptr genesis_conf,mem_zone_ref_ptr genesis)
{
	hash_t								blk_pow, merkle;
	mem_zone_ref						txs = { PTR_NULL };
	uint64_t							StakeMod;
	unsigned int						version, time, bits, nonce;
	hash_t								hmod;
	

	if (genesis->zone == PTR_NULL)
	{
		if (!tree_manager_create_node("genesis", NODE_BITCORE_BLK_HDR, genesis))
			return 0;
	}
	
	if (!tree_manager_create_node("txs", NODE_BITCORE_TX_LIST, &txs))
		return 0;
	
	if (!tree_manager_get_child_value_hash(genesis_conf, NODE_HASH("merkle_root"), merkle))
	{
		make_iadix_merkle					(genesis, &txs, merkle);

		/*
		printf("genesis merkle:\n");
		for (n = 0; n < 32; n++){printf("%02x", merkle[31 - n]);}
		printf("\n");
		*/
	}
	
	tree_manager_set_child_value_hash	(genesis, "merkle_root"			, merkle);
	tree_manager_set_child_value_hash	(genesis, "prev"					, null_hash);

	tree_manager_get_child_value_i32	(genesis_conf, NODE_HASH("version")	, &version);
	tree_manager_get_child_value_i32	(genesis_conf, NODE_HASH("time")	, &time);
	tree_manager_get_child_value_i32	(genesis_conf, NODE_HASH("bits")	, &bits);
	tree_manager_get_child_value_i32	(genesis_conf, NODE_HASH("nonce")	, &nonce);




	tree_manager_set_child_value_i32	(genesis, "version"			, version);
	tree_manager_set_child_value_i32	(genesis, "time"			, time);
	tree_manager_set_child_value_i32	(genesis, "bits"			, bits);
	tree_manager_set_child_value_i32	(genesis, "nonce"			, nonce);
	
	tree_manager_node_add_child			(genesis, &txs);

	compute_block_pow					(genesis, blk_pow);
	tree_manager_set_child_value_bhash	(genesis, "blkHash", blk_pow);
	tree_manager_set_child_value_hash	(genesis, "blk pow" , blk_pow);

	/*
	printf("genesis block hash :\n");
	for (n = 0; n < 32; n++){ printf("%02x", blk_pow[31 - n]); }
	printf("\n");
	*/
	
	if (tree_manager_get_child_value_i64(genesis_conf, NODE_HASH("InitialStakeModifier"), &StakeMod))
		tree_manager_set_child_value_i64(genesis, "StakeMod", StakeMod);

	if (tree_manager_get_child_value_hash(genesis_conf, NODE_HASH("InitialStakeModifier2"), hmod))
		tree_manager_set_child_value_hash(genesis, "StakeMod2", hmod);

	if (!find_hash(blk_pow))
		store_block		(genesis, &txs);

	release_zone_ref(&txs);
	return 1;

}