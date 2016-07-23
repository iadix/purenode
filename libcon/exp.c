#define LIBC_API C_EXPORT

#include "base/std_def.h"
#include "base/std_mem.h"
#include "base/mem_base.h"
#include "base/std_str.h"
#include "base/utf.h"

#include "strs.h"

#define KERNEL_API C_EXPORT
#include "mem_stream.h"
#include "tpo_mod.h"
#include "fsio.h"
#include "zlib.h"
#include "xmlparse.h"

void init_funcs()
{
	sys_add_tpo_mod_func_name("libcon", "utf8_encode", utf8_encode, 0);
	sys_add_tpo_mod_func_name("libcon", "utf8_check_first", utf8_check_first, 0);
	sys_add_tpo_mod_func_name("libcon", "utf8_check_full", utf8_check_full, 0);

	sys_add_tpo_mod_func_name("libcon", "console_print", console_print, 0);
	sys_add_tpo_mod_func_name("libcon", "stat_file", stat_file, 0);
	sys_add_tpo_mod_func_name("libcon", "create_dir", create_dir, 0);
	sys_add_tpo_mod_func_name("libcon", "put_file", put_file, 0);
	sys_add_tpo_mod_func_name("libcon", "get_file", get_file, 0);
	sys_add_tpo_mod_func_name("libcon", "file_size", file_size, 0);
	sys_add_tpo_mod_func_name("libcon", "get_hash_idx", get_hash_idx, 0);
	sys_add_tpo_mod_func_name("libcon", "get_sub_dirs", get_sub_dirs, 0);
	sys_add_tpo_mod_func_name("libcon", "get_sub_files", get_sub_files, 0);

	sys_add_tpo_mod_func_name("libcon", "inflate", inflate, 0);
	sys_add_tpo_mod_func_name("libcon", "inflateEnd", inflateEnd, 0);
	sys_add_tpo_mod_func_name("libcon", "inflateInit2_", inflateInit2_, 0);
	sys_add_tpo_mod_func_name("libcon", "daemonize", daemonize, 0);
	sys_add_tpo_mod_func_name("libcon", "get_time_c", get_time_c, 0);
	sys_add_tpo_mod_func_name("libcon", "append_file", append_file, 0);
	sys_add_tpo_mod_func_name("libcon", "XML_ParserCreate", XML_ParserCreate, 0);
	sys_add_tpo_mod_func_name("libcon", "XML_SetElementHandler", XML_SetElementHandler, 0);
	sys_add_tpo_mod_func_name("libcon", "XML_SetCharacterDataHandler", XML_SetCharacterDataHandler, 0);
	sys_add_tpo_mod_func_name("libcon", "XML_SetUserData", XML_SetUserData, 0);
	sys_add_tpo_mod_func_name("libcon", "XML_Parse", XML_Parse, 0);
	sys_add_tpo_mod_func_name("libcon", "XML_ParserFree", XML_ParserFree, 0);
	sys_add_tpo_mod_func_name("libcon", "log_file_name", &log_file_name, 0);
}