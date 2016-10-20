//copyright iadix 2016
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
#include "xmlparse.h"

extern int init_zfuncs();
extern struct string home_path;
extern struct string log_file_name;
extern struct string exe_path;
void init_funcs()
{

	sys_add_tpo_mod_func_name("libcon", "utf8_encode", utf8_encode, 0);
	sys_add_tpo_mod_func_name("libcon", "utf8_check_first", utf8_check_first, 0);
	sys_add_tpo_mod_func_name("libcon", "utf8_check_full", utf8_check_full, 0);

	sys_add_tpo_mod_func_name("libcon", "console_print", console_print, 0);
	sys_add_tpo_mod_func_name("libcon", "stat_file", stat_file, 0);
	sys_add_tpo_mod_func_name("libcon", "create_dir", create_dir, 0);
	sys_add_tpo_mod_func_name("libcon", "del_dir", del_dir, 0);
	sys_add_tpo_mod_func_name("libcon", "rm_dir", rm_dir, 0);
	sys_add_tpo_mod_func_name("libcon", "put_file", put_file, 0);
	sys_add_tpo_mod_func_name("libcon", "append_file", append_file, 0);
	sys_add_tpo_mod_func_name("libcon", "truncate_file", truncate_file, 0);
	sys_add_tpo_mod_func_name("libcon", "get_file", get_file, 0);
	sys_add_tpo_mod_func_name("libcon", "del_file", del_file, 0);
	sys_add_tpo_mod_func_name("libcon", "move_file", move_file, 0);
	sys_add_tpo_mod_func_name("libcon", "file_size", file_size, 0);
	sys_add_tpo_mod_func_name("libcon", "get_hash_idx", get_hash_idx, 0);
	sys_add_tpo_mod_func_name("libcon", "get_sub_dirs", get_sub_dirs, 0);
	sys_add_tpo_mod_func_name("libcon", "get_sub_files", get_sub_files, 0);
	sys_add_tpo_mod_func_name("libcon", "log_output", log_output, 0);
	sys_add_tpo_mod_func_name("libcon", "set_ftime", set_ftime, 0);
	sys_add_tpo_mod_func_name("libcon", "get_ftime", get_ftime, 0);
	sys_add_tpo_mod_func_name("libcon", "get_home_dir", get_home_dir, 0);
	sys_add_tpo_mod_func_name("libcon", "set_home_path", set_home_path, 0);
	sys_add_tpo_mod_func_name("libcon", "set_cwd", set_cwd, 0);
	sys_add_tpo_mod_func_name("libcon", "get_cwd", get_cwd, 0);
	
	sys_add_tpo_mod_func_name("libcon", "background_func", background_func, 0);

	sys_add_tpo_mod_func_name("libcon", "daemonize", daemonize, 0);
	sys_add_tpo_mod_func_name("libcon", "get_time_c", get_time_c, 0);
	sys_add_tpo_mod_func_name("libcon", "XML_ParserCreate", XML_ParserCreate, 0);
	sys_add_tpo_mod_func_name("libcon", "XML_SetElementHandler", XML_SetElementHandler, 0);
	sys_add_tpo_mod_func_name("libcon", "XML_SetCharacterDataHandler", XML_SetCharacterDataHandler, 0);
	sys_add_tpo_mod_func_name("libcon", "XML_SetUserData", XML_SetUserData, 0);
	sys_add_tpo_mod_func_name("libcon", "XML_Parse", XML_Parse, 0);
	sys_add_tpo_mod_func_name("libcon", "XML_ParserFree", XML_ParserFree, 0);


	init_string	(&exe_path);
	init_string(&home_path);
	init_string(&log_file_name);


	

	init_zfuncs();	
}
