/* copyright iadix 2016 */
#define LIBC_API C_EXPORT
#include "../../base/std_base.h"
#include "../../base/std_def.h"
#include "../../base/std_str.h"

#include "include/strs.h"
#include "zlib.h"


C_EXPORT unsigned int KERN_API_FUNC	sys_add_tpo_mod_func_name(const char *name, const char *fn_name, void_func_ptr addr, unsigned int deco);

int init_zfuncs()
{
	sys_add_tpo_mod_func_name("libcon", "crc32", (void_func_ptr)crc32, 0);

	sys_add_tpo_mod_func_name("libcon", "deflateInit_", (void_func_ptr)deflateInit_, 0);
	sys_add_tpo_mod_func_name("libcon", "deflate", (void_func_ptr)deflate, 0);
	sys_add_tpo_mod_func_name("libcon", "deflateEnd", (void_func_ptr)deflateEnd, 0);


	sys_add_tpo_mod_func_name("libcon", "inflate", (void_func_ptr)inflate, 0);
	sys_add_tpo_mod_func_name("libcon", "inflateReset", (void_func_ptr)inflateReset, 0);
	sys_add_tpo_mod_func_name("libcon", "inflateEnd", (void_func_ptr)inflateEnd, 0);
	sys_add_tpo_mod_func_name("libcon", "inflateInit2_", (void_func_ptr)inflateInit2_, 0);
	sys_add_tpo_mod_func_name("libcon", "inflateInit_", (void_func_ptr)inflateInit_, 0);


	sys_add_tpo_mod_func_name("libcon", "do_zip", (void_func_ptr)do_zip, 0);
	return 1;
}