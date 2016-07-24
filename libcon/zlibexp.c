#define LIBC_API C_EXPORT
#include "../../base/std_base.h"
#include "zlib.h"



C_EXPORT unsigned int KERN_API_FUNC	sys_add_tpo_mod_func_name(const char *name, const char *fn_name, void *addr, unsigned int deco);

int init_zfuncs()
{
	sys_add_tpo_mod_func_name("libcon", "inflate", inflate, 0);
	sys_add_tpo_mod_func_name("libcon", "inflateEnd", inflateEnd, 0);
	sys_add_tpo_mod_func_name("libcon", "inflateInit2_", inflateInit2_, 0);
	return 1;
}