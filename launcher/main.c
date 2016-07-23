#include <stdio.h>

#include <base/std_def.h>
#include <base/std_mem.h>
#include <base/mem_base.h>
#include <base/std_str.h>

#include <strs.h>
#include <connect.h>
#include <mem_stream.h>
#include <tpo_mod.h>
#include <fsio.h>

#if 1
C_IMPORT int C_API_FUNC app_init(mem_zone_ref_ptr params);
C_IMPORT int C_API_FUNC app_start(mem_zone_ref_ptr params);
C_IMPORT int C_API_FUNC app_loop(mem_zone_ref_ptr params);
C_IMPORT int C_API_FUNC app_stop(mem_zone_ref_ptr params);
#else
typedef int C_API_FUNC app_func(mem_zone_ref_ptr params);
typedef app_func *app_func_ptr;
app_func_ptr app_init, app_start, app_loop, app_stop;
#endif
tpo_mod_file protocol_mod = { 0 }, block_mod = { 0 }, libbase_mod = { 0 }, iadix_mod = { 0 };


int load_module(const char *file, const char *mod_name, tpo_mod_file *mod)
{
	mem_stream			mod_file;
	mem_zone_ref		tpo_file_data = { PTR_NULL };
	unsigned char		*data;
	size_t				data_len;

	if (get_file(file, &data, &data_len)<=0)return 0;
	
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



int main(int argc, char **argv)
{
	int done = 0;
	init_mem_system();
	init_default_mem_area(8 * 1024 * 1024);
	network_init();

	load_module("modz/libbase.tpo", "libbase", &libbase_mod);
	load_module("modz/protocol_adx.tpo", "protocol_adx", &protocol_mod);
	load_module("modz/block_adx.tpo", "block_adx", &block_mod);
	load_module("modz/iadixcoin.tpo", "iadixcoin", &iadix_mod);

#if 0
	app_init = get_tpo_mod_exp_addr_name(&iadix_mod, "app_init", iadix_mod.deco_type);
	app_start = get_tpo_mod_exp_addr_name(&iadix_mod, "app_start", iadix_mod.deco_type);
	app_loop = get_tpo_mod_exp_addr_name(&iadix_mod, "app_loop", iadix_mod.deco_type);
	app_stop = get_tpo_mod_exp_addr_name(&iadix_mod, "app_stop", iadix_mod.deco_type);
#endif
	app_init	(PTR_NULL);
	daemonize	("iadixcoin");
	app_start	(PTR_NULL);

	while (!done)
	{
		app_loop(PTR_NULL);
	}

	app_stop(PTR_NULL);
}


void mainCRTStartup(void)
{
	main(0, PTR_NULL);
}