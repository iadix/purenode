//copyright iadix 2016
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

//#define _DEBUG

#ifdef _DEBUG
C_IMPORT int C_API_FUNC app_init(mem_zone_ref_ptr params);
C_IMPORT int C_API_FUNC app_start(mem_zone_ref_ptr params);
C_IMPORT int C_API_FUNC app_loop(mem_zone_ref_ptr params);
C_IMPORT int C_API_FUNC app_stop(mem_zone_ref_ptr params);

typedef int C_API_FUNC init_func();
typedef init_func *init_func_ptr;


#else
typedef int C_API_FUNC app_func(mem_zone_ref_ptr params);
typedef app_func *app_func_ptr;
app_func_ptr app_init, app_start, app_loop, app_stop;
#endif
tpo_mod_file protocol_mod = { 0 }, block_mod = { 0 }, libbase_mod = { 0 }, iadix_mod = { 0 };

int main(int argc, char **argv)
{
	int done = 0;
	init_mem_system			();
	init_default_mem_area	(4 * 1024 * 1024);
	network_init			();
	
	set_exe_path			();
	set_home_path			("purenode");

	load_module("modz/libbase.tpo", "libbase", &libbase_mod);
	load_module("modz/protocol_adx.tpo", "protocol_adx", &protocol_mod);
	load_module("modz/block_adx.tpo", "block_adx", &block_mod);
	load_module("modz/iadixcoin.tpo", "iadixcoin", &iadix_mod);
	/*
#ifdef _DEBUG
	init_func_ptr init;
	init=get_tpo_mod_exp_addr_name(&libbase_mod, "tree_manager_init", 0);
	if(init)
		init();
#endif
	*/
#ifndef _DEBUG
	app_init = get_tpo_mod_exp_addr_name(&iadix_mod, "app_init", 0);
	app_start = get_tpo_mod_exp_addr_name(&iadix_mod, "app_start", 0);
	app_loop = get_tpo_mod_exp_addr_name(&iadix_mod, "app_loop", 0);
	app_stop = get_tpo_mod_exp_addr_name(&iadix_mod, "app_stop", 0);
#endif
	if (!app_init(PTR_NULL))
	{
		console_print("could not initialize app ");
		console_print(iadix_mod.name);
		console_print("\n");
		return 0;
	}
	daemonize	("purenode");
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