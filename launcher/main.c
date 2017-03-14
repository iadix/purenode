/* copyright iadix 2016 */
#include <base/std_def.h>
#include <base/std_mem.h>
#include <base/mem_base.h>
#include <base/std_str.h>

#include <strs.h>
#include <connect.h>
#include <mem_stream.h>
#include <tpo_mod.h>
#include <fsio.h>

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
	mem_zone_ref			 params = { PTR_NULL };
	mem_ptr					*params_ptr;
	int done = 0,n;
	init_mem_system			();
	init_default_mem_area	(8 * 1024 * 1024);
	set_exe_path			();
	if (!set_home_path("purenode"))
	{
		console_print("could not set home dir 'purenode' \n");
		return 0;
	}

	network_init();
	load_module("modz/libbase.tpo", "libbase", &libbase_mod);
	load_module("modz/protocol_adx.tpo", "protocol_adx", &protocol_mod);
	load_module("modz/block_adx.tpo", "block_adx", &block_mod);
	load_module("modz/iadixcoin.tpo", "iadixcoin", &iadix_mod);

#ifndef _DEBUG
	app_init	= (app_func_ptr)get_tpo_mod_exp_addr_name(&iadix_mod, "app_init", 0);
	app_start	= (app_func_ptr)get_tpo_mod_exp_addr_name(&iadix_mod, "app_start", 0);
	app_loop	= (app_func_ptr)get_tpo_mod_exp_addr_name(&iadix_mod, "app_loop", 0);
	app_stop	= (app_func_ptr)get_tpo_mod_exp_addr_name(&iadix_mod, "app_stop", 0);
#endif
	if (!app_init((mem_zone_ref_ptr)PTR_NULL))
	{
		console_print("could not initialize app ");
		console_print(iadix_mod.name);
		console_print("\n");
		return 0;
	}
	if (daemonize("purenode") <= 0)
	{
		console_print("daemonize failed \n");
		return 0;
	}
	
	if (argc > 1)
	{
		allocate_new_zone(0, argc*sizeof(mem_ptr), &params);
		for (n = 0; n < (argc-1); n++)
		{
			params_ptr		= get_zone_ptr(&params, n*sizeof(mem_ptr));
			(*params_ptr)	= argv[n+1];
		}
		params_ptr		= get_zone_ptr(&params, n*sizeof(mem_ptr));
		(*params_ptr)	= PTR_NULL;
	}
	if (!app_start(&params))
	{
		console_print("could not start app ");
		console_print(iadix_mod.name);
		console_print("\n");
		return 0;
	}

	while (isRunning())
	{
		app_loop(PTR_NULL);
	}

	app_stop(PTR_NULL);
}

#ifdef _WIN32
#include <Windows.h>
void mainCRTStartup(void)
{
	char		*command;
	char		*argv[32];
	int			argc;
	size_t		cmd_len;

	argc	= 0;
	command	=	GetCommandLine();
	if (command != PTR_NULL)
	{
		cmd_len = strlen_c(command);
		if (cmd_len > 0)
		{
			const char *last_cmd = command;
			int			open_quote = 0;
			size_t		n;
			for (n = 0; n < cmd_len;n++)
			{
				if ((open_quote == 0) && (command[n] == '"'))
				{ 
					last_cmd = (command + n + 1); 
					open_quote = 1; 
					continue; 
				}
				
				if (((open_quote == 0)&&(command[n] == ' '))||
					((open_quote == 1)&&(command[n] == '"')))
				{
					if (command[n+1] != 0 )
					{
						argv[argc++]	= last_cmd;

						if (open_quote)
						{
							last_cmd = (command + n + 2);
							command[n] = 0;
							n++;
						}
						else
						{
							last_cmd = (command + n + 1);
							command[n] = 0;
						}
						
					}
					open_quote		= 0;
				}
			}
			argv[argc++] = last_cmd;
		}
	}
	else
	{
		argc	= 0;
		argv[0]	= PTR_NULL;
		argv[1] = PTR_NULL;
	}
	main(argc, argv);
}
#endif