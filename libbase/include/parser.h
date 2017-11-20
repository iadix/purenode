#ifndef LIBBASE_API
	#define LIBBASE_API C_IMPORT
#endif

LIBBASE_API int	C_API_FUNC load_script				(const char *file,const char *name, mem_zone_ref_ptr script_vars,unsigned int opts);
LIBBASE_API int	C_API_FUNC get_script_var_value_str (mem_zone_ref_ptr global_vars, const char *var_path, struct string *out, unsigned int radix);
LIBBASE_API int	C_API_FUNC get_script_var_value_i32 (mem_zone_ref_ptr global_vars, const char *var_path, unsigned int *out);
LIBBASE_API int	C_API_FUNC get_script_var_value_ptr	(mem_zone_ref_ptr global_vars, const char *var_path, mem_ptr *out);
LIBBASE_API int	C_API_FUNC resolve_script_var(mem_zone_ref_ptr global_vars, mem_zone_ref_ptr script_proc, const char *var_path, unsigned int var_type, mem_zone_ref_ptr out_var, mem_zone_ref_ptr pout_var);
LIBBASE_API int	C_API_FUNC execute_script_proc		(mem_zone_ref_ptr global_vars, mem_zone_ref_ptr script_proc);
LIBBASE_API int	C_API_FUNC load_mod_def				(mem_zone_ref_ptr mod_def);

