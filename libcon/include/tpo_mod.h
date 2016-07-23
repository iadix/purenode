#ifndef LIBC_API
#define LIBC_API C_IMPORT
#endif

#define MOD_HASH(name) calc_crc32_c(name,64)
#define FUNC_HASH(name) calc_crc32_c(name,256)

typedef struct
{
	unsigned int		crc_32;
	unsigned int		sym_addr;
	unsigned int		string_idx;
}tpo_export;

typedef struct
{
	size_t				reloc_addr;
	unsigned int		sym_addr;
}tpo_import;

typedef struct
{
	size_t				section_ptr;
	size_t				section_size;
	size_t				section_img_ofset;
	mem_zone_ref		exports_fnc;
	mem_zone_ref		imports_fnc;
}tpo_section;

typedef struct
{
	unsigned int			mod_idx;
	mod_name_decoration_t	deco_type;
	char					name[64];
	unsigned int			name_hash;
	mem_zone_ref			string_buffer_ref;
	unsigned int			string_buffer_len;
	mem_zone_ref			data_sections;
	tpo_section				sections[16];
}tpo_mod_file;
struct kern_mod_fn_t
{
	unsigned int	func_hash;
	unsigned int	func_addr;
	unsigned int	section_start_addr;
	unsigned int	string_idx;
};
typedef const tpo_mod_file *const_tpo_mod_file_ptr ;



LIBC_API void			C_API_FUNC tpo_mod_init(tpo_mod_file *driver);

LIBC_API int			C_API_FUNC tpo_mod_load_tpo(mem_stream *file_stream, tpo_mod_file *tpo_file, unsigned int imp_func_addr);

LIBC_API mem_ptr		C_API_FUNC tpo_mod_get_exp_addr(mem_stream *file_stream, const char *sym);
LIBC_API mem_ptr		C_API_FUNC get_tpo_mod_exp_addr(const tpo_mod_file *tpo_mod, unsigned int crc_32);
LIBC_API mem_ptr		C_API_FUNC get_tpo_mod_exp_addr_name(const tpo_mod_file *tpo_mod, const char *name, unsigned int deco_type);
LIBC_API int			C_API_FUNC set_tpo_mod_exp_value32(const tpo_mod_file *tpo_mod, unsigned int crc_32, unsigned int value);
LIBC_API int			C_API_FUNC set_tpo_mod_exp_value32_name(const tpo_mod_file *tpo_mod, const char *name, unsigned int value);
LIBC_API void			C_API_FUNC register_tpo_exports(tpo_mod_file *tpo_mod, const char *mod_name);
	
LIBC_API int			C_API_FUNC		run_tpo(const char *file_system, const char *file_name, tpo_mod_file *mod);
LIBC_API int			C_API_FUNC		load_tpo_dll(const char *file_system, const char *file_name, tpo_mod_file *mod);
LIBC_API int			C_API_FUNC		run_app(const char *file_system, const char *file_name, tpo_mod_file *mod, mem_zone_ref_ptr app_data);

#define KERN_API_FUNC			ASM_API_FUNC

#ifndef KERNEL_API
#define KERNEL_API	C_IMPORT
#endif

KERNEL_API unsigned int KERN_API_FUNC	sys_add_tpo_mod_func_name(const char *name, const char *fn_name, mem_ptr addr, unsigned int deco);

typedef unsigned int	C_API_FUNC defaut_import_func_ptr		(void *data);
typedef int			    C_API_FUNC run_func_fn					();
typedef int			    C_API_FUNC init_func_fn					(mem_zone_ref_ptr	init_data);

typedef run_func_fn *run_func_fn_ptr;
typedef init_func_fn *init_func_fn_ptr;