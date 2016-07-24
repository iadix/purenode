#ifndef LIBC_API
#define LIBC_API C_IMPORT
#endif

LIBC_API size_t			C_API_FUNC file_size(const char *path);
LIBC_API int			C_API_FUNC append_file(const char *path, void *data, size_t data_len);
LIBC_API int			C_API_FUNC stat_file(const char *path);
LIBC_API int			C_API_FUNC create_dir(const char *path);
LIBC_API int			C_API_FUNC put_file(const char *path, void *data, size_t data_len);
LIBC_API int			C_API_FUNC get_sub_dirs(const char *path, struct string *dir_list);
LIBC_API int			C_API_FUNC get_sub_files(const char *path, struct string *file_list);
LIBC_API int			C_API_FUNC get_file(const char *path, unsigned char **data, size_t *data_len);
LIBC_API int			C_API_FUNC get_hash_idx(const char *path, size_t idx, hash_t hash);
LIBC_API int			C_API_FUNC daemonize(const char *name);
LIBC_API ctime_t		C_API_FUNC get_time_c(void);
LIBC_API void			C_API_FUNC console_print(const char *msg);
LIBC_API int			C_API_FUNC log_output(const char *data);
