
struct string
{
	char	*str;
	size_t  len;
	size_t  size;
};
struct host_def
{
	struct string		host;
	struct string		port_str;
	unsigned short		port;
};


LIBC_API		void				C_API_FUNC init_string				(struct string *str);
LIBC_API		int					C_API_FUNC make_string(struct string *str, const char *toto);
LIBC_API		size_t				C_API_FUNC cat_string(struct string *str, const struct string *src);
LIBC_API		int 				C_API_FUNC prepare_new_data(struct string *str, size_t len);
LIBC_API		int					C_API_FUNC strcat_uint(struct string *str, size_t i);
LIBC_API		int					C_API_FUNC strcat_float(struct string *str, double f);
LIBC_API		int 				C_API_FUNC strcat_int(struct string *str, int i);
LIBC_API		int 				C_API_FUNC cat_cstring(struct string *str, const char *src);
LIBC_API		int 				C_API_FUNC cat_ncstring(struct string *str, const char *src, size_t src_len);
LIBC_API		int					C_API_FUNC cat_ncstring_p(struct string *str, const char *src, size_t src_len);
LIBC_API		int					C_API_FUNC cat_cstring_p(struct string *str, const char *src);

LIBC_API		int 				C_API_FUNC make_cstring(const struct string *str, char *toto, size_t len);
LIBC_API		int 				C_API_FUNC make_string_l(struct string *str, const char *toto, size_t len);
LIBC_API		int 				C_API_FUNC make_string_url(struct string *str, const char *toto, size_t len);
LIBC_API		int 				C_API_FUNC make_string_from_uint(struct string *str, size_t i);
LIBC_API		int 				C_API_FUNC make_string_from_url(struct string *str, const char *toto, size_t len);
LIBC_API		int					C_API_FUNC clone_string(struct string *str, const struct string *str1);
LIBC_API		void				C_API_FUNC free_string(struct string *str);
LIBC_API		struct host_def *	C_API_FUNC make_host_def(const char *host, unsigned short port);
LIBC_API		struct host_def	*	C_API_FUNC make_host_def_url(const struct string *url, struct string *path);
LIBC_API		void				C_API_FUNC copy_host_def(struct host_def *dhost, const struct host_def *host);
LIBC_API		void				C_API_FUNC cat_tag(struct string *str, const char *tag, const char *val);
LIBC_API		void				C_API_FUNC free_host_def(struct host_def *host);
LIBC_API		void				C_API_FUNC copy_host_def(struct host_def *dhost, const struct host_def *host);
LIBC_API		int					C_API_FUNC my_itoa_s(int num, unsigned char* str, int len, int base);

#ifndef _WIN32
#define strcpy_s(a,b,c) strcpy(a,c)
#define strcat_s(a,b,c) strcat(a,c)
#define _strnicmp(a,b,c)strncasecmp(a,b,c)
#define _stricmp(a,b) strcasecmp(a,b)
#endif