#ifndef LIBC_API	
#define LIBC_API	C_IMPORT
#endif
/*
typedef unsigned char *va_list;
#define va_start(list,args) list=(va_list)&args
#define va_arg(list,type) *((type *)(list+=sizeof(type))) 
#define va_end(list) list=PTR_NULL
*/

#ifndef _VA_LIST
#define _VA_LIST char*
#endif

//typedef _VA_LIST va_list;

/*
 * define a macro to compute the size of a type, variable or expression,
 * rounded up to the nearest multiple of sizeof(int). This number is its
 * size as function argument (Intel architecture). Note that the macro
 * depends on sizeof(int) being a power of 2!
 */



LIBC_API char *			C_API_FUNC strncpy_c				(char *string,const char *src_string,size_t		 cnt);
LIBC_API char *			C_API_FUNC strncpy_cs				(char *string,size_t str_len,const char *src_string,size_t cnt);

LIBC_API int			C_API_FUNC strcpy_cs				(char *string,size_t size,const char *src_string);
LIBC_API char *			C_API_FUNC strcpy_c					(char *string,const char *src_string);
LIBC_API int			C_API_FUNC strcat_cs				(char *string,size_t size,const char *src_string);
LIBC_API int			C_API_FUNC strcat_intval_s			(char *string,size_t size,const char *name,int val,int radix);
LIBC_API int			C_API_FUNC strcat_uintval_s			(char *string,size_t size,const char *name,unsigned int val,int radix);
LIBC_API int			C_API_FUNC strcat_escaped_s			(char *string,size_t size,const char *src_string);
LIBC_API int			C_API_FUNC strncat_c				(char *string,const char *src_string,size_t max);
LIBC_API int			C_API_FUNC strcat_c					(char *string,const char *src_string);
LIBC_API int			C_API_FUNC strcmp_c					(const char *string1,const char *string2);
LIBC_API int			C_API_FUNC strncmp_c				(const char *string1,const char *string2,size_t len);
LIBC_API int			C_API_FUNC strincmp_c				(const char *string1,const char *string2,size_t len);
LIBC_API int			C_API_FUNC stricmp_c				(const char *string1,const char *string2);

LIBC_API const char	*	C_API_FUNC strrchr_c				(const char *src,int car);
LIBC_API size_t 		C_API_FUNC strlen_c					(const char *string);
LIBC_API size_t			C_API_FUNC strlpos_c				(const char *string,size_t ofset,char c);
LIBC_API size_t			C_API_FUNC strrpos_c				(const char *string,char c);
LIBC_API char *			C_API_FUNC itoa_s					(int value, char *string,size_t len, int radix);
LIBC_API char *			C_API_FUNC uitoa_s					(size_t value, char *string,size_t len, int radix);
LIBC_API long			C_API_FUNC strtol_c					(const char *nptr, char **endptr,int base);
LIBC_API unsigned long	C_API_FUNC strtoul_c				(const char *nptr, char **endptr, int base);
LIBC_API short			C_API_FUNC strtos_c					(const char *nptr, char **endptr, int base);
LIBC_API long			C_API_FUNC atol_c					(const char *str ); 
LIBC_API const char *	C_API_FUNC strstr_c					(const char *buf, const char *sub);
LIBC_API int			C_API_FUNC writestr					(const char *string);
LIBC_API int			C_API_FUNC writenstr				(const char *text,size_t n);
/*LIBC_API int			C_API_FUNC writenstr				(const char *text,size_t n);*/
LIBC_API void			C_API_FUNC writestr_fmt				(const char *fmt,...);
/*LIBC_API void			C_API_FUNC writestr_vfmt			(const char *fmt	,va_list Args);*/
LIBC_API void			C_API_FUNC writeint					(int val,unsigned int radix);
LIBC_API void		    C_API_FUNC writesz					(size_t val,unsigned int radix);
LIBC_API void			C_API_FUNC writeptr					(const_mem_ptr val);
LIBC_API unsigned int	C_API_FUNC get_new_kern_log_id		(const char *pref,unsigned char color);
LIBC_API void			C_API_FUNC kernel_log				(unsigned int kern_log_id,const char *str);
LIBC_API int			C_API_FUNC tolower_c				(int _c);
LIBC_API int			C_API_FUNC toupper_c				(int _c);
LIBC_API int			C_API_FUNC isprint_c				(int _c);
LIBC_API int			C_API_FUNC isalpha_c				(int _c);
LIBC_API int			C_API_FUNC isdigit_c				(int _c);
LIBC_API int			C_API_FUNC isdigit_c				(int _c);
LIBC_API int			C_API_FUNC isxdigit_c				(int _c);
LIBC_API int			C_API_FUNC isspace_c				(int _c);
LIBC_API void			C_API_FUNC snooze					(unsigned int micro_sec);
LIBC_API void			C_API_FUNC dtoa_c					(char *buff, char conv, int bsize, int dplace, double value);

static const char		hex_chars[]		=	{'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};

typedef unsigned char	ipv4_t[4];
typedef	char			bitcore_cmd_t[12];
typedef	unsigned char	hash_t[32];
typedef	char			btc_addr_t[34];
/*
LIBC_API char *			C_API_FUNC strcpy				(char *string,const char *src_string);
*/
