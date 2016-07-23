#ifndef __STD_DEF__

#define __STD_DEF__

#ifdef __GNUC__
	#define C_EXPORT __attribute__ ((visibility ("default")))
	#define C_IMPORT __attribute__ ((visibility ("default"))) 

	#if defined(_M_X64) || defined(__amd64__)
		
		#define KERN_API_FUNC		__attribute__((__stdcall))

		#define C_API_FUNC			
		#define ASM_API_FUNC		
		#define C_INT_FUNC			

		#define	MOD_NAME_DECO		GCC_STDCALL_64

		typedef long int				int64_t;
		typedef unsigned long int		uint64_t;


	#else
		#define KERN_API_FUNC		__attribute__((__stdcall))

		#define C_API_FUNC			
		#define ASM_API_FUNC		
		#define C_INT_FUNC			

		#define	MOD_NAME_DECO		GCC_STDCALL_32
		typedef long long				int64_t;
		typedef	unsigned long long		uint64_t;

#endif

	#define struct_packed			__attribute__((packed))
#endif

#ifdef _MSC_VER
	#define C_EXPORT		__declspec(dllexport)
	#define C_IMPORT		__declspec(dllimport)

	#if defined(_M_X64) || defined(__amd64__)
		
	#else
		#define C_API_FUNC			__stdcall
		#define ASM_API_FUNC		__cdecl
		#define C_INT_FUNC			__cdecl

		#define	MOD_NAME_DECO		MSVC_STDCALL_32
	#endif	

	#define struct_packed 
	typedef __int64					int64_t;
	typedef unsigned __int64		uint64_t;
#endif


#ifndef MOD_NAME_DECO
	#error compiler not supported !
#endif
	
#if defined(_M_X64) || defined(__amd64__)
	typedef int64_t			ptrdiff_t;
	typedef __SIZE_TYPE__	size_t;

	#define INVALID_SIZE	0xffffffffUL

	#define LONG_MAX		0x7FFFFFFFL
	#define LONG_MIN		((long) 0x80000000L)
	
	#define UINT_MAX	    0xffffffffUL
	#define ULONG_MAX	    0xffffffffUL
	#define CHAR_BIT	 8						/* number of bits in a char */
	#define USHRT_MAX    0xffff					/* maximum unsigned short value */
	#define SHRT_MIN    (-32768)				/* minimum (signed) short value */
	#define SHRT_MAX      32767					/* maximum (signed) short value */
	#define INT_MIN     (-2147483647 - 1)		/* minimum (signed) int value */
	#define INT_MAX       2147483647			/* maximum (signed) int value */
	#define offsetof(s,m)   (size_t)( (ptrdiff_t)&(((s *)0)->m) )

#else
	
	typedef unsigned int	size_t;
	typedef int64_t			time_t;

	typedef int				ptrdiff_t;
	#define offsetof(s,m)   (size_t)&(((s *)0)->m)


	#define INVALID_SIZE	0xffffffffUL
	#ifndef LONG_MAX		
		#define LONG_MAX		0x7FFFFFFFL
		#define LONG_MIN		((long) 0x80000000L)

		#define UINT_MAX		0xffffffffUL
		#define ULONG_MAX		0xffffffffUL
		#define ULONG_MIN		0x00000000L
		#define CHAR_BIT		8						/* number of bits in a char */
		#define USHRT_MAX		0xffff					/* maximum unsigned short value */
		#define SHRT_MIN		(-32768)				/* minimum (signed) short value */
		#define SHRT_MAX		32767					/* maximum (signed) short value */
		#define INT_MIN			(-2147483647 - 1)		/* minimum (signed) int value */
		#define INT_MAX			2147483647			/* maximum (signed) int value */
	#endif
#endif

#define OS_API_C_FUNC(return_type) C_EXPORT return_type C_API_FUNC 
#define OS_INT_C_FUNC(return_type) return_type C_INT_FUNC 
#define OS_API_XTRN_ASM_FUNC(return_type) extern return_type ASM_API_FUNC 


typedef		unsigned int		C_INT_FUNC interupt_func(void *data);
typedef		interupt_func		*interupt_func_ptr	;


typedef enum
{
	NO_DECORATION	=	0,
	MSVC_STDCALL_32	=	1,
	MSVC_CDECL_32	=	2,
	GCC_STDCALL_32	=	3,
	GCC_CDECL_32	=	4
}mod_name_decoration_t;

typedef union
{
	struct {
		uint64_t	val;
	}uint64;
	struct {
		unsigned int ints[2];
	}uint32;
}large_uint_t;

#endif

OS_API_XTRN_ASM_FUNC(unsigned int)		compare_z_exchange_c			(unsigned int *data,unsigned int new_value);
OS_API_XTRN_ASM_FUNC(unsigned int)		fetch_add_c						(unsigned int *data,int new_value);
OS_API_XTRN_ASM_FUNC(unsigned int)		calc_crc32_c					(const char *,size_t );
