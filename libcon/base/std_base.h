#ifdef __GNUC__
#define C_EXPORT __attribute__ ((visibility ("default")))
#define C_IMPORT __attribute__ ((visibility ("default"))) 
#define struct_packed			__attribute__((packed))

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
#define KERN_API_FUNC		
#define	MOD_NAME_DECO		GCC_STDCALL_32
typedef long long				int64_t;
typedef	unsigned long long		uint64_t;

#endif


#endif

#ifdef _MSC_VER
	#define C_EXPORT			__declspec(dllexport)
	#define C_IMPORT			__declspec(dllimport)
	typedef __int64				int64_t;
	typedef unsigned __int64	uint64_t;
	#define struct_packed 

	#if defined(_M_X64) || defined(__amd64__)

	#else
		#define C_API_FUNC			__stdcall
		#define ASM_API_FUNC		__cdecl
		#define C_INT_FUNC			__cdecl
		#define KERN_API_FUNC		ASM_API_FUNC
		#define	MOD_NAME_DECO		MSVC_STDCALL_32
	#endif	


#endif

#ifndef MOD_NAME_DECO
#error compiler not supported !
#endif

typedef enum
{
	NO_DECORATION = 0,
	MSVC_STDCALL_32 = 1,
	MSVC_CDECL_32 = 2,
	GCC_STDCALL_32 = 3,
	GCC_CDECL_32 = 4
}mod_name_decoration_t;

#define OS_API_C_FUNC(return_type) C_EXPORT return_type C_API_FUNC 
#define OS_INT_C_FUNC(return_type) return_type C_INT_FUNC 
#define OS_API_XTRN_ASM_FUNC(return_type) extern return_type ASM_API_FUNC

