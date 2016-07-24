#ifndef __STD_DEF__

#define __STD_DEF__

#include "std_base.h"

	
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
	typedef int64_t			ctime_t;

	typedef int				ptrdiff_t;
	#define offsetof(s,m)   (size_t)&(((s *)0)->m)


	#define INVALID_SIZE	0xffffffffUL
	#ifndef UINT_MAX		
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



typedef		unsigned int		C_INT_FUNC interupt_func(void *data);
typedef		interupt_func		*interupt_func_ptr	;




typedef union
{
	struct {
		uint64_t	val;
	}uint64;
	struct {
		unsigned int ints[2];
	}uint32;
}large_uint_t;

OS_API_XTRN_ASM_FUNC(unsigned int)		compare_z_exchange_c(unsigned int *data, unsigned int new_value);
OS_API_XTRN_ASM_FUNC(unsigned int)		fetch_add_c(unsigned int *data, int new_value);
OS_API_XTRN_ASM_FUNC(unsigned int)		calc_crc32_c(const char *, size_t);

#endif

