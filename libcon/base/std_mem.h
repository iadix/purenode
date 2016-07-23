#ifndef LIBC_API	
#define LIBC_API	C_IMPORT
#endif

typedef	void				   void_func();
typedef	void_func			  *void_func_ptr;

typedef void				*mem_ptr;
typedef const void			*const_mem_ptr;

typedef size_t				mem_size;


#ifdef __cplusplus
	extern "C" {
#endif

		
LIBC_API mem_ptr		C_API_FUNC memcpy_c				(mem_ptr dst_ptr,const_mem_ptr src_ptr,mem_size size);
/*LIBC_API mem_ptr		C_API_FUNC _intel_fast_memcpy	(mem_ptr dst_ptr,const_mem_ptr src_ptr,mem_size size);*/
/*LIBC_API mem_ptr		C_API_FUNC memcpy				(mem_ptr dst_ptr,const_mem_ptr src_ptr,mem_size size);*/

LIBC_API mem_ptr		C_API_FUNC memmove_c			(mem_ptr dst_ptr,const_mem_ptr src_ptr,mem_size size);
LIBC_API mem_ptr		C_API_FUNC memset_c				(mem_ptr ptr,unsigned char v,mem_size size);
LIBC_API mem_ptr		C_API_FUNC memset_32_c			(mem_ptr ptr,unsigned int v,mem_size size);
/*LIBC_API mem_ptr		C_API_FUNC memset				(mem_ptr ptr,unsigned char v,mem_size size);*/
LIBC_API int			C_API_FUNC memcmp_c				(const_mem_ptr ptr1,const_mem_ptr ptr2,size_t size);
LIBC_API const_mem_ptr	C_API_FUNC memchr_c				(const_mem_ptr ptr,int value,mem_size size);
LIBC_API size_t			C_API_FUNC memchr_32_c			(const_mem_ptr ptr,unsigned int value,mem_size size);
LIBC_API void			C_API_FUNC qsort_c				(mem_ptr base, mem_size num, mem_size width,  int ( *comp)(const_mem_ptr,const_mem_ptr));

LIBC_API mem_ptr		C_API_FUNC realloc_c			(mem_ptr ptr,mem_size sz);
LIBC_API void			C_API_FUNC free_c				(mem_ptr ptr);
LIBC_API mem_ptr		C_API_FUNC malloc_c				(mem_size sz);
LIBC_API mem_ptr		C_API_FUNC calloc_c				(mem_size sz,mem_size blk);
LIBC_API mem_ptr		C_API_FUNC get_next_aligned_ptr (mem_ptr ptr);

#ifdef __cplusplus
	}
#endif

#ifndef NULL 
#define NULL (void *)0x00000000
#endif



