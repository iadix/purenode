//copyright iadix 2016
#define LIBC_API C_EXPORT
#include "std_def.h"
#include "std_mem.h"
#include "mem_base.h"
#include "std_str.h"
#include "strs.h"

#define KERNEL_API C_EXPORT
#include "mem_stream.h"
#include "tpo_mod.h"
#include "fsio.h"

#include <math.h>
#include <stdlib.h>


 LIBC_API void	*	C_API_FUNC kernel_memory_map_c				(unsigned int size);
 LIBC_API void		C_API_FUNC kernel_memory_free_c				(mem_ptr ptr);
  extern void init_exit();
			
typedef struct
{
	mem_ptr			ptr;
	mem_size		size;
}mem_zone_desc;

typedef struct
{
	mem_zone_desc		mem;
	unsigned int		area_id;
	unsigned int		n_refs;
	unsigned int		time;
	zone_free_func_ptr  free_func;
}mem_zone;

typedef			mem_zone			*mem_zone_ptr;
typedef const	mem_zone_desc		*mem_zone_desc_ptr;
int			   out_debug			=	0xFFFFFFFF;

typedef struct
{
	unsigned int			area_id;
	mem_area_type_t			type;
	mem_ptr					lock_sema;
	mem_ptr					area_start;
	mem_ptr					area_end;
	mem_zone_desc			zones_free[MAX_MEM_ZONES];
	mem_zone_ptr			zones_buffer;
	

}mem_area;

mem_area	*__global_mem_areas		=	PTR_INVALID;
mem_zone	*__global_mem_zones		=	PTR_INVALID;


mem_zone		mapped_zones[32]	=	{PTR_INVALID};
unsigned int	n_mapped_zones		=	0xCDCDCDCD;
unsigned int	area_lock			=	0xCDCDCDCD;

int C_API_FUNC tree_manager_free_node		(mem_zone_ref_ptr p_node_ref);
int C_API_FUNC tree_manager_free_node_array	(mem_zone_ref_ptr childs_ref_ptr);

/*
C_EXPORT mem_ptr __cdecl memset(mem_ptr ptr,unsigned char v,mem_size size)
{
	unsigned char *cptr=ptr;
	while(size--){cptr[size]=v;  }
	return ptr;

}

C_EXPORT mem_ptr __cdecl memcpy(mem_ptr dst_ptr,const_mem_ptr src_ptr,mem_size size)
{
	const unsigned char *sptr	=src_ptr;
	unsigned char *dptr			=dst_ptr;
	unsigned int	n			=0;;

	while(n<size){dptr[n]=sptr[n];n++;}

	return dst_ptr;
	
}
*/
OS_API_C_FUNC(mem_ptr) memset_c(mem_ptr ptr,unsigned char v,mem_size size)
{
	unsigned char *cptr=ptr;
	while(size--){cptr[size]=v;  }
	return ptr;

}
OS_API_C_FUNC(mem_ptr) memset_32_c(mem_ptr ptr,unsigned int v,mem_size size)
{
	unsigned int *cptr=ptr;

	size>>=2;

	while(size--){cptr[size]=v;  }
	return ptr;

}

OS_API_C_FUNC(size_t) memchr_32_c(const_mem_ptr ptr,unsigned int value,mem_size size)
{
	const unsigned int *uint;
	const unsigned int *last_uint;

	if ((size & (~0x03))<4)return INVALID_SIZE;

	uint		=ptr;
	last_uint	=mem_add(ptr,(size & (~0x03))-4);
	
	while(uint<last_uint){ if((*uint)==value)return mem_sub(ptr,uint); uint++;}

	return INVALID_SIZE;

}

OS_API_C_FUNC(const_mem_ptr) memchr_c(const_mem_ptr ptr,int value,mem_size size)
{
	unsigned int n;
	const unsigned char *uchar;

	uchar	=ptr;
	n		=0;
	while(n<size){ if(uchar[n]==value)return &uchar[n]; n++;}

	return PTR_NULL;

}

OS_API_C_FUNC(int) memcmp_c(const_mem_ptr ptr_1,const_mem_ptr ptr_2,size_t size)
{
	unsigned int n;
	const unsigned char *ptr1,*ptr2;
	n=0;
	ptr1=ptr_1;
	ptr2=ptr_2;

	while(n<size){ if(ptr1[n]>ptr2[n])return 1; if(ptr1[n]<ptr2[n])return -1; n++;}
	return 0;

}
/*
typedef	int word;		// "word" used for optimal copy speed 
#define	wsize	sizeof(word)
#define	wmask	(wsize - 1)

OS_API_C_FUNC(mem_ptr)	memmove_c(mem_ptr dst_ptr,const_mem_ptr src_ptr,mem_size length)
{
	//register char *dst = dst_ptr;
	//register const char *src = src_ptr;
	//register size_t t;
	char *dst = dst_ptr;
	const char *src = src_ptr;
	mem_size t;

	if (length == 0 || dst == src)		// nothing to do 
	    goto done;

	
	 // Macros: loop-t-times; and loop-t-times, t>0
	
#define	TLOOP(s) if (t) TLOOP1(s)
#define	TLOOP1(s) do { s; } while (--t)

	if (mem_to_uint(dst) < mem_to_uint(src)) {
	
		 // Copy forward.
		t = mem_to_uint(src);	// only need low bits 
		if ((t | mem_to_uint(dst)) & wmask) {
			
			 // Try to align operands.  This cannot be done
			 // unless the low bits match.
			if ((t ^ mem_to_uint(dst)) & wmask || length < wsize)
			    t = length;
			else
			    t = wsize - (t & wmask);
			length -= t;
			TLOOP1(*dst++ = *src++);
		}
		
		 // Copy whole words, then mop up any trailing bytes.
		t = length / wsize;
		TLOOP(*(word *)dst = *(word *)src; src += wsize; dst += wsize);
		t = length & wmask;
		TLOOP(*dst++ = *src++);
	} else {
		 // Copy backwards.  Otherwise essentially the same.
		 // Alignment works as before, except that it takes
		 // (t&wmask) bytes to align, not wsize-(t&wmask).
		 
		src += length;
		dst += length;
		t = mem_to_uint(src);
		if ((t | mem_to_uint(dst)) & wmask) {
			if ((t ^  mem_to_uint(dst)) & wmask || length <= wsize)
			    t = length;
			else
			    t &= wmask;
			length -= t;
			TLOOP1(*--dst = *--src);
		}
		t = length / wsize;
		TLOOP(src -= wsize; dst -= wsize; *(word *)dst = *(word *)src);
		t = length & wmask;
		TLOOP(*--dst = *--src);
	}
    done:
	
	return dst_ptr;
}
*/
/*
mem_ptr _intel_fast_memcpy(mem_ptr dst_ptr,const_mem_ptr src_ptr,mem_size size)
{
	return memcpy_c(dst_ptr,src_ptr,size);
}
*/

OS_API_C_FUNC(unsigned int ) rand_c()
{
	return rand();

}

OS_API_C_FUNC(mem_ptr) memmove_c(mem_ptr dst_ptr, const_mem_ptr src_ptr, mem_size size)
{
	const unsigned char *sptr = src_ptr;
	unsigned char *dptr = dst_ptr;

	if (mem_to_uint(dptr) < mem_to_uint(sptr))
		memcpy_c(dst_ptr, src_ptr, size);
	else
	{
		unsigned int	n = size;;
		while (n--){ dptr[n] = sptr[n]; }
	}

	return dst_ptr;

}


OS_API_C_FUNC(mem_ptr) memcpy_c(mem_ptr dst_ptr,const_mem_ptr src_ptr,mem_size size)
{
	const unsigned char *sptr	=src_ptr;
	unsigned char *dptr			=dst_ptr;
	unsigned int	n			=0;;

	while(n<size){dptr[n]=sptr[n];n++;}

	return dst_ptr;
	
}

OS_API_C_FUNC(mem_area *) get_area(unsigned int area_id)
{
	int n;
	n=0;
	if(__global_mem_areas==PTR_NULL)return PTR_NULL;
	if(__global_mem_zones==PTR_NULL)return PTR_NULL;

	if(area_id==0)
	{
		unsigned int m_area_id;
		m_area_id = get_mem_area_id();
		n=0;
		while(n<MAX_MEM_AREAS)
		{
			if (__global_mem_areas[n].area_id == m_area_id)
				return &__global_mem_areas[n];
			n++;
		}
		return PTR_NULL;
	}


	while(n<MAX_MEM_AREAS)
	{
		if(__global_mem_areas[n].area_id==area_id)
			return &__global_mem_areas[n];
		n++;
	}
	return PTR_NULL;
}


mem_area	*get_area_by_zone_ptr	(const mem_zone *zone)
{
	int n;
	if(__global_mem_areas==PTR_NULL)return PTR_NULL;
	if(__global_mem_zones==PTR_NULL)return PTR_NULL;


	n=0;
	while(n<MAX_MEM_AREAS)
	{
		if(__global_mem_areas[n].area_start == 0x00000000)return PTR_NULL;
		if((zone>=__global_mem_areas[n].zones_buffer)&&(zone<&__global_mem_areas[n].zones_buffer[MAX_MEM_AREAS]))
			return &__global_mem_areas[n];
		n++;
	}


	return PTR_NULL;

}

//int check_zone			(const mem_zone_ref *ref)
int check_zone	(const mem_zone *zone)
{
	mem_area				*area_ptr;
	if(zone->area_id==0xFFFF)return 1;
	

	area_ptr			=	get_area(zone->area_id);
	if(area_ptr==PTR_NULL)
	{
		return 0;
	}
	if((zone<area_ptr->zones_buffer)||(zone>=&area_ptr->zones_buffer[MAX_MEM_ZONES]))
	{

	}

	if((zone->mem.ptr==uint_to_mem(0xFFFFFFFF))&&(zone->mem.size==0))return 1;


	if((zone->mem.ptr==PTR_NULL)&&(zone->mem.size==0))
	{
		return 0;
	}

	if((zone->mem.ptr<area_ptr->area_start)||(zone->mem.ptr>area_ptr->area_end))
	{
		return 0;
	}

	return 1;

}



OS_API_C_FUNC(mem_ptr)	get_zone_ptr(mem_zone_ref_const_ptr ref, mem_size ofset)
{
	if(ref==PTR_NULL) return PTR_INVALID;
	if(ref->zone==PTR_NULL)return PTR_INVALID;
	if((((mem_zone *)(ref->zone))->mem.size)==0)
	{
		return PTR_INVALID;
	}

	if(ofset==0xFFFFFFFF)return mem_add( ((mem_zone *)(ref->zone))->mem.ptr,((mem_zone *)(ref->zone))->mem.size);
	if (ofset >= ((mem_zone *)(ref->zone))->mem.size)
	{
		return PTR_INVALID;
	}

	/*
	if(!check_zone(ref->zone))
	{
		return PTR_INVALID;
	}
	*/

	return mem_add( ((mem_zone *)(ref->zone))->mem.ptr,ofset);
}

/*
OS_API_C_FUNC(mem_ptr)	get_zone_const_ptr	(mem_zone_const_ref_ptr ref,mem_size ofset)
{
	mem_ptr ret;

	if(ref==PTR_NULL) return PTR_INVALID;
	if(ref->zone==PTR_NULL)
	{
		writestr("const zone null \n");
		dump_task_infos_c();
		snooze(1000000);

		return PTR_INVALID;
	}

	if(!check_zone(ref->zone))
	{
		writestr("const check zone failed \n");
		dump_task_infos_c();
		snooze(1000000);

		return PTR_INVALID;
	}

	if((ofset!=0xFFFFFFFF)&&(ofset>((mem_zone *)(ref->zone))->mem.size))
	{
		writestr("const get_zone_ptr ofset out of boundary \n");
		dump_task_infos_c();
		snooze(1000000);
		return PTR_INVALID;
	}
	
	if(ofset==0xFFFFFFFF)
		ret=mem_add(((mem_zone *)(ref->zone))->mem.ptr,((mem_zone *)(ref->zone))->mem.size);
	else
		ret=mem_add(((mem_zone *)(ref->zone))->mem.ptr,ofset);

	return ret;
}

OS_API_C_FUNC(mem_size) get_zone_const_size(mem_zone_const_ref_ptr ref)
{
	if(ref==PTR_NULL) return 0;
	if(ref->zone==PTR_NULL) return 0;

	return ((mem_zone *)(ref->zone))->mem.size;
}
*/
OS_API_C_FUNC(mem_size) get_zone_size(mem_zone_ref_const_ptr ref)
{
	if(ref==PTR_NULL) return 0;
	if(ref->zone==PTR_NULL) return 0;

	return ((mem_zone *)(ref->zone))->mem.size;
}


OS_API_C_FUNC(mem_size) set_zone_free(mem_zone_ref_ptr ref,zone_free_func_ptr	free_func)
{
	if(ref==PTR_NULL) return 0;
	if(ref->zone==PTR_NULL) return 0;

	((mem_zone *)(ref->zone))->free_func=free_func;

	return 1;
}




OS_API_C_FUNC(void) init_default_mem_area(unsigned int size)
{
	mem_ptr				start,end;
	unsigned int		default_mem_area_id;
	
	start					=	kernel_memory_map_c(size+8);
	end						=	mem_add(start,size);
	memset_c(start, 0, mem_sub(start, end));

	default_mem_area_id		=	init_new_mem_area	(start,end,MEM_TYPE_DATA);
	set_mem_area_id				(default_mem_area_id);
	


	return;
}

OS_API_C_FUNC(unsigned int) inc_zone_ref(mem_zone_ref_ptr zone_ref)
{
	if (zone_ref->zone == PTR_NULL)return 0;
	if (zone_ref->zone == uint_to_mem(0xDEF0DEF0))return 0;
	if (fetch_add_c(&((mem_zone *)(zone_ref->zone))->n_refs, 1) == 0)return 0;
	return 1;

}
OS_API_C_FUNC(void) swap_zone_ref(mem_zone_ref_ptr dest_zone_ref, mem_zone_ref_ptr src_zone_ref)
{
	mem_zone *dst_zone = dest_zone_ref->zone;

	dest_zone_ref->zone = src_zone_ref->zone;
	src_zone_ref->zone = dst_zone;
}

extern void init_funcs(void);

#ifdef _MSC_VER
extern mem_ptr			ASM_API_FUNC memset(mem_ptr ptr, int value, unsigned int size);
extern mem_ptr			ASM_API_FUNC memcpy(mem_ptr ptr, int value, unsigned int size);
#endif
OS_API_C_FUNC(void) init_mem_system()
{
	if(__global_mem_areas	!= PTR_INVALID)return;
	if(__global_mem_zones	!= PTR_INVALID)return;

	__global_mem_areas	=get_next_aligned_ptr(kernel_memory_map_c(MAX_MEM_AREAS*sizeof(mem_area)+8));
	__global_mem_zones	=get_next_aligned_ptr(kernel_memory_map_c(MAX_MEM_AREAS*MAX_MEM_ZONES*sizeof(mem_zone)+8));

	memset_c(__global_mem_areas,0,MAX_MEM_AREAS*sizeof(mem_area)	);
	memset_c(__global_mem_zones,0,MAX_MEM_AREAS*MAX_MEM_ZONES*sizeof(mem_zone) );

	n_mapped_zones			=	0;
	out_debug				=	0;
	
	area_lock				=	0;

	

	sys_add_tpo_mod_func_name("libcon", "init_new_mem_area", init_new_mem_area, 0);
	sys_add_tpo_mod_func_name("libcon", "get_tree_mem_area_id", get_tree_mem_area_id, 0);
	sys_add_tpo_mod_func_name("libcon", "set_tree_mem_area_id", set_tree_mem_area_id, 0);
	sys_add_tpo_mod_func_name("libcon", "get_mem_area_id", get_mem_area_id, 0);
	sys_add_tpo_mod_func_name("libcon", "free_mem_area", free_mem_area, 0);

	sys_add_tpo_mod_func_name("libcon", "realloc_zone", realloc_zone, 0);
	sys_add_tpo_mod_func_name("libcon", "malloc_c", malloc_c, 0);
	sys_add_tpo_mod_func_name("libcon", "calloc_c", calloc_c, 0);
	sys_add_tpo_mod_func_name("libcon", "memset_c", memset_c, 0);
	sys_add_tpo_mod_func_name("libcon", "rand_c", rand_c, 0);
#ifdef _MSC_VER
	sys_add_tpo_mod_func_name("libcon", "memset", memset, 0);
	sys_add_tpo_mod_func_name("libcon", "memcpy", memcpy, 0);
#endif
	sys_add_tpo_mod_func_name("libcon", "memcpy_c", memcpy_c,0);
	sys_add_tpo_mod_func_name("libcon", "memcmp_c", memcmp_c, 0);
	sys_add_tpo_mod_func_name("libcon", "memmove_c", memmove_c, 0);
	sys_add_tpo_mod_func_name("libcon", "memchr_c", memchr_c, 0);
	sys_add_tpo_mod_func_name("libcon", "memchr_32_c", memchr_32_c, 0);
	sys_add_tpo_mod_func_name("libcon", "store_bigendian", store_bigendian, 0);
	sys_add_tpo_mod_func_name("libcon", "load_bigendian", load_bigendian, 0); 
	
	 


	sys_add_tpo_mod_func_name("libcon", "allocate_new_zone", allocate_new_zone, 0);
	sys_add_tpo_mod_func_name("libcon", "allocate_new_empty_zone", allocate_new_empty_zone, 0);
	sys_add_tpo_mod_func_name("libcon", "expand_zone", expand_zone, 0);
	sys_add_tpo_mod_func_name("libcon", "get_next_aligned_ptr", get_next_aligned_ptr, 0);
	sys_add_tpo_mod_func_name("libcon", "kernel_memory_map_c", kernel_memory_map_c, 0);
	sys_add_tpo_mod_func_name("libcon", "inc_zone_ref", inc_zone_ref, 0);
	sys_add_tpo_mod_func_name("libcon", "swap_zone_ref", swap_zone_ref, 0);
	sys_add_tpo_mod_func_name("libcon", "dump_mem_used_after", dump_mem_used_after, 0);
	sys_add_tpo_mod_func_name("libcon", "set_zone_free", set_zone_free, 0);
	sys_add_tpo_mod_func_name("libcon", "free_c", free_c, 0);
	sys_add_tpo_mod_func_name("libcon", "find_zones_used", find_zones_used, 0);

	sys_add_tpo_mod_func_name("libcon", "dec_zone_ref", dec_zone_ref, 0);
	sys_add_tpo_mod_func_name("libcon", "copy_zone_ref", copy_zone_ref, 0);
	sys_add_tpo_mod_func_name("libcon", "get_zone_ptr", get_zone_ptr, 0);
	sys_add_tpo_mod_func_name("libcon", "get_zone_size", get_zone_size, 0);
	sys_add_tpo_mod_func_name("libcon", "release_zone_ref", release_zone_ref, 0);
	sys_add_tpo_mod_func_name("libcon", "strcpy_c", strcpy_c, 0);
	sys_add_tpo_mod_func_name("libcon", "strcpy_cs", strcpy_cs, 0);
	sys_add_tpo_mod_func_name("libcon", "strncpy_c", strncpy_c, 0);
	sys_add_tpo_mod_func_name("libcon", "strncpy_cs", strncpy_cs, 0);
	sys_add_tpo_mod_func_name("libcon", "strcat_cs", strcat_cs, 0);
	sys_add_tpo_mod_func_name("libcon", "strncat_c", strncat_c, 0);
	sys_add_tpo_mod_func_name("libcon", "strcmp_c", strcmp_c, 0);
	sys_add_tpo_mod_func_name("libcon", "strncmp_c", strncmp_c, 0);
	sys_add_tpo_mod_func_name("libcon", "strincmp_c", strincmp_c, 0);
	sys_add_tpo_mod_func_name("libcon", "strlen_c", strlen_c, 0);
	sys_add_tpo_mod_func_name("libcon", "strlpos_c", strlpos_c, 0);
	sys_add_tpo_mod_func_name("libcon", "strtol_c", strtol_c, 0);
	sys_add_tpo_mod_func_name("libcon", "strtoll_c", strtoll_c, 0);
	sys_add_tpo_mod_func_name("libcon", "str_replace_char_c", str_replace_char_c, 0);
	sys_add_tpo_mod_func_name("libcon", "parseDate", parseDate, 0);
	sys_add_tpo_mod_func_name("libcon", "strtoul_c", strtoul_c, 0);
	sys_add_tpo_mod_func_name("libcon", "stricmp_c", stricmp_c, 0);
	sys_add_tpo_mod_func_name("libcon", "uitoa_s", uitoa_s, 0);
	sys_add_tpo_mod_func_name("libcon", "luitoa_s", luitoa_s, 0);
	sys_add_tpo_mod_func_name("libcon", "itoa_s", itoa_s, 0);
	sys_add_tpo_mod_func_name("libcon", "isalpha_c", isalpha_c, 0);
	sys_add_tpo_mod_func_name("libcon", "isdigit_c", isdigit_c, 0);
	sys_add_tpo_mod_func_name("libcon", "dtoa_c", dtoa_c, 0);

	sys_add_tpo_mod_func_name("libcon", "muldiv64", muldiv64, 0);
	sys_add_tpo_mod_func_name("libcon", "mul64", mul64, 0);
	sys_add_tpo_mod_func_name("libcon", "shl64", shl64, 0);
	sys_add_tpo_mod_func_name("libcon", "shr64", shr64, 0);
	sys_add_tpo_mod_func_name("libcon", "big128_mul", big128_mul, 0);
		

	sys_add_tpo_mod_func_name("libcon", "calc_crc32_c", calc_crc32_c, 0);
	sys_add_tpo_mod_func_name("libcon", "compare_z_exchange_c", compare_z_exchange_c, 0);
	sys_add_tpo_mod_func_name("libcon", "fetch_add_c", fetch_add_c, 0);


	sys_add_tpo_mod_func_name("libcon", "init_string", init_string, 0);
	sys_add_tpo_mod_func_name("libcon", "make_string", make_string, 0);
	sys_add_tpo_mod_func_name("libcon", "cat_string", cat_string, 0);
	sys_add_tpo_mod_func_name("libcon", "prepare_new_data", prepare_new_data, 0);
	sys_add_tpo_mod_func_name("libcon", "strcat_int", strcat_int, 0);
	sys_add_tpo_mod_func_name("libcon", "cat_cstring", cat_cstring, 0);
	sys_add_tpo_mod_func_name("libcon", "cat_ncstring", cat_ncstring, 0);
	sys_add_tpo_mod_func_name("libcon", "cat_cstring_p", cat_cstring_p, 0);
	sys_add_tpo_mod_func_name("libcon", "cat_ncstring_p", cat_ncstring_p, 0);
	sys_add_tpo_mod_func_name("libcon", "make_cstring", make_cstring, 0);
	sys_add_tpo_mod_func_name("libcon", "make_string_l", make_string_l, 0);
	sys_add_tpo_mod_func_name("libcon", "make_string_url", make_string_url, 0);
	sys_add_tpo_mod_func_name("libcon", "make_string_from_uint", make_string_from_uint, 0);
	sys_add_tpo_mod_func_name("libcon", "clone_string", clone_string, 0);
	sys_add_tpo_mod_func_name("libcon", "free_string", free_string, 0);
	sys_add_tpo_mod_func_name("libcon", "make_host_def", make_host_def, 0);
	sys_add_tpo_mod_func_name("libcon", "make_host_def_url", make_host_def_url, 0);
	sys_add_tpo_mod_func_name("libcon", "cat_tag", cat_tag, 0);
	sys_add_tpo_mod_func_name("libcon", "free_host_def", free_host_def, 0);
	sys_add_tpo_mod_func_name("libcon", "strcat_uint", strcat_uint, 0);
	sys_add_tpo_mod_func_name("libcon", "strcat_float", strcat_float, 0);
	sys_add_tpo_mod_func_name("libcon", "copy_host_def", copy_host_def, 0);


	sys_add_tpo_mod_func_name("libcon", "mem_stream_init", mem_stream_init, 0);
	sys_add_tpo_mod_func_name("libcon", "mem_stream_decomp", mem_stream_decomp, 0);
	sys_add_tpo_mod_func_name("libcon", "mem_stream_read_8", mem_stream_read_8, 0);
	sys_add_tpo_mod_func_name("libcon", "mem_stream_peek_8", mem_stream_peek_8, 0);
	sys_add_tpo_mod_func_name("libcon", "mem_stream_read_16", mem_stream_read_16, 0);
	sys_add_tpo_mod_func_name("libcon", "mem_stream_read_32", mem_stream_read_32, 0);
	sys_add_tpo_mod_func_name("libcon", "mem_stream_peek_32", mem_stream_peek_32, 0);
	sys_add_tpo_mod_func_name("libcon", "mem_stream_read", mem_stream_read, 0);
	sys_add_tpo_mod_func_name("libcon", "mem_stream_skip", mem_stream_skip, 0);
	sys_add_tpo_mod_func_name("libcon", "mem_stream_skip_to", mem_stream_skip_to, 0);
	sys_add_tpo_mod_func_name("libcon", "mem_stream_write", mem_stream_write, 0);
	sys_add_tpo_mod_func_name("libcon", "mem_stream_close", mem_stream_close, 0);

	sys_add_tpo_mod_func_name("libcon", "tpo_mod_load_tpo", tpo_mod_load_tpo, 0);
	sys_add_tpo_mod_func_name("libcon", "tpo_mod_init", tpo_mod_init, 0);
	sys_add_tpo_mod_func_name("libcon", "load_module", load_module, 0);
	sys_add_tpo_mod_func_name("libcon", "register_tpo_exports", register_tpo_exports, 0);
	sys_add_tpo_mod_func_name("libcon", "get_tpo_mod_exp_addr_name", get_tpo_mod_exp_addr_name, 0);
	sys_add_tpo_mod_func_name("libcon", "isRunning", isRunning, 0);

	init_exit();
	
	init_funcs();

}
OS_API_C_FUNC(mem_ptr)	get_next_aligned_ptr(mem_ptr ptr)
{
	unsigned int val_addr;

	val_addr=mem_to_uint(ptr);
	if((val_addr&0x0000000F)==0)return ptr;

	return uint_to_mem(((val_addr&0xFFFFFFF0)+16));
}


mem_ptr	get_next_seg_aligned_ptr(mem_ptr ptr)
{
	unsigned int val_addr;

	val_addr=mem_to_uint(ptr);
	if((val_addr&0x0000FFFF)==0)return ptr;

	return uint_to_mem(((val_addr&0xFFFF0000)+0x10000));
}
mem_size get_aligned_size(mem_ptr ptr,mem_ptr end)
{
	mem_ptr			start_align;
	mem_size		size_align;
	mem_size		size_av;
	
	start_align		=	get_next_aligned_ptr(ptr);
	if(start_align>=end)return 0;
	
	size_av			=	mem_sub(start_align,end);
	size_align		=	size_av&0xFFFFFFF0;

	return (size_align);
}



OS_API_C_FUNC(unsigned int) init_new_mem_area(mem_ptr phys_start,mem_ptr phys_end,mem_area_type_t type)
{
	int n;
	if(__global_mem_areas==PTR_NULL)return 0xFFFFFFFF;
	if(__global_mem_zones==PTR_NULL)return 0xFFFFFFFF;



	n = 0;
	while (!compare_z_exchange_c(&area_lock, 1))
		if ((n++) >= 1000)return 0;
	
	n = 0;
	while(n<MAX_MEM_AREAS)
	{
		if(__global_mem_areas[n].area_start == 0x00000000)
		{
			__global_mem_areas[n].area_start		= phys_start;
			__global_mem_areas[n].area_id			=n+1;
			__global_mem_areas[n].area_end			=phys_end;
			__global_mem_areas[n].type				=type;
			__global_mem_areas[n].zones_buffer		=&__global_mem_zones[MAX_MEM_ZONES*n];
			__global_mem_areas[n].lock_sema			=PTR_NULL;
			memset_c	(__global_mem_areas[n].zones_free		,0,MAX_MEM_ZONES*sizeof(mem_zone_desc));

			__global_mem_areas[n].zones_free[0].ptr		=	get_next_aligned_ptr(__global_mem_areas[n].area_start);
			__global_mem_areas[n].zones_free[0].size	=	get_aligned_size	( __global_mem_areas[n].area_start, __global_mem_areas[n].area_end);

			area_lock									= 0;
			return __global_mem_areas[n].area_id;
	
		}
		n++;
	}


	area_lock = 0;

	return 0xFFFFFFFF;
	
}

mem_area * find_area(mem_ptr ptr,mem_size size)
{
	int n;
	mem_ptr	 end_zone;
	
	if(__global_mem_areas==PTR_NULL)return PTR_NULL;
	if(__global_mem_zones==PTR_NULL)return PTR_NULL;

	end_zone	=	mem_add(ptr,size);

	n=0;
	while(n<MAX_MEM_AREAS)
	{
		if((ptr>=__global_mem_areas[n].area_start)&&(end_zone<__global_mem_areas[n].area_end))
			return &__global_mem_areas[n];
		n++;
	}


	return PTR_NULL;
}

OS_API_C_FUNC(unsigned int) free_mem_area(unsigned int area_id)
{
	mem_area	*area_ptr;
	int			n;
	if (__global_mem_areas == PTR_NULL)return 0xFFFFFFFF;
	if (__global_mem_zones == PTR_NULL)return 0xFFFFFFFF;

	n = 0;
	while (!compare_z_exchange_c(&area_lock, 1))
		if ((n++) >= 1000)return 0;
	
	area_ptr = get_area(area_id);

	kernel_memory_free_c(area_ptr->area_start);
	memset_c	(area_ptr ->zones_buffer,0,MAX_MEM_ZONES*sizeof(mem_zone_desc));
	memset_c	(area_ptr ->zones_free,0, MAX_MEM_ZONES*sizeof(mem_zone_desc));
	memset_c	(area_ptr, 0, sizeof(mem_area));

	area_lock = 0;

	return 1;

}

OS_API_C_FUNC(void) dump_mem_used_after	(unsigned int area_id,unsigned int time)
{
	int						n;
	size_t					mem_size;
	int						n_zones;
	mem_area				*area_ptr;

	area_ptr			=	get_area(area_id);
	if(area_ptr==PTR_NULL)
	{
		return ;
	}

	mem_size		=  0;
	n_zones			=  0;
	n				=  0;
	while(n<MAX_MEM_ZONES)
	{
		if(area_ptr->zones_buffer[n].mem.ptr != PTR_NULL)
		{
			if(area_ptr->zones_buffer[n].time>time)
			{
				n_zones++;
				/*
				unsigned int	*data;
				int _n;

				if(area_ptr->zones_buffer[n].mem.size>0)
				{
					data=area_ptr->zones_buffer[n].mem.ptr;
					for(_n=0;_n<4;_n++)
					{
						writeint(data[_n],16);
						writestr(",");
					}
					writestr("\n");
				}
				*/
			}
		}
		n++;
	}

}
OS_API_C_FUNC(unsigned int) find_zones_used(unsigned int area_id)
{
	unsigned int n, nfree;
	mem_area	*area_ptr;

	area_ptr = get_area(area_id);
	if (area_ptr == PTR_NULL)
	{
		return 0;
	}

	nfree = 0;
	n = 0;
	while (n<MAX_MEM_ZONES)
	{
		if (area_ptr->zones_buffer[n].mem.ptr == PTR_NULL)
		{
			nfree++;
		}
		n++;
	}

	return (MAX_MEM_ZONES-nfree);
}
OS_API_C_FUNC(void) dump_mem_used	(unsigned int area_id)
{
	int						n;
	size_t					mem_size;
	int						n_zones;
	mem_area				*area_ptr;

	if(__global_mem_areas==PTR_NULL)return ;
	if(__global_mem_zones==PTR_NULL)return ;

	if(area_id==0xFFFFFFFF)
	{
		int n;

		n=0;
		while(n<MAX_MEM_AREAS)
		{
			unsigned int _n;


			area_ptr		=	&__global_mem_areas[n];

			if(area_ptr->area_start!=0x00000000)
			{
				mem_size		=  0;
				n_zones			=  0;
				_n				=  0;
				while(_n<MAX_MEM_ZONES)
				{
					if(area_ptr->zones_buffer[_n].mem.ptr != PTR_NULL)
					{
						mem_size+=area_ptr->zones_buffer[_n].mem.size;
						n_zones++;
					}
					_n++;
				}

			}
			n++;
		}
		return;
	}

	area_ptr			=	get_area(area_id);
	if(area_ptr==PTR_NULL)
	{
		return ;
	}

	mem_size		=  0;
	n_zones			=  0;
	n				=  0;
	while(n<MAX_MEM_ZONES)
	{
		if(area_ptr->zones_buffer[n].mem.ptr != PTR_NULL)
		{
			mem_size+=area_ptr->zones_buffer[n].mem.size;
			n_zones++;
		}
		n++;
	}

}

/*
OS_API_C_FUNC(void) dump_free_zones	(unsigned int area_id)
{
	int						n;
	mem_area				*area_ptr;

	area_ptr			=	get_area(area_id);
	if(area_ptr==PTR_NULL)
	{
		writestr("area [");
		writeint(area_id,16);
		writestr("] not found \n");
		return ;
	}
	
	n	=	0;
	while(area_ptr->zones_free[n].ptr!= PTR_NULL)
	{
		mem_ptr	 start_free_zone;
		mem_ptr	 end_free_zone;

		start_free_zone			=	area_ptr->zones_free[n].ptr;
		end_free_zone			=	mem_add(area_ptr->zones_free[n].ptr,area_ptr->zones_free[n].size);

		writestr("free zone ");
		writeint(n,10);
		writestr(" ");
		writeptr(start_free_zone);
		writestr(" ");
		writeptr(end_free_zone);
		writestr("\n");

		n++;
	}
}
*/
int find_free_zone		(const mem_area *area,mem_size size,mem_zone_desc	*desc)
{
	int						n;
	n	=	0;
	
	while(area->zones_free[n].ptr!= PTR_NULL)
	{
		mem_ptr	 start_free_zone;
		mem_ptr	 end_free_zone;
		mem_ptr	 start_aligned_free_zone;
		mem_size size_aligned_free_zone;

		start_free_zone			=	area->zones_free[n].ptr;
		end_free_zone			=	mem_add(area->zones_free[n].ptr,area->zones_free[n].size);



		start_aligned_free_zone	=	get_next_aligned_ptr(start_free_zone);
		if(start_aligned_free_zone!=0x0)
		{
			size_aligned_free_zone	=	mem_sub	(start_aligned_free_zone,end_free_zone);

			if(size_aligned_free_zone>=size)
			{
				desc->ptr	=start_aligned_free_zone;
				desc->size	=size;
				return 1;
			}
		}
		n++;
		if(n>=MAX_MEM_ZONES)return 0;
	}
	desc->ptr	=	PTR_NULL;
	desc->size	=	0;

	return 0;
}


int allocate_zone(mem_area *area,const mem_zone_desc *desc)
{
	int						n;
	mem_zone_desc_ptr		ret;
	
	n	=	0;
	ret	=	PTR_NULL;

	while(area->zones_free[n].ptr!=	PTR_NULL)
	{
		mem_ptr		start_aligned_free_zone,end_free_zone;
		mem_size	size_aligned_free_zone;

		end_free_zone			=	mem_add(area->zones_free[n].ptr,area->zones_free[n].size);

		start_aligned_free_zone	=	get_next_aligned_ptr(area->zones_free[n].ptr);
		size_aligned_free_zone	=	mem_sub	(start_aligned_free_zone,end_free_zone);

		if(	(start_aligned_free_zone==desc->ptr)&&(size_aligned_free_zone>=desc->size))
		{
			mem_ptr					free_zone_end_ptr;
			mem_ptr					zone_end_ptr;
			mem_ptr					zone_end_aligned_ptr;

			free_zone_end_ptr		= 	mem_add	 (desc->ptr,area->zones_free[n].size);
			zone_end_ptr			=	mem_add	 (desc->ptr,desc->size);
			zone_end_aligned_ptr	=	get_next_aligned_ptr(zone_end_ptr);
			if(zone_end_aligned_ptr<free_zone_end_ptr)
			{
				area->zones_free[n].ptr		=  zone_end_aligned_ptr;
				area->zones_free[n].size	=  mem_sub	(zone_end_aligned_ptr,free_zone_end_ptr);
			}
			else
			{
				while(area->zones_free[n].ptr	!=	PTR_NULL)
				{
					area->zones_free[n].ptr		=area->zones_free[n+1].ptr;
					area->zones_free[n].size	=area->zones_free[n+1].size;
					n++;
				}
				area->zones_free[n].ptr		=PTR_NULL;
				area->zones_free[n].size	=0;
			}

			
			return 1;
		}
		n++;
	}

	return 0;
}


void	free_zone_area		(unsigned int area_id,mem_zone_desc *mem)
{
	unsigned int			n,cnt;
	mem_ptr					start_zone,end_zone;
	mem_ptr					start_free_zone,end_free_zone;
	mem_zone_desc			new_free_zone;
	mem_area				*area_ptr;

	if(area_id	==0xFFFF)return;
	if(mem->ptr	==PTR_INVALID)return;
	
	area_ptr			=	get_area(area_id);
	if(area_ptr==PTR_NULL)
	{
		return ;
	}

	if(mem->size>0)
	{
		start_zone			=	mem->ptr;
		end_zone			=	mem_add(start_zone,mem->size);

		new_free_zone.ptr	=	start_zone;
		new_free_zone.size	=	mem_sub(start_zone,end_zone);

		n					=  0;
		while(area_ptr->zones_free[n].ptr!=PTR_NULL)
		{
			start_free_zone	=	area_ptr->zones_free[n].ptr;
			end_free_zone	=	mem_add(start_free_zone,area_ptr->zones_free[n].size);

			if(end_zone==start_free_zone)
			{
				new_free_zone.ptr	=start_zone;
				new_free_zone.size	=mem_sub(start_zone,end_free_zone);

				end_zone			=end_free_zone;

				cnt=n;
				while(area_ptr->zones_free[cnt].ptr!=PTR_NULL)
				{
					area_ptr->zones_free[cnt]=area_ptr->zones_free[cnt+1];
					cnt++;
				}
				area_ptr->zones_free[cnt].ptr=PTR_NULL;
				area_ptr->zones_free[cnt].size=0;
				
			}
			else if(start_zone==end_free_zone)
			{
				new_free_zone.ptr	=start_free_zone;
				new_free_zone.size	=mem_sub(new_free_zone.ptr,end_zone);
				start_zone			=start_free_zone;

				cnt=n;
				while(area_ptr->zones_free[cnt].ptr!=PTR_NULL)
				{
					area_ptr->zones_free[cnt]=area_ptr->zones_free[cnt+1];
					cnt++;
				}
				area_ptr->zones_free[cnt].ptr	=PTR_NULL;
				area_ptr->zones_free[cnt].size	=0;
			}
			else
			{
				n++;
			}
		}
		memset_32_c			(new_free_zone.ptr,0xDEF0DEF0,new_free_zone.size);

		n	=  0;
		while(n<MAX_MEM_ZONES)
		{
			if(area_ptr->zones_free[n].ptr==PTR_NULL)
			{
				area_ptr->zones_free[n].ptr		=new_free_zone.ptr;
				area_ptr->zones_free[n].size	=new_free_zone.size;
				break;
			}
			n++;
		}
	}

	mem->ptr	=PTR_NULL;
	mem->size	=0;


	
	
}

void	free_zone		(mem_zone_ref_ptr zone_ref)
{
	mem_zone *src_zone=zone_ref->zone;

	if(src_zone==PTR_NULL)return;
	

	if(src_zone->n_refs>0)
	{
		//snooze				(10000000);
		return;
	}

	free_zone_area			(src_zone->area_id,&src_zone->mem);

	src_zone->n_refs		=0;
	src_zone->free_func		=PTR_NULL;
	src_zone->area_id		=0;

//	zone_ref->zone			=PTR_NULL;

}
OS_API_C_FUNC(unsigned int) get_zone_numref(mem_zone_ref *zone_ref)
{
	if(zone_ref==PTR_NULL)return 0;
	if(zone_ref->	zone==PTR_NULL)return 0;
	return ((mem_zone *)(zone_ref->	zone))->n_refs;
}
OS_API_C_FUNC(void) dec_zone_ref(mem_zone_ref *zone_ref)
{
	mem_zone			*zone_ptr;
	if(zone_ref			==PTR_NULL)return;
	if(zone_ref			==uint_to_mem(0xDEF0DEF0))return;
	if(zone_ref->zone	==PTR_NULL)return;
	if(zone_ref->zone	==uint_to_mem(0xDEF0DEF0))return;
	zone_ptr=	zone_ref->	zone;
	if(zone_ptr->area_id==0xFFFF)return;


	if(fetch_add_c(&zone_ptr->n_refs,-1)==1)
	{
		if(zone_ptr->mem.ptr!=PTR_NULL)
		{
			if(zone_ptr->free_func!=PTR_NULL)
				zone_ptr->free_func(zone_ref);
			free_zone(zone_ref);
		}
	}

}

OS_API_C_FUNC(void) release_zone_ref(mem_zone_ref *zone_ref)
{
	dec_zone_ref(zone_ref);
	zone_ref->zone=PTR_NULL;
}



OS_API_C_FUNC(void) copy_zone_ref(mem_zone_ref_ptr dest_zone_ref,const mem_zone_ref *zone_ref)
{
	if(zone_ref->zone==PTR_NULL)return;
	
	if(fetch_add_c				(&((mem_zone *)(zone_ref->zone))->n_refs,1)>=1)
	{
		release_zone_ref		(dest_zone_ref);
		dest_zone_ref->zone		=zone_ref->zone;
	}
	
}







OS_API_C_FUNC(unsigned int) create_zone_ref(mem_zone_ref *dest_zone_ref,mem_ptr ptr,mem_size size)
{
	mem_zone		*new_zone;

	if(n_mapped_zones>=32)
	{

	}

	new_zone			=&mapped_zones[n_mapped_zones];

	new_zone->area_id	=0xFFFF;
	new_zone->n_refs	=1;
	new_zone->mem.ptr	=ptr;
	new_zone->mem.size	=size;
	new_zone->free_func =PTR_NULL;
	dest_zone_ref->zone=new_zone;

	n_mapped_zones++;
	return 1;
}


OS_API_C_FUNC(unsigned int) allocate_new_empty_zone(unsigned int area_id,mem_zone_ref *zone_ref)
{
	unsigned int n,ret;
	mem_area	*area_ptr;

	area_ptr		=	get_area(area_id);
	if(area_ptr==PTR_NULL)
	{
		return 0;
	}
	//task_manager_aquire_semaphore	(area_ptr->lock_sema,0);
	
	release_zone_ref				(zone_ref);

	ret				=  0;
	n				=  0;
	while((n+1)<MAX_MEM_ZONES)
	{
		if(area_ptr->zones_buffer[n].mem.ptr == PTR_NULL)
		{
			mem_zone		*nzone;

			nzone			=	&area_ptr->zones_buffer[n];
			nzone->mem.ptr	=	uint_to_mem(0xFFFFFFFF);
			nzone->mem.size	=	0;
			nzone->area_id	=	area_ptr->area_id;
			nzone->n_refs	=	1;
			nzone->free_func=	PTR_NULL;
			zone_ref->zone	=	nzone;
			ret				=	1;
			break;
		}
		n++;
	}

	//task_manager_release_semaphore(area_ptr->lock_sema,0);

	if(ret==0)
	{
		//dump_task_infos_c	();	
	}

		

	return ret;
}

extern unsigned int tree_output;
		



OS_API_C_FUNC(unsigned int) allocate_new_zone(unsigned int area_id,mem_size zone_size,mem_zone_ref *zone_ref)
{
	unsigned int n;
	mem_area	*area_ptr;

	area_ptr		=	get_area(area_id);
	if(area_ptr==PTR_NULL)
	{
		return 0;
	}

	//task_manager_aquire_semaphore(area_ptr->lock_sema,0);

	release_zone_ref	(zone_ref);


	zone_size		=	((zone_size&0xFFFFFFF0)+16);
	n				=  0;
	while(n<MAX_MEM_ZONES)
	{
		if(area_ptr->zones_buffer[n].mem.ptr == PTR_NULL)
		{
			mem_zone		*nzone;

			nzone			=	&area_ptr->zones_buffer[n];
			if(find_free_zone(area_ptr,zone_size,&nzone->mem)==1)
			{
				if(allocate_zone(area_ptr,&nzone->mem)==1)
				{
					nzone->area_id	=	area_ptr->area_id;
					nzone->n_refs	=	1;
					nzone->free_func=	PTR_NULL;
					memset_c			(nzone->mem.ptr,0x00,nzone->mem.size);
					zone_ref->	zone	=	nzone;	

					//task_manager_release_semaphore(area_ptr->lock_sema,0);
					return 1;

				}
				else
				{
					//task_manager_release_semaphore(area_ptr->lock_sema,0);


					//dump_task_infos_c	();	
					

			
					return 0;
				}
			}
			else
			{

				//task_manager_release_semaphore(area_ptr->lock_sema,0);

				/*
				dump_mem_used(area_ptr->area_id);

				dump_task_infos_c	();
				snooze				(10000000);
				*/
				

				return 0;
			}
		}
		n++;
	}

	//task_manager_release_semaphore(area_ptr->lock_sema,0);

	

	
	return 0;
}

OS_API_C_FUNC(int) 	align_zone_memory(mem_zone_ref *zone_ref, mem_size align)
{
	mem_area				*area_ptr;
	mem_zone_desc			new_free_zone;
	size_t					new_size;
	unsigned int			mask;
	mem_zone				*src_zone;
	mem_zone_desc			new_zone;
	mem_zone_desc			*mem;
	mem_ptr					aligned_ptr;
	src_zone = zone_ref->zone;
	mask	 = align - 1;
	if ((mem_to_uint(src_zone->mem.ptr) & mask) == 0)return 1;

	new_size = src_zone->mem.size + align;

	if (new_size & mask)
		new_size = ((new_size & (~mask)) + align);

	area_ptr = get_area(src_zone->area_id);
	if (area_ptr == PTR_NULL)
	{
		return 0;
	}
	mem = &src_zone->mem;
	
	if (find_free_zone(area_ptr, new_size, &new_zone) == 0)
	{
		//task_manager_release_semaphore(area_ptr->lock_sema,0);
		return -1;
	}

	if (mem_to_uint(new_zone.ptr) & mask)
	{
		aligned_ptr		= uint_to_mem(((mem_to_uint(new_zone.ptr) & (~mask)) + align));
		new_zone.ptr	= aligned_ptr;

		new_free_zone.size = mem_sub(new_zone.ptr, aligned_ptr);
		if (new_free_zone.size > 0)
		{
			new_zone.size	 -= new_free_zone.size;
			new_free_zone.ptr = new_zone.ptr;
			free_zone_area(src_zone->area_id, &new_free_zone);
		}
	}
	memcpy_c		(new_zone.ptr, src_zone->mem.ptr, src_zone->mem.size);
	free_zone_area	(src_zone->area_id, &src_zone->mem);
	src_zone->mem.ptr = new_zone.ptr;
	src_zone->mem.size = new_zone.size;

	return 1;

	

}



OS_API_C_FUNC(int) 	realloc_zone	(mem_zone_ref *zone_ref,mem_size new_size)
{
	unsigned int			n,cnt;
	mem_zone_desc			new_zone;
	mem_zone_desc			*mem;
	mem_area				*area_ptr;
	mem_zone				*src_zone;
	
	src_zone			=	zone_ref->zone;
	if(src_zone==PTR_NULL)return 0;

	area_ptr			=	get_area(src_zone->area_id);
	if(area_ptr==PTR_NULL)
	{
		return 0;
	}

	//task_manager_aquire_semaphore(area_ptr->lock_sema,0);

	if(new_size&0x0000000F)
		new_size	=	((new_size&0xFFFFFFF0)+16);
	
	mem					=	&src_zone->mem;


	if(mem->size>0)
	{
		mem_ptr					start_zone,end_zone,end_zone_aligned,new_end_zone;
		mem_ptr					new_end_zone_aligned;
		mem_zone_desc			new_free_zone;

		start_zone			=	mem->ptr;
		end_zone			=	mem_add(start_zone,mem->size);
		end_zone_aligned	=	get_next_aligned_ptr(end_zone);
		new_end_zone		=	mem_add(start_zone,new_size);
		new_end_zone_aligned=	get_next_aligned_ptr(new_end_zone);

		n					=  0;

		//try to find free zone contigous to the end of the current memory

		while(area_ptr->zones_free[n].ptr!=PTR_NULL)
		{
			mem_ptr		start_free_zone,end_free_zone;

			if(n>=MAX_MEM_ZONES)
			{
				//task_manager_release_semaphore(area_ptr->lock_sema,0);
				return -1;
			}

			//current free zone to test
			start_free_zone	=	area_ptr->zones_free[n].ptr;
			end_free_zone	=	mem_add(start_free_zone,area_ptr->zones_free[n].size);
			

			if((end_zone_aligned==start_free_zone)&&(new_size<=area_ptr->zones_free[n].size))
			{
				//free zone big enought contigous to current memory block
				new_free_zone.ptr	=	new_end_zone_aligned;
				new_free_zone.size	=	mem_sub(new_free_zone.ptr,end_free_zone);

				if(new_free_zone.ptr>=end_free_zone)
				{
					//contigous free zone entirely consumed by the new alloc, remove it
					cnt=n;
					while(area_ptr->zones_free[cnt].ptr!=PTR_NULL)
					{
						area_ptr->zones_free[cnt]=area_ptr->zones_free[cnt+1];
						cnt++;
					}
				}
				else
				{
					//update the free zone to start at the end of the reallocated block
					area_ptr->zones_free[n]	= new_free_zone;
				}

				//reset newly allocated memory
				memset_c(end_zone,0,mem_sub(end_zone,new_end_zone));

				//return
				((mem_zone *)(zone_ref->zone))->mem.size = new_size;

				//task_manager_release_semaphore(area_ptr->lock_sema,0);
				return 1;
			}
			n++;
		}
	}


	if(find_free_zone		(area_ptr,new_size,&new_zone)==0)
	{
		//task_manager_release_semaphore(area_ptr->lock_sema,0);
		return -1;
	}
	
	if(allocate_zone(area_ptr,&new_zone)==0)
	{
		//task_manager_release_semaphore(area_ptr->lock_sema,0);
		return -1;
	}
	
	if(new_zone.size>src_zone->mem.size)
	{
		mem_ptr		start_new;
		mem_size	size_new;
		
		start_new	=  mem_add(new_zone.ptr,src_zone->mem.size);
		size_new	= new_zone.size-src_zone->mem.size;
		memset_c	(start_new,0x00,size_new);
	}
	
	if(src_zone->mem.size>0)
		memcpy_c				(new_zone.ptr,get_zone_ptr(zone_ref,0),src_zone->mem.size);
	
	free_zone_area			(src_zone->area_id,&src_zone->mem);

	src_zone->mem.ptr		=new_zone.ptr;
	src_zone->mem.size		=new_zone.size;

	//task_manager_release_semaphore(area_ptr->lock_sema,0);

	return 1;
}

OS_API_C_FUNC(int) expand_zone			(mem_zone_ref *ref,mem_size new_size)
{
	size_t ns;
	
	if(ref->zone==PTR_NULL)return 0;
	if(((mem_zone *)(ref->zone))->mem.size>=new_size)return 0;
	
	if(((mem_zone *)(ref->zone))->mem.size==0)
		ns		=	16;
	else
		ns		=	((mem_zone *)(ref->zone))->mem.size;

	while(ns<new_size)
		ns=ns*2;

	new_size=ns;

	return realloc_zone	(ref,new_size);
}


OS_API_C_FUNC(mem_ptr) malloc_c(mem_size sz)
{
	mem_zone_ref	ref;
	mem_ptr			m_ptr,ret_ptr;

	ref.zone=PTR_NULL;
	
	if(allocate_new_zone(0x00,sz+16,&ref)!=1)
	{
		return PTR_NULL;
	}
	
	m_ptr	=	get_zone_ptr(&ref,0);

	*((unsigned int *)(m_ptr))=mem_to_uint(ref.zone);

	ret_ptr	=	mem_add(m_ptr,16);

	return ret_ptr;
}


OS_API_C_FUNC(mem_ptr) realloc_c(mem_ptr ptr,mem_size sz)
{
	mem_zone_ref	ref;
	mem_ptr			m_ptr,ret_ptr;

	m_ptr		=	mem_dec(ptr,16);
	ref.zone	=	uint_to_mem(*((unsigned int *)(m_ptr)));

	if(realloc_zone	(&ref,sz+16)!=1)
	{
		return PTR_NULL;
	}

	m_ptr		=	get_zone_ptr(&ref,0);

	*((unsigned int *)(m_ptr))=mem_to_uint(ref.zone);

	ret_ptr		=	mem_add(m_ptr,16);

	return ret_ptr;
}


OS_API_C_FUNC(void) free_c(mem_ptr ptr)
{
	
	mem_zone_ref	ref;
	mem_ptr			m_ptr;
	if(ptr==PTR_NULL)return;

	m_ptr		=	mem_dec(ptr,16);
	ref.zone	=	uint_to_mem(*((unsigned int *)(m_ptr)));
	release_zone_ref(&ref);
	
	

}

OS_API_C_FUNC(mem_ptr) calloc_c(mem_size sz,mem_size blk)
{
	return malloc_c(sz*blk);
}


OS_API_C_FUNC(uint64_t) mul64(uint64_t a, uint64_t b)
{
	return a * b;
}

OS_API_C_FUNC(uint64_t) shl64(uint64_t a, unsigned char n)
{
	return a << n;
}
OS_API_C_FUNC(uint64_t) shr64(uint64_t a, unsigned char n)
{
	return a >> n;
}
OS_API_C_FUNC(uint64_t) muldiv64(uint64_t a, uint64_t b, uint64_t c)
{
	uint64_t tmp;
	tmp = a	* b;
	tmp = tmp / c;
	return tmp;
}

#define UINT32_MAX 0xFFFFFFFF
OS_API_C_FUNC(void) big128_mul(unsigned int x, struct big64 y, struct big128 *out)
{
	/* x * y = (z2 << 64) + (z1 << 32) + z0
	* where z2 = x1 * y1
	*       z1 = x0 * y1 + x1 * y0
	*       z0 = x0 * y0
	*/
	uint64_t x0 = x, x1 = 0, y0 = y.v[0], y1 = y.v[1];
	uint64_t z0 = x0 * y0;
	uint64_t z1a = x1 * y0;
	uint64_t z1b = x0 * y1;
	uint64_t z2 = x1 * y1;

	unsigned int z0l = z0 & UINT32_MAX;
	unsigned int z0h = z0 >> 32u;

	uint64_t z1al = z1a & UINT32_MAX;
	uint64_t z1bl = z1b & UINT32_MAX;
	uint64_t z1l = z1al + z1bl + z0h;

	uint64_t z1h = (z1a >> 32u) + (z1b >> 32u) + (z1l >> 32u);
	z2 += z1h;

	out->v[0] = z0l;
	out->v[1] = z1l & UINT32_MAX;
	out->v[2] = z2 & UINT32_MAX;
	out->v[3] = z2 >> 32u;
}

/*
OS_API_C_FUNC(double) exp_c(double a)
{
	return exp(a);
}
*/
