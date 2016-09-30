
#define MAX_MEM_AREAS 4
#define MAX_MEM_ZONES 1024*32
#define PTR_NULL	(void *)0x00000000L
#define PTR_INVALID (void *)0xDEADBEEFLL
#define PTR_FF		(void *)0xFFFFFFFFLL


typedef struct
{
	mem_ptr		 zone;
}mem_zone_ref;

typedef struct
{
	 const_mem_ptr	 zone;
}mem_zone_const_ref;

typedef mem_zone_ref			*mem_zone_ref_ptr;
typedef const mem_zone_ref		*mem_zone_ref_const_ptr;
typedef mem_zone_const_ref		*mem_zone_const_ref_ptr;

typedef int C_API_FUNC zone_free_func(mem_zone_ref_ptr zone_ref);
typedef  zone_free_func	*zone_free_func_ptr;

typedef enum {MEM_TYPE_DATA = 1,MEM_TYPE_TREE = 2}mem_area_type_t;
 
struct obj_array_t
{
	char			name[32];
	unsigned int	type;
	mem_zone_ref	char_buffer;
	unsigned int	len_str;
	unsigned int	n_objs[16];
	unsigned int	depth_level;
	unsigned int	n_props;
};


	
typedef int				vec_2s_t[2];
typedef unsigned int	vec_2_t[2];
typedef unsigned char	vec_4uc_t[4];

struct gfx_rect
{
	vec_2s_t	pos;
	vec_2_t		size;
};
#ifdef __cplusplus
	extern "C" {
#endif
LIBC_API void			C_API_FUNC init_default_mem_area	(unsigned int size);
LIBC_API unsigned int	C_API_FUNC mem_area_enable_sem		(unsigned int area_id);
//LIBC_API void			C_API_FUNC set_default_mem_area		(unsigned int size);
LIBC_API unsigned int	C_API_FUNC init_new_mem_area		(mem_ptr phys_start,	mem_ptr phys_end,mem_area_type_t type);
LIBC_API unsigned int	C_API_FUNC allocate_new_zone		(unsigned int area_id,	mem_size zone_size,	mem_zone_ref *zone_ref);
LIBC_API unsigned int	C_API_FUNC allocate_new_empty_zone	(unsigned int area_id,mem_zone_ref *zone_ref);
LIBC_API int			C_API_FUNC expand_zone				(mem_zone_ref *ref,mem_size new_size);
LIBC_API int 			C_API_FUNC realloc_zone				(mem_zone_ref *zone_ref,mem_size new_size);;

		
LIBC_API void			C_API_FUNC copy_zone_ref			(mem_zone_ref_ptr dest_zone_ref,mem_zone_ref_const_ptr zone_ref);
LIBC_API void			C_API_FUNC copy_zone_const_ref		(mem_zone_const_ref_ptr dest_zone_ref,mem_zone_const_ref_ptr zone_ref);
LIBC_API unsigned int	C_API_FUNC create_zone_ref			(mem_zone_ref *dest_zone_ref,mem_ptr ptr,mem_size size);
LIBC_API void			C_API_FUNC init_mem_system			();
//LIBC_API void			C_API_FUNC dump_free_zones			(unsigned int area_id);
LIBC_API void			C_API_FUNC dump_mem_used			(unsigned int area_id);
LIBC_API void			C_API_FUNC dump_mem_used_after		(unsigned int area_id,unsigned int time);

LIBC_API mem_ptr		C_API_FUNC get_zone_ptr				(mem_zone_ref_const_ptr ref,mem_size ofset);
LIBC_API mem_size		C_API_FUNC get_zone_size			(mem_zone_ref_const_ptr ref);

LIBC_API unsigned int	C_API_FUNC find_zones_used			(unsigned int area_id);
LIBC_API void			C_API_FUNC do_gdt_real_mode			(mem_ptr new_gdt);
LIBC_API unsigned int	C_API_FUNC get_zone_numref			(mem_zone_ref *zone_ref);

LIBC_API unsigned int	C_API_FUNC get_mem_area_list			(struct obj_array_t *ctrl_items,unsigned int first,unsigned int num,const char *style);
LIBC_API unsigned int	C_API_FUNC get_mem_area_zone_list		(unsigned int area_id,struct obj_array_t *ctrl_items,unsigned int first,unsigned int num,const char *style);
LIBC_API unsigned int	C_API_FUNC get_tree_area_zone_list		(unsigned int area_id,struct obj_array_t *ctrl_items,unsigned int first,unsigned int num,const char *style);
LIBC_API unsigned int	C_API_FUNC update_mem_area_list			(mem_zone_ref_ptr mem_area_list_node,unsigned int first,unsigned int num);
LIBC_API unsigned int	C_API_FUNC update_tree_area_zone_list	(mem_zone_ref_ptr mem_area_zone_list_node,unsigned int first,unsigned int num);
LIBC_API unsigned int	C_API_FUNC update_mem_area_zone_list	(mem_zone_ref_ptr mem_area_zone_list_node,unsigned int first,unsigned int num);

LIBC_API unsigned int	C_API_FUNC gfx_ctrl_new						(struct obj_array_t *ctrl_data,const char *style);
LIBC_API unsigned int	C_API_FUNC gfx_ctrl_new_row					(struct obj_array_t *ctrl_data,const char *style,const char *cols);
LIBC_API unsigned int	C_API_FUNC gfx_ctrl_add_item				(struct obj_array_t *ctrl_data,const char *name,const char *label,unsigned int item_id);
LIBC_API unsigned int	C_API_FUNC gfx_ctrl_create_object			(struct obj_array_t *ctrl_data,const char *class_name,const char *name,mem_zone_ref_ptr ctrl_data_node,unsigned int n_items);
LIBC_API int			C_API_FUNC gfx_create_rect_style			(struct obj_array_t *rect_style_ar,const struct gfx_rect *rect,const vec_4uc_t color);
LIBC_API unsigned int	C_API_FUNC gfx_ctrl_add_item_data			(mem_zone_ref_ptr ctrl_data_node,unsigned int item_id,mem_zone_ref_ptr item_data);
LIBC_API int			C_API_FUNC gfx_create_set_ctrl_event		(mem_zone_ref_ptr ctrl_data_node,const char *type,const struct gfx_rect *rect,const char *prop,unsigned int prop_val);
LIBC_API void			C_API_FUNC swap_zone_ref					(mem_zone_ref_ptr dest_zone_ref, mem_zone_ref_ptr src_zone_ref);
LIBC_API int			C_API_FUNC align_zone_memory				(mem_zone_ref *zone_ref, mem_size align);

extern mem_ptr			ASM_API_FUNC memset							(mem_ptr ptr, int value, unsigned int size);

LIBC_API uint64_t		C_API_FUNC mul64							(uint64_t a, uint64_t b);
LIBC_API uint64_t		C_API_FUNC muldiv64							(uint64_t a, uint64_t b, uint64_t c);


static __inline unsigned int mem_to_uint(const_mem_ptr ptr)
{
	return *((unsigned int *)&ptr);
}

static __inline unsigned short mem_to_ushort(const_mem_ptr ptr,unsigned char which)
{
	unsigned int ptr_val;
	unsigned int mask;
	unsigned short ret;
	mask	=	(0xFFFF<<which);
	ptr_val	=	*((unsigned int *)&ptr);
	ret		=	(unsigned short )((ptr_val&mask)>>which);
	return ret;
}
static __inline mem_size mem_to_size(const_mem_ptr ptr)
{
	return *((mem_size *)&ptr);
}
static __inline int mem_to_int(const_mem_ptr ptr)
{
	return *((int *)&ptr);
	//return ((int)ptr);
}


static __inline mem_ptr uint_to_mem(unsigned int val)
{
	large_uint_t val64;

	val64.uint32.ints[0]=val;
	val64.uint32.ints[1]=0;
	return ((mem_ptr )val64.uint64.val);
}
static __inline mem_ptr size_to_mem(size_t val)
{
	return ((mem_ptr )val);

	//return ((mem_ptr )val);
}

static __inline mem_size mem_sub(const_mem_ptr base,const_mem_ptr end)
{
	mem_size	s_base,s_end;

	s_base	=	mem_to_uint(base);
	s_end	=	mem_to_uint(end);

	return (s_end-s_base);

}

static __inline mem_ptr mem_add(const_mem_ptr base,mem_size size)
{
	mem_size	s_base;

	s_base	=	mem_to_uint(base);
	s_base  =    s_base + size;
	return		size_to_mem(s_base);
}

static __inline mem_ptr mem_dec(const_mem_ptr base,mem_size size)
{
	mem_size	s_base;

	s_base	=	 mem_to_uint(base);
	s_base  =    s_base - size;
	return		size_to_mem(s_base);
}


static __inline void copy_vec4u_c	(vec_4uc_t d,const vec_4uc_t s)
{
	d[0]=s[0];
	d[1]=s[1];
	d[2]=s[2];
	d[3]=s[3];
}




LIBC_API void			C_API_FUNC release_zone_ref	(mem_zone_ref_ptr zone_ref);
LIBC_API void			C_API_FUNC dec_zone_ref		(mem_zone_ref_ptr zone_ref);



#ifdef __cplusplus
	}
#endif




