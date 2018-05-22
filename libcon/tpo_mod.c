/* copyright iadix 2016 */

//#define _DEBUG


#define LIBC_API C_EXPORT
#include "base/std_def.h"
#include "base/std_mem.h"
#include "base/std_str.h"
#include "base/mem_base.h"

#define KERNEL_API				C_EXPORT
#include "include/strs.h"
#include "include/fsio.h"
#include "include/mem_stream.h"
#include "include/tpo_mod.h"


unsigned int			debug				=	0xFFFFFFFF;
tpo_mod_file			*modz[64]			= { PTR_INVALID };
size_t					n_modz				=	0xFFFFFFFF;

extern unsigned int		kernel_log_id;


KERNEL_API unsigned int 		KERN_API_FUNC 	tpo_mod_imp_func_addr_c(unsigned int mod_hash, unsigned int crc_func);
KERNEL_API unsigned int 		KERN_API_FUNC 	tpo_mod_add_func_addr_c(unsigned int mod_hash, unsigned int crc_func, unsigned int func_addr);

KERNEL_API unsigned int 		 KERN_API_FUNC 	tpo_add_mod_c(unsigned int mod_hash, unsigned int deco_type, unsigned int string_table_addr);
KERNEL_API unsigned int 		 KERN_API_FUNC 	tpo_mod_add_section_c(unsigned int mod_idx, unsigned int section_addr, unsigned int section_size);
KERNEL_API struct kern_mod_fn_t	*KERN_API_FUNC 	tpo_mod_add_func_c(unsigned int mod_idx, unsigned int func_addr, unsigned int func_type, unsigned int string_id);



KERNEL_API struct kern_mod_t		*KERN_API_FUNC 	tpo_get_mod_entry_hash_c(unsigned int mod_hash);
KERNEL_API struct kern_mod_t		*KERN_API_FUNC 	tpo_get_mod_entry_idx_c(unsigned int idx);
KERNEL_API struct kern_mod_sec_t	*KERN_API_FUNC 	tpo_get_mod_sec_idx_c(unsigned int mod_idx, unsigned int sec_idx);

KERNEL_API struct kern_mod_fn_t	*KERN_API_FUNC 	tpo_get_fn_entry_idx_c(unsigned int mod_hash, unsigned int idx_func);
KERNEL_API struct kern_mod_fn_t *KERN_API_FUNC 	tpo_get_fn_entry_hash_c(unsigned int mod_hash, unsigned int crc_func);

KERNEL_API unsigned int 		 KERN_API_FUNC	tpo_calc_exp_func_hash_c(unsigned int mod_idx, unsigned int string_id);
KERNEL_API unsigned int 		 KERN_API_FUNC	tpo_calc_exp_func_hash_name_c(const char *func_name, unsigned int deco_type);
KERNEL_API unsigned int 		 KERN_API_FUNC	tpo_calc_imp_func_hash_name_c(const char *func_name, unsigned int src_deco_type, unsigned int deco_type);

/*KERNEL_API unsigned int 		 KERN_API_FUNC	sys_add_tpo_mod_func_name(const char *name, const char *fn_name, mem_ptr addr,unsigned int deco );*/

OS_API_C_FUNC(void) tpo_mod_init			(tpo_mod_file *tpo_mod)
{
	int	n;

	tpo_mod->data_sections.zone=PTR_NULL;
	allocate_new_empty_zone		(0,&tpo_mod->data_sections);
	memset_c					(tpo_mod->name,0,64);

	
	n=0;
	while(n<16)
	{
		tpo_mod->sections[n].section_ptr		=0xFFFFFFFF;
		tpo_mod->sections[n].section_img_ofset	=0;
		tpo_mod->sections[n].section_size		=0;
		tpo_mod->sections[n].exports_fnc.zone	=PTR_NULL;
		tpo_mod->sections[n].imports_fnc.zone	=PTR_NULL;
		
		allocate_new_empty_zone		(0,&tpo_mod->sections[n].exports_fnc);
		n++;
	}
}


struct kern_mod_fn_t *find_sym(unsigned int mod_idx,size_t sym_ofset, unsigned int deco_type)
{
	unsigned int		n;
	struct kern_mod_t	*mod;

	n = 0;
	while ( (mod=tpo_get_mod_entry_idx_c(n)) != PTR_NULL)
	{
		struct kern_mod_fn_t	*func_ptr;
		func_ptr = tpo_get_fn_entry_name_c(mod_idx, mod->mod_hash, sym_ofset, deco_type);
		if (func_ptr != PTR_FF)
			return func_ptr;
		n++;
	}
	return PTR_FF;
}

OS_API_C_FUNC(struct kern_mod_t *)tpo_mod_find(const char *name)
{
	return tpo_get_mod_entry_hash_c(MOD_HASH(name));
}




unsigned int tpo_mod_add_section		(tpo_mod_file *tpo_mod,mem_size img_ofset,mem_ptr ptr,mem_size section_size,unsigned int *crc_data)
{
	unsigned int		n;
	size_t				new_size;
	size_t				total_size;

	n=0;
	while(n<16)
	{
		if(tpo_mod->sections[n].section_ptr==0xFFFFFFFF)
		{
			mem_ptr			new_sec_ptr;
			
			total_size		=	get_zone_size	(&tpo_mod->data_sections);

			if(section_size > 0 )
			{
			  new_size		=	total_size+section_size;
			
			  if(realloc_zone(&tpo_mod->data_sections,new_size)<0)
			  	return 0xFFFFFFFF;
			}
	
			tpo_mod->sections[n].section_ptr		=	total_size;
			tpo_mod->sections[n].section_img_ofset	=	img_ofset;
			tpo_mod->sections[n].section_size		=	section_size;

			if(section_size > 0 )
			{
			  new_sec_ptr		=  get_zone_ptr(&tpo_mod->data_sections,tpo_mod->sections[n].section_ptr);
			  memcpy_c			(new_sec_ptr,ptr,section_size);
			  (*crc_data)=calc_crc32_c(new_sec_ptr,(unsigned int)section_size);
			}
			return n;
		}
		n++;
	}
	return 0xFFFFFFFF;
}

size_t tpo_mod_get_section_img_ofset	(tpo_mod_file *tpo_mod,unsigned int sec_idx)
{
	return tpo_mod->sections[sec_idx].section_img_ofset;
}


unsigned int tpo_mode_do_import				(tpo_mod_file *tpo_mod)
{
	int sec_idx;
	sec_idx=0;

	while(tpo_mod->sections[sec_idx].section_size>0)
	{
		mem_ptr			section_ptr;
		mem_ptr			section_relloc_addr;
		int				relloc_value;		
		int				imp_idx;
		tpo_import		*imp_ptr;
		size_t			size;
		mem_ptr			end_zone;

		if(tpo_mod->sections[sec_idx].imports_fnc.zone!=NULL)
		{
			imp_ptr				=	get_zone_ptr	(&tpo_mod->sections[sec_idx].imports_fnc,0);
			size				=	get_zone_size	(&tpo_mod->sections[sec_idx].imports_fnc);
			end_zone			=	mem_add(imp_ptr,size);

			section_ptr			=	get_zone_ptr(&tpo_mod->data_sections,tpo_mod->sections[sec_idx].section_ptr);
			imp_idx				=	0;

			while(imp_ptr->reloc_addr!=0xFFFFFFFF)
			{
			
				section_relloc_addr	=	mem_add(section_ptr,imp_ptr->reloc_addr);
				relloc_value		=	*((int *)(section_relloc_addr));

				if(relloc_value==-4)
				{
					int				relative_addr;
					int				reloc_addr;

			
					reloc_addr						=	mem_to_int(section_relloc_addr);

					relative_addr					=	((int)(imp_ptr->sym_addr))-(reloc_addr+4);

					*((int *)(section_relloc_addr))	=	relative_addr;

				}
				else
				{
					*((unsigned int *)(section_relloc_addr))=imp_ptr->sym_addr;
				}
				imp_ptr++;
			}
		}
		sec_idx++;
	}


	return 1;
}

unsigned int tpo_mod_write_import			(tpo_mod_file *tpo_mod,unsigned int sec_idx,mem_size ofset_addr,mem_ptr ptr)
{
	tpo_import		*imp_ptr;
	size_t			size;
	tpo_import		*end_zone;


	if(tpo_mod->sections[sec_idx].section_ptr==0xFFFFFFFF)return 0;

	

	imp_ptr	=	get_zone_ptr	(&tpo_mod->sections[sec_idx].imports_fnc,0);
	size	=	get_zone_size	(&tpo_mod->sections[sec_idx].imports_fnc);
	end_zone=	mem_add			(imp_ptr,size);

	while(imp_ptr->reloc_addr!=0xFFFFFFFF)
	{
		imp_ptr++;

		if(imp_ptr>=end_zone)return 0;
	}

	imp_ptr->reloc_addr	=	ofset_addr;
	imp_ptr->sym_addr	=	mem_to_uint(ptr);
	imp_ptr++;

	return 1;
}

unsigned int tpo_mod_write_reloc(tpo_mod_file *tpo_mod,unsigned int sec_idx,mem_ptr baseAddr,unsigned int ofset_addr)
{
	mem_ptr section_ptr;
	mem_ptr section_relloc_addr_ptr;
	mem_ptr section_relloc_img_ofset;
	mem_ptr section_relloc_addr_abs;
	mem_size section_relloc_addr_rel;
	unsigned int *dest_addr_ptr;
	unsigned int n;
	if(tpo_mod->sections[sec_idx].section_size<=0)return 0;

	section_ptr					=	get_zone_ptr(&tpo_mod->data_sections,tpo_mod->sections[sec_idx].section_ptr);
	section_relloc_addr_ptr		=	mem_add(section_ptr,ofset_addr);
	dest_addr_ptr				=	((unsigned int *)(section_relloc_addr_ptr));
	section_relloc_img_ofset	=	uint_to_mem(*dest_addr_ptr);

	if((*dest_addr_ptr)==0xFFFFFFFC)
	{
		int				relative_addr;
		int				reloc_addr;

		n							=	0;
		while(n<16)
		{
			if(tpo_mod->sections[n].section_size>0)
			{
				mem_ptr				sec_start_img;
				mem_ptr				sec_end_img;

				sec_start_img	=	size_to_mem(tpo_mod->sections[n].section_img_ofset);
				sec_end_img		=	mem_add(sec_start_img,tpo_mod->sections[n].section_size);
			
				if((baseAddr>=sec_start_img)&&(baseAddr<sec_end_img))
				{

					mem_ptr	target_sec_ptr;

					target_sec_ptr				=  get_zone_ptr		(&tpo_mod->data_sections,tpo_mod->sections[n].section_ptr);	
					
					section_relloc_addr_rel		=  mem_sub			(sec_start_img			,baseAddr);
					section_relloc_addr_abs		=  mem_add			(target_sec_ptr			,section_relloc_addr_rel);

					
					
					reloc_addr					=	mem_to_int(dest_addr_ptr);

					relative_addr				=	mem_to_int(section_relloc_addr_abs)-(reloc_addr+4);

					*((int *)(dest_addr_ptr))	=	relative_addr;


					return 1;
				}
			}
			n++;
		}
	}
	else
	{	
		n							=	0;
		while(n<16)
		{
			if(tpo_mod->sections[n].section_size>0)
			{
				mem_ptr	sec_start_img;
				mem_ptr	sec_end_img;

				sec_start_img	=	size_to_mem(tpo_mod->sections[n].section_img_ofset);
				sec_end_img		=	mem_add(sec_start_img,tpo_mod->sections[n].section_size);
			
				if((section_relloc_img_ofset>=sec_start_img)&&(section_relloc_img_ofset<sec_end_img))
				{
					mem_ptr	target_sec_ptr;

					section_relloc_addr_rel		=  mem_sub			(sec_start_img			,section_relloc_img_ofset);
					
					target_sec_ptr				=  get_zone_ptr		(&tpo_mod->data_sections,tpo_mod->sections[n].section_ptr);	
					section_relloc_addr_abs		=  mem_add			(target_sec_ptr			,section_relloc_addr_rel);

						
					*dest_addr_ptr				=  mem_to_uint(section_relloc_addr_abs);
					return 1;
				}
			}
			n++;
		}
	}
	
	return 0;
}
unsigned int tpo_mod_add_export(tpo_mod_file *tpo_mod,unsigned int sec_idx,unsigned int crc_32,unsigned int string_idx,unsigned int ofsetAddr)
{
	int					n;
	tpo_export			*exports;
	tpo_export			*end_zone;
	size_t				size;


	exports	=	get_zone_ptr	(&tpo_mod->sections[sec_idx].exports_fnc,0);
	size	=	get_zone_size	(&tpo_mod->sections[sec_idx].exports_fnc);
	end_zone=	mem_add(exports,size);
	n		=	0;



	while((exports->crc_32!=crc_32)&&(exports->crc_32!=0)){ exports++; if(exports>=end_zone)return 0; }

	exports->crc_32		=	crc_32;
	exports->sym_addr	=	ofsetAddr;
	exports->string_idx	=	string_idx;
	return 1;
}

OS_API_C_FUNC(int)	set_tpo_mod_exp_value32_name(const tpo_mod_file *tpo_mod,const char *name,unsigned int value)
{
	tpo_export			*exports;
	tpo_export			*end_zone;
	mem_ptr				sec_ptr,sym_ptr;
	size_t				size;
	unsigned int		n;
	unsigned int		crc_32;

		crc_32	=	calc_crc32_c(name,256);

	


	n		=	0;
	while(tpo_mod->sections[n].section_size>0)
	{
		size	=	get_zone_size	(&tpo_mod->sections[n].exports_fnc);
		if(size>0)
		{
			exports	=	get_zone_ptr	(&tpo_mod->sections[n].exports_fnc,0);
			end_zone=	mem_add			(exports,size);
			
			while(exports<end_zone)
			{ 
				if(exports->crc_32==0)break;
				if(exports->crc_32==crc_32)
				{
					unsigned int *sym_ptr_ptr;

					sec_ptr			=	get_zone_ptr(&tpo_mod->data_sections,tpo_mod->sections[n].section_ptr);
					sym_ptr			=	mem_add		(sec_ptr, exports->sym_addr);

					/*
					sym_ptr_addr	=	(unsigned int **)(sym_ptr);
					sym_ptr_ptr		=	((unsigned int *)((*sym_ptr_addr)));
					(*sym_ptr_ptr)	=	value;
					*/

					sym_ptr_ptr		=	((unsigned int *)(sym_ptr));
					(*sym_ptr_ptr)	=	value;
					
					return 1;
				}
				exports++; 
			}
		}
		n++;
	}

	return 0;

	
}


OS_API_C_FUNC(void_func_ptr)	get_tpo_mod_exp_addr_name(const tpo_mod_file *tpo_mod, const char *name, unsigned int deco_type)
{
	tpo_export			*exports;
	tpo_export			*end_zone;
	mem_ptr				sec_ptr;
	void_func_ptr		sym_ptr;
	
	size_t				size;
	unsigned int		n;
	unsigned int		crc_32;

	
	char				func_name[256];
	switch (tpo_mod->deco_type)
	{
		case MSVC_STDCALL_32:
			strcpy_cs(func_name,256,"_");
			strcat_cs(func_name,256,name);
		break;
		/*
		case GCC_STDCALL_32:
			strcpy_cs(func_name,256,"_");
			strcat_cs(func_name,256,name);
		break;
		*/
		default:
			strcpy_cs(func_name,256,name);
		break;
	}
	
	
	crc_32	=	calc_crc32_c(func_name,256);
	

	/*crc_32	=	tpo_calc_imp_func_hash_name_c(name,0,tpo_mod->deco_type);*/
	n		=	0;

	while(tpo_mod->sections[n].section_size>0)
	{
		size	=	get_zone_size	(&tpo_mod->sections[n].exports_fnc);
		if(size>=sizeof(tpo_export))
		{
			exports	=	get_zone_ptr	(&tpo_mod->sections[n].exports_fnc,0);
			end_zone=	mem_add			(exports,size-sizeof(tpo_export));
			
			while(exports<end_zone)
			{ 
				if(exports->crc_32==0)break;
				if(exports->crc_32==crc_32)
				{
					
					sec_ptr=	get_zone_ptr(&tpo_mod->data_sections,tpo_mod->sections[n].section_ptr);
					sym_ptr=	(void_func_ptr)mem_add(sec_ptr, exports->sym_addr);
					
					return sym_ptr;
				}
				exports++; 
			}
		}
		n++;
	}

				
				
	return PTR_NULL;
}


OS_API_C_FUNC(void) register_tpo_exports(tpo_mod_file *tpo_mod,const char *mod_name)
{
	unsigned int	crc_dll_name;
	tpo_section		*section;
	tpo_export		*end_zone;
	size_t		size;



	if(mod_name!=PTR_NULL)
		crc_dll_name	=	calc_crc32_c(mod_name,64);
	else
		crc_dll_name	=	calc_crc32_c(tpo_mod->name,64);

	
	section=tpo_mod->sections;
	
	while(section->section_size>0)
	{
		tpo_export		*exports;

		if(get_zone_size(&section->exports_fnc)>0)
		{
			exports	=	get_zone_ptr	(&section->exports_fnc,0);
			if(exports	!= uint_to_mem(0xFFFFFFFF))
			{
				size	=	get_zone_size	(&section->exports_fnc);
				end_zone=	mem_add(exports,size);
				while((exports<end_zone)&&(exports->crc_32!=0))
				{
					if(tpo_get_fn_entry_name_c(tpo_mod->mod_idx,crc_dll_name,exports->string_idx,tpo_mod->deco_type)==uint_to_mem(0xFFFFFFFF))
					{
						mem_ptr				sec_ptr,sym_ptr;
						sec_ptr=	get_zone_ptr(&tpo_mod->data_sections,section->section_ptr);
						sym_ptr=	mem_add		(sec_ptr, exports->sym_addr);
						tpo_mod_add_func_c		(tpo_mod->mod_idx,mem_to_uint(sym_ptr),mem_to_uint(sec_ptr),exports->string_idx);
					}
					exports++;
				}
			}
		}
		section++;
	}

}

struct ctx_t
{
	unsigned short StackSeg;
	unsigned short DataSeg;
	unsigned short CodeSeg;
	unsigned int   mem_area_id;
	unsigned int   tree_area_id;
};

struct sandbox_t
{
	struct ctx_t	newctx;
	struct ctx_t	origctx;

};


int generate_export_stub(struct sandbox_t *sand_box,mem_ptr sec_ptr,size_t func_ofset,unsigned int StackOffset,mem_zone_ref_ptr stub_code)
{
	mem_stream				strm;
	unsigned char			cpy_stack[] = { 0x8B,0x06,0x89,0x07,0x83,0xEE,0x04,0x83,0xEF,0x04,0x49,0x75,0xF3 };
	unsigned int			jmp_adr;

	mem_stream_init(&strm, stub_code, 0);

	mem_stream_write_8		(&strm, 0x55);		//push ebp
	mem_stream_write_16		(&strm, 0xE589);	//mov  ebp	, esp
	mem_stream_write_8		(&strm, 0x60);		//pusha

	mem_stream_write_16		(&strm, 0xB866);	//mov ax	, StackSeg
	mem_stream_write_16		(&strm, sand_box->newctx.StackSeg);

	mem_stream_write_16		(&strm, 0xC08E);	//mov es	, ax
	mem_stream_write_16		(&strm, 0xFF31);	//xor edi	, edi

	mem_stream_write_16		(&strm, 0x758D);	//lea esi	, [ebp+4]
	mem_stream_write_8		(&strm, 0x04);
	
	mem_stream_write_8		(&strm, 0xB9);		//mov ecx	, StackOffset
	mem_stream_write_32		(&strm, StackOffset);

	mem_stream_write_16		(&strm, 0xE9C1);	///shr ecx	, 2
	mem_stream_write_8		(&strm, 0x02);

	mem_stream_write		(&strm,cpy_stack,sizeof(cpy_stack));

	mem_stream_write_16		(&strm, 0xB866);	//mov ax	,	StackSeg
	mem_stream_write_16		(&strm, sand_box->newctx.StackSeg);
	
	mem_stream_write_16		(&strm, 0xD08E);	//mov ss	,	ax
	mem_stream_write_16		(&strm, 0xE431);	//xor esp	,	esp
	
	mem_stream_write_16		(&strm, 0xB866);	//mov ax	,	DataSeg
	mem_stream_write_16		(&strm, sand_box->newctx.DataSeg);

	mem_stream_write_16		(&strm, 0xC08E);	//mov es	,	ax
	mem_stream_write_16		(&strm, 0xD88E);	//mov ds	,	ax
	
	mem_stream_write_8		(&strm, 0x9A);		//call CodeSeg:my_func
	mem_stream_write_32		(&strm, func_ofset);
	mem_stream_write_16		(&strm, sand_box->newctx.CodeSeg);

	jmp_adr					= mem_stream_get_pos(&strm)+7;

	mem_stream_write_8		(&strm, 0xEA);		//jmp OrigCodeSeg:export_stub_back
	mem_stream_write_32		(&strm, jmp_adr);
	mem_stream_write_16		(&strm, sand_box->origctx.CodeSeg);

	mem_stream_write_16		(&strm, 0xB866);	//mov ax		,	OrigDataSeg
	mem_stream_write_16		(&strm, sand_box->origctx.DataSeg);

	mem_stream_write_16		(&strm, 0xC08E);	//mov es		,	ax
	mem_stream_write_16		(&strm, 0xD88E);	//mov ds		,	ax

	mem_stream_write_16		(&strm, 0xB866);	//mov ax		,	OrigStackSeg
	mem_stream_write_16		(&strm, sand_box->origctx.DataSeg);
	
	mem_stream_write_16		(&strm, 0xD08E);	//mov ss		,	ax
	
	mem_stream_write_8		(&strm, 0x61);		//popa


	mem_stream_write_16		(&strm, 0xEC89);	//mov esp		, ebp
	
	mem_stream_write_8		(&strm, 0xED);		//pop ebp

	mem_stream_write_8		(&strm, 0xC2);		//ret StackOffset
	mem_stream_write_16		(&strm, StackOffset);

	/*
	55						//push ebp
	89 E5					//mov  ebp	, esp
	60						//pusha
	66 B8 20 00				//mov ax	, StackSeg
	
	8E C0					//mov es	, ax
	31 FF					//xor edi	, edi
	8D 75 04				//lea esi	, [ebp+4]
	B9 04 00 00 00			//mov ecx	, StackOffset
	C1 E9 02				//shr ecx	, 2
		
	8B 06 89 07 83 EE 04 83 EF 04 49 75 F3	// stack cpy
		
	66 B8	20 00			//mov ax	,	StackSeg
	8E D0					//mov ss	,	ax
	31 E4					//xor esp	,	esp

	66 B8 70 00				//mov ax	,	DataSeg
	8E C0					//mov es	,	ax
	8E D8					//mov ds	,	ax
		
	9A 84 01 00 00 50 00	//call CodeSeg:my_func
	EA C7 01 00 00 60 00	//jmp OrigCodeSeg:export_stub_back
		
	66 B8 80 00				//mov ax		,	OrigDataSeg
	8E C0					//mov es		,	ax
	8E D8					//mov ds		,	ax
	66 B8 40 00				//mov ax		,	OrigStackSeg
	8E D0					//mov ss		,	ax
	61						//popa
	89 EC					//mov esp		, ebp
	5D						//pop ebp
	C2 04 00				//ret StackOffset
	*/
}


OS_API_C_FUNC(int) tpo_mod_load_tpo(mem_stream *file_stream,tpo_mod_file *tpo_file,unsigned int imp_func_addr)
{
	char			mod_name[128];
	
	unsigned int	nsecs;
	mem_ptr			section_remaps[16]={PTR_NULL};
	unsigned int	section_remaps_n[16]= {0};
	unsigned int	n;
	size_t			file_start;
	size_t			file_ofset;
	
	
	file_start	=	file_stream->current_ptr;

	mem_stream_read	(file_stream,mod_name,128);
	
	if( (!strncmp_c(mod_name,"lib",3)) && (strncmp_c(mod_name, "libcon", 6)) && (strncmp_c(mod_name, "libbase", 7)) )
		strcpy_cs(tpo_file->name, 64, &mod_name[3]);
	else
		strcpy_cs(tpo_file->name, 64, mod_name);
		
	tpo_file->string_buffer_len			=	mem_stream_read_32(file_stream);
	tpo_file->string_buffer_ref.zone	= PTR_NULL;

	allocate_new_zone		(0,tpo_file->string_buffer_len	,&tpo_file->string_buffer_ref);
	mem_stream_read			(file_stream,get_zone_ptr(&tpo_file->string_buffer_ref,0),tpo_file->string_buffer_len);
	debug=0;

	tpo_file->deco_type	=	mem_stream_read_32(file_stream);

	

	tpo_file->name_hash	=	MOD_HASH(tpo_file->name);
	tpo_file->mod_idx	=	tpo_add_mod_c(tpo_file->name_hash,tpo_file->deco_type,mem_to_uint(get_zone_ptr(&tpo_file->string_buffer_ref,0)));
	nsecs				=	mem_stream_read_32(file_stream);


	

	/*
	char			modh[16];
	uitoa_s(tpo_file->name_hash, modh, 16, 16);
	log_output("load mod name ");
	log_output(tpo_file->name);
	log_output("[");
	log_output(modh);
	log_output("]\n");
	*/

	n=0;
	while(n<nsecs)
	{
		char			name[8];
		unsigned int	sec_data_len;
		unsigned int	sec_imps_n;
		unsigned int	sec_exps_n;
		unsigned int	sec_imps_o;
		unsigned int	sec_exps_o;
		unsigned int	sec_flags;
		unsigned int	num_remap;
		unsigned int	sec_idx;
		unsigned int	crc_data;
		unsigned int	crc_file;
		unsigned int	n_exps,n_imps;
		size_t			file_pos;
		mem_ptr			sec_data_ptr;

		
		mem_stream_read(file_stream, name, 8);
		mem_stream_skip(file_stream,4);

		sec_flags		=	mem_stream_read_32(file_stream);
		crc_file		=	mem_stream_read_32(file_stream);
		mem_stream_skip(file_stream,4);

		sec_data_len	=	mem_stream_read_32	(file_stream);
		
		file_ofset		=	file_stream->current_ptr-file_start;
		file_pos		=	file_ofset;
		
		if((file_pos&0x0000000F)!=0)
			file_stream->current_ptr+= (((file_pos&0xFFFFFFF0)+16)-file_pos);
			
		sec_data_ptr	=	get_zone_ptr		(&file_stream->data,file_stream->current_ptr+file_stream->buf_ofs);
		
		file_ofset		=	file_stream->current_ptr-file_start;
 		sec_idx			=	tpo_mod_add_section	(tpo_file,file_ofset,sec_data_ptr,sec_data_len,&crc_data);

		mem_stream_skip			(file_stream,sec_data_len);

		sec_imps_n		=	mem_stream_read_32(file_stream);
		n_imps			=	0;

		if (!strcmp_c(name, ".text"))
			tpo_file->sections[sec_idx].is_code = 1;


		if(sec_imps_n>0)
		{
			int sz;
			sz					=(sec_imps_n+1)*sizeof(tpo_import);
			if (allocate_new_zone(0, sz, &tpo_file->sections[sec_idx].imports_fnc) != 1)
				return 0;
			
			memset_c(get_zone_ptr(&tpo_file->sections[sec_idx].imports_fnc,0),0xFF,sz);
		}

		while(n_imps<sec_imps_n)
		{
			char					dll_name[64];
			char					dll_imp_name[64];
			char					sym_name[256];
			unsigned int			fn_crc,dll_crc,ofs_addr,new_addr;
			unsigned int			imp_ofs,str_n;
			struct kern_mod_fn_t	*func_ptr;

			memset_c(dll_name, 0, 64);
			memset_c(dll_imp_name, 0, 64);
			memset_c(sym_name, 0, 256);

			if(sec_flags&0x00000001)
			{
				dll_crc		=	mem_stream_read_32(file_stream);
				fn_crc		=	mem_stream_read_32(file_stream);
				new_addr	=	tpo_mod_imp_func_addr_c(dll_crc,fn_crc);
			}
			else
			{
				int ofset;
				
				ofset		=	mem_stream_read_32		(file_stream);
				strcpy_cs(dll_name, 64, get_zone_ptr(&tpo_file->string_buffer_ref, ofset));

				dll_crc		=	calc_crc32_c(dll_name,64);
				ofset		=	mem_stream_read_32		(file_stream);

				strcpy_cs		(sym_name,256,get_zone_ptr(&tpo_file->string_buffer_ref,ofset));
	
				imp_ofs		=	0;
				func_ptr	=	uint_to_mem(0xFFFFFFFF);

				while(func_ptr	== uint_to_mem(0xFFFFFFFF))
				{
					str_n		=	0;
					while((dll_name[imp_ofs]!=';')&&(dll_name[imp_ofs]!=0))
					{
						dll_imp_name[str_n]=dll_name[imp_ofs];
						str_n++;
						imp_ofs++;
					}
					dll_imp_name[str_n]	=	0;

					dll_crc		=	calc_crc32_c(dll_imp_name,64);
					func_ptr = tpo_get_fn_entry_name_c(tpo_file->mod_idx, dll_crc, ofset, tpo_file->deco_type);
					if(dll_name[imp_ofs]==0)break;
					imp_ofs++;
				}

				if (func_ptr == uint_to_mem(0xFFFFFFFF))
					func_ptr = find_sym(tpo_file->mod_idx,ofset, tpo_file->deco_type);
			}
			ofs_addr	=	mem_stream_read_32(file_stream);
			if(func_ptr	!= uint_to_mem(0xFFFFFFFF))
			{
				tpo_mod_write_import(tpo_file, sec_idx, ofs_addr, uint_to_mem(func_ptr->func_addr));
			}
			else
			{
				console_print("import symbol not found ");
				console_print(sym_name);
				console_print(" ");
				console_print(dll_name);
				console_print(" in ");
				console_print(tpo_file->name);
				console_print("\n");
			}
			
			n_imps++;
		}
		
		sec_imps_o		=	mem_stream_read_32(file_stream);
		mem_stream_skip	(file_stream,sec_imps_o*12);

		sec_exps_n		=	mem_stream_read_32(file_stream);
		if(sec_exps_n>0)
		{
			int sz;
			sz					=(sec_exps_n+1)*sizeof(tpo_export);

			tpo_file->sections[sec_idx].exports_fnc.zone=PTR_NULL;
			if (allocate_new_zone(0, sz, &tpo_file->sections[sec_idx].exports_fnc) != 1)
				return 0;
			
			memset_c(get_zone_ptr(&tpo_file->sections[sec_idx].exports_fnc,0),0,sz);

			n_exps			=	0;
			while(n_exps<sec_exps_n)
			{
				char			dll_name[64];
				char			sym_name[256];
				unsigned int crc_dll,crc_func,sym_ofs;
				int		     mod_str_ofs,fn_str_ofs;

				if(sec_flags&0x00000001)
				{
					crc_dll	=mem_stream_read_32(file_stream);
					crc_func=mem_stream_read_32(file_stream);
				}
				else
				{
					mod_str_ofs		=	mem_stream_read_32		(file_stream);
					strcpy_cs	(dll_name,64,get_zone_ptr(&tpo_file->string_buffer_ref,mod_str_ofs));

					fn_str_ofs		=	mem_stream_read_32		(file_stream);
					strcpy_cs	(sym_name,256,get_zone_ptr(&tpo_file->string_buffer_ref,fn_str_ofs));

					crc_dll			=	calc_crc32_c(dll_name,64);
					crc_func		=	tpo_calc_exp_func_hash_c(tpo_file->mod_idx,fn_str_ofs);

				}
				sym_ofs		=	mem_stream_read_32	(file_stream);

				if(tpo_mod_add_export(tpo_file,sec_idx,crc_func,fn_str_ofs,sym_ofs)!=1)
				{
					console_print("could not add tpo export ");
					console_print(sym_name);
					console_print(" ");
					console_print(dll_name);
					console_print("\n");
				}
					
				
				n_exps++;
			}
		}

		
		sec_exps_o		=	mem_stream_read_32(file_stream);
		mem_stream_skip	(file_stream,sec_exps_o*12);
		
		num_remap					=	mem_stream_read_32(file_stream);
		section_remaps[sec_idx]		=	get_zone_ptr(&file_stream->data,file_stream->current_ptr+file_stream->buf_ofs);
		section_remaps_n[sec_idx]	=	num_remap;
		mem_stream_skip		(file_stream,num_remap*8);

		n++;
	}
	
	tpo_mode_do_import	(tpo_file);
	n	=	0;
	while(n<nsecs)
	{
		unsigned int n_rmp;
		unsigned int *remap_ptr;

		n_rmp		=	0;
		remap_ptr	=	(unsigned int *)section_remaps[n];
	
		if(remap_ptr == PTR_NULL){ n++; continue;}

		while(n_rmp<section_remaps_n[n])
		{
			unsigned int offset;
			mem_ptr		 baseAddr;
				
			baseAddr=uint_to_mem(remap_ptr[n_rmp*2+0]);
			offset	=remap_ptr[n_rmp*2+1];
			
			if(!tpo_mod_write_reloc		(tpo_file,n,baseAddr,offset))
			{
				console_print("error in hard remap \n");
			}
			n_rmp++;
		}

		
		tpo_mod_add_section_c	(tpo_file->mod_idx,mem_to_uint(get_zone_ptr(&tpo_file->data_sections,tpo_file->sections[n].section_ptr)),(unsigned int)tpo_file->sections[n].section_size);
		n++;
	}
	
	set_mem_exe(&tpo_file->data_sections);
	return 1;
}


OS_API_C_FUNC(void_func_ptr) tpo_mod_get_exp_addr(mem_stream *file_stream,const char *sym)
{
	char			mod_name[128];
	unsigned int	nsecs,deco_type;
	unsigned int	crc_sym;
	unsigned int	n;
	size_t			file_start;
	unsigned int	str_buffer_len;
	char			*str_buffer	;

	
	file_stream->current_ptr=0;
	file_start				=file_stream->current_ptr;

	
	mem_stream_read		(file_stream,mod_name,128);
	str_buffer_len	=	mem_stream_read_32(file_stream);
	str_buffer		=	get_zone_ptr(&file_stream->data,file_stream->current_ptr+file_stream->buf_ofs);
	mem_stream_skip		(file_stream,str_buffer_len);

	
	deco_type	=	mem_stream_read_32(file_stream);
	nsecs		=	mem_stream_read_32(file_stream);

	crc_sym		=	calc_crc32_c(sym,256);

	/*
	kernel_log		(kernel_log_id,"loading tpo export ");
	writestr		(mod_name);
	writestr		(" ");
	writeint		(nsecs,16);
	writestr		("\n");
	*/
	n=0;
	while(n<nsecs)
	{
		unsigned int	sec_data_len;
		unsigned int	sec_imps_n;
		unsigned int	sec_exps_n;
		unsigned int	sec_imps_o;
		unsigned int	sec_exps_o;
		unsigned int	sec_flags;
		unsigned int	num_remap;
		unsigned int	n_exps;
		size_t			file_pos;
		size_t			file_ofset;
		mem_ptr			sec_data_ptr;

		mem_stream_skip(file_stream,8);
		mem_stream_skip(file_stream,4);

		sec_flags		=	mem_stream_read_32(file_stream);
		mem_stream_skip(file_stream,4);
		mem_stream_skip(file_stream,4);

		sec_data_len	=	mem_stream_read_32	(file_stream);

		file_ofset		=	file_stream->current_ptr-file_start;
		file_pos		=	file_ofset;
		
		if((file_pos&0x0000000F)!=0)
			file_stream->current_ptr+= (((file_pos&0xFFFFFFF0)+16)-file_pos);

		sec_data_ptr	=	get_zone_ptr		(&file_stream->data,file_stream->current_ptr+file_stream->buf_ofs);

		mem_stream_skip		(file_stream,sec_data_len);

		sec_imps_n		=	mem_stream_read_32(file_stream);

		mem_stream_skip		(file_stream,sec_imps_n*12);



		sec_imps_o		=	mem_stream_read_32(file_stream);

		mem_stream_skip	(file_stream,sec_imps_o*12);

		sec_exps_n		=	mem_stream_read_32(file_stream);
		
		
		n_exps			=	0;
		while(n_exps<sec_exps_n)
		{
			unsigned int	crc_dll,crc_func,sym_ofs;
			void_func_ptr	sym_addr;
			if(sec_flags&0x00000001)
			{
				crc_dll	=mem_stream_read_32(file_stream);
				crc_func=mem_stream_read_32(file_stream);
			}
			else
			{
				char			dll_name[64];
				char			sym_name[256];
				int				ofset;
					
				ofset		=	mem_stream_read_32		(file_stream);
				strcpy_cs	(dll_name,64,&str_buffer[ofset]);

				ofset		=	mem_stream_read_32		(file_stream);
				strcpy_cs	(sym_name,256,&str_buffer[ofset]);

				/*mem_stream_read			(file_stream,dll_name,64);*/
				/*mem_stream_read			(file_stream,sym_name,256);*/



				crc_dll			=	calc_crc32_c(dll_name,64);
				crc_func		=	calc_crc32_c(sym_name,256);
				/*
				kernel_log(kernel_log_id,"func exp ");
				writestr(sym_name);
				writestr(" ");
				writestr(sym);
				writestr("\n");
				*/
			}

			sym_ofs		=	mem_stream_read_32	(file_stream);
			sym_addr	=  (void_func_ptr)mem_add(sec_data_ptr, sym_ofs);

			if(crc_func==crc_sym)
			{
				/*
				writestr	("export symbole found : ");
				writeptr	(sec_data_ptr);
				writestr	(" ");
				writeint	(sym_ofs,16);
				writestr	(" ");
				writeptr	(sym_addr);
				writestr	("\n");
				*/
				
				
				return sym_addr;
			}
			n_exps++;
		}

		sec_exps_o		=	mem_stream_read_32(file_stream);
		
		mem_stream_skip	(file_stream,sec_exps_o*12);
		
		num_remap		=	mem_stream_read_32(file_stream);
		mem_stream_skip		(file_stream,num_remap*8);
		n++;
	}

	/*
	writestr	("export symbole not found : ");
	writestr	(mod_name);
	writestr	(" ");
	writestr	(sym);
	writestr	("\n");
	*/
	
	return PTR_NULL;
}
OS_API_C_FUNC(tpo_mod_file *) find_mod_ptr(unsigned int name_hash)
{
	size_t n = n_modz;
	while (n--)
	{
		if (modz[n]->name_hash == name_hash)return modz[n];
	}

	return PTR_NULL;
}


#ifdef _DEBUG

#include <windows.h>
#include <psapi.h>

void mark_modz_zones(mem_ptr lower_bound, mem_ptr higher_bound)
{
	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;
	unsigned int i;
	unsigned int scan_id = 1;

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, GetCurrentProcessId());
	if (NULL == hProcess)
		return 1;

	// Get a list of all the modules in this process.

	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			char szModName[MAX_PATH];
			char *bn;
			size_t len;
			size_t pos;
			MODULEINFO modinfos;
			mem_ptr	   sec_ptr, end_ptr;

			// Get the full path to the module's file.
			GetModuleFileName(hMods[i], szModName, sizeof(szModName));

			if ((pos = strrpos_c(szModName, '\\')) != INVALID_SIZE)
				bn = &szModName[pos];
			else
				bn = szModName;

			if (!strncmp_c(bn, "libcon", 6))continue;

			len = strlen_c(bn);

			if (!strncmp_c(&bn[len-6],"_d",2))
			{
				GetModuleInformation(GetCurrentProcess(), hMods[i], &modinfos, sizeof(MODULEINFO));
				sec_ptr = modinfos.lpBaseOfDll;
				end_ptr = mem_add(sec_ptr, modinfos.SizeOfImage);

				while (sec_ptr < end_ptr)
				{
					mem_ptr my_zone = *((mem_ptr *)(sec_ptr));
					if ((my_zone >= lower_bound) && (my_zone < higher_bound))
					{
						mark_zone(my_zone, scan_id++);
					}

					sec_ptr = mem_add(sec_ptr, 4);
				}
			}
			/*
			if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
				sizeof(szModName) / sizeof(TCHAR)))
			{
				// Print the module name and handle value.

				_tprintf(TEXT("\t%s (0x%08X)\n"), szModName, hMods[i]);
			}
			*/
		}
	}

	// Release the handle to the process.

	CloseHandle(hProcess);
}
#else
void mark_modz_zones(mem_ptr lower_bound, mem_ptr higher_bound)
{
	size_t n = 0;
	unsigned int scan_id = 1;
	while (n<n_modz)
	{
		size_t nsecs=0;


		while (modz[n]->sections[nsecs].section_ptr != 0xFFFFFFFF)
		{
			if (!modz[n]->sections[nsecs].is_code)
			{
				mem_ptr sec_ptr = get_zone_ptr(&modz[n]->data_sections, modz[n]->sections[nsecs].section_ptr);
				mem_ptr end_ptr = mem_add(sec_ptr, modz[n]->sections[nsecs].section_size);

				while (sec_ptr < end_ptr)
				{
					mem_ptr my_zone = *((mem_ptr *)(sec_ptr));
					if ((my_zone >= lower_bound) && (my_zone < higher_bound))
					{
						mark_zone(my_zone, scan_id++);
					}

					sec_ptr = mem_add(sec_ptr, 4);
				}
			}
			nsecs++;
		}
		n++;
	}

	return;
}
#endif

OS_API_C_FUNC(int) load_module(const char *file, const char *mod_name, tpo_mod_file *mod)
{
	char				mod_addr[16];
	mem_stream			mod_file = { 0 };

	if (!get_file_to_memstream(file, &mod_file))
	{
		log_output("error opening mod file ");
		log_output(file);
		log_output(" ");
		log_output(mod_name);
		log_output("\n");
		return 0;
	}

	log_output	("mod open ");
	log_output	(file);
	log_output	(" ");
	log_output	(mod_name);
	log_output	("\n");

	tpo_mod_init		(mod);
	tpo_mod_load_tpo	(&mod_file, mod, 0);


	uitoa_s				(get_zone_ptr(&mod->data_sections, 0), mod_addr, 16, 16);
	log_output			("mod addr ");
	log_output			(mod_addr);
	log_output			("\n");

	register_tpo_exports(mod, mod_name);
	
	
	/*
	release_zone_ref	(&tpo_file_data);
	free_c(data); 
	*/
	
	/*
	log_output("register new mod ");
	log_output(mod_name);
	log_output("\n");
	*/


	if (n_modz<32)
		modz[n_modz++] = mod;

	return 1;

}

#ifdef _DEBUG
module_rproc_ptr  init_protocol;
module_rwproc_ptr init_blocks;
module_rproc_ptr  node_init_self;
module_rproc_ptr  node_log_version_infos;

module_rproc_ptr  init_pos, store_blk_staking, load_last_pos_blk, find_last_pos_block, store_blk_tx_staking;
module_rwproc_ptr compute_last_pos_diff, stake_get_reward;

module_rproc_ptr  set_block_hash, add_money_supply, sub_money_supply, remove_stored_block, node_store_last_pos_hash, node_set_last_block, node_truncate_chain_to, block_has_pow, set_next_check, store_wallet_tx, store_wallet_txs, node_list_accounts ;
module_rwproc_ptr accept_block, compute_pow_diff, store_block, node_init_service, get_pow_reward, node_list_addrs;
module_rwproc_ptr get_sess_account;


module_rproc_ptr  queue_verack_message, queue_getblock_hdrs_message, queue_getaddr_message, queue_version_message, node_is_next_block, connect_peer_node, node_get_script_modules, node_get_script_msg_handlers, node_get_mem_pool, node_del_txs_from_mempool, node_add_tx_to_mempool, queue_mempool_message;
module_rwproc_ptr make_genesis_block, node_add_block_header;
module_proc_ptr	  node_load_block_indexes, node_load_last_blks, node_check_chain, node_del_btree_from_mempool,node_load_bookmark;

module_rproc_ptr  queue_ping_message, node_has_service_module, node_get_root_app, node_get_root_app_addr, node_get_root_app_fee, node_get_mempool_hashes, node_get_apps, node_get_types_def, node_add_tmp_file, get_nscene, blog_get_ncats, node_broadcast_addr;
module_rwproc_ptr queue_pong_message, queue_getdata_message, queue_inv_message, node_get_app, node_get_app_types_def, node_get_app_objs, check_tx_files, get_scene_list, blog_get_cats, blog_get_cat_posts, blog_get_cat, blog_get_post, blog_get_last_posts, blog_get_accounts, node_add_remote_peers, node_set_bookmark, blog_get_msgs;



// set_block_hash add_money_supply node_truncate_chain_to sub_money_supply remove_stored_block store_block block_has_pow set_next_check 
//node_add_block_header accept_block compute_last_pow_diff 

//  
OS_API_C_FUNC(int) set_dbg_ptr2(module_rwproc_ptr  a, module_rwproc_ptr b, module_rwproc_ptr  c, module_rwproc_ptr d, module_rwproc_ptr e, module_rproc_ptr f, module_rwproc_ptr g, module_rproc_ptr h, module_rproc_ptr i, module_rproc_ptr j, module_rproc_ptr k, module_rproc_ptr l, module_rproc_ptr m, module_rproc_ptr n, module_rproc_ptr o, module_rwproc_ptr p, module_rwproc_ptr q, module_rproc_ptr r, module_rproc_ptr s, module_rproc_ptr t, module_rproc_ptr u, module_rproc_ptr v, module_rproc_ptr w, module_rproc_ptr x, module_rwproc_ptr y, module_rwproc_ptr z, module_rproc_ptr zz, module_rwproc_ptr zz2, module_rproc_ptr  zz3, module_rwproc_ptr  zz4, module_rwproc_ptr zz5, module_rproc_ptr zz6, module_proc_ptr zz7, module_rproc_ptr zz8, module_rwproc_ptr zz9, module_rwproc_ptr zz10, module_rwproc_ptr zz11, module_rwproc_ptr zz12, module_rwproc_ptr zz13, module_rproc_ptr zz14, module_rwproc_ptr zz15, module_rwproc_ptr zz16, module_proc_ptr zz17, module_rproc_ptr zz18, module_rwproc_ptr zz19)
{
	node_add_block_header = a;
	accept_block = b;
	compute_pow_diff = c;
	store_block = d;
	node_init_service = e;
	node_get_script_modules = f;
	get_pow_reward = g;
	node_get_script_msg_handlers = h;
	node_get_mem_pool = i;
	node_del_txs_from_mempool = j;
	node_add_tx_to_mempool = k;
	store_wallet_tx = l;
	store_wallet_txs = m;
	queue_mempool_message = n;
	node_list_accounts = o;
	node_list_addrs   = p;
	get_sess_account = q;
	node_has_service_module = r;
	queue_getblock_hdrs_message = s;

	node_get_root_app = t;
	node_get_root_app_addr=u;
	node_get_mempool_hashes = v;
	node_get_root_app_fee = w;
	node_get_apps = x;
	node_get_app = y;
	node_get_app_types_def = z;
	node_get_types_def = zz;
	node_get_app_objs = zz2;
	node_add_tmp_file = zz3;
	check_tx_files = zz4;
	get_scene_list = zz5;
	get_nscene = zz6;
	node_del_btree_from_mempool = zz7;

	blog_get_ncats = zz8;
	blog_get_cats = zz9;
	blog_get_cat_posts = zz10;
	blog_get_cat = zz11;
	blog_get_post = zz12;
	blog_get_last_posts = zz13;
	node_broadcast_addr = zz14;
	node_add_remote_peers = zz15;
	node_set_bookmark = zz16;
	node_load_bookmark = zz17;
	blog_get_accounts = zz18;
	blog_get_msgs = zz19;
	return 1;
}

OS_API_C_FUNC(int) set_dbg_ptr(module_rproc_ptr a, module_rwproc_ptr b, module_rproc_ptr c, module_proc_ptr d, module_rwproc_ptr  e, module_proc_ptr f, module_rproc_ptr  g, module_rproc_ptr h, module_rproc_ptr  i, module_rproc_ptr  j, module_rproc_ptr  k, module_rproc_ptr  l, module_rwproc_ptr  m, module_rwproc_ptr  n, module_rwproc_ptr o, module_rproc_ptr p, module_rwproc_ptr q, module_rproc_ptr r, module_rproc_ptr s, module_rproc_ptr t, module_rproc_ptr u, module_rproc_ptr v, module_rproc_ptr w, module_rproc_ptr x, module_rproc_ptr y, module_rproc_ptr z)
{
	init_protocol=a;
	init_blocks=b;
	node_init_self=c;
	node_load_block_indexes=d;
	make_genesis_block = e;
	node_load_last_blks = f;
	connect_peer_node = g;
	node_log_version_infos = h;
	queue_verack_message = i;
	queue_getaddr_message = j;
	queue_version_message = k;
	queue_ping_message = l;
	queue_pong_message = m; 
	queue_inv_message = n;
	queue_getdata_message = o;
	node_is_next_block = p;
	node_check_chain = q;
	node_store_last_pos_hash = r;
	node_set_last_block = s;
	set_block_hash = t;
	add_money_supply = u;
	node_truncate_chain_to = v;
	sub_money_supply = w;
	remove_stored_block = x;
	block_has_pow = y;
	set_next_check = z;
	return 1;
}


OS_API_C_FUNC(int) set_pos_dbg_ptr(module_rproc_ptr a, module_rproc_ptr b, module_rproc_ptr c, module_rproc_ptr d, module_rwproc_ptr e, module_rproc_ptr f, module_rwproc_ptr g)
{
	init_pos = a;
	store_blk_staking = b;
	load_last_pos_blk = c;
	find_last_pos_block = d;
	compute_last_pos_diff = e;
	store_blk_tx_staking = f;
	stake_get_reward = g;
	return 1;
}

#endif



OS_API_C_FUNC(int) execute_script_mod_rwcall(tpo_mod_file		*tpo_mod, const char *method, mem_zone_ref_ptr input, mem_zone_ref_ptr output)
{
	module_rwproc_ptr mod_func;
	mod_func = (module_rwproc_ptr)get_tpo_mod_exp_addr_name(tpo_mod, method, 0);

	if (mod_func == PTR_NULL)
	{
		log_output("method not found : ");
		log_output(method);
		log_output("\n");
		return -1;
	}

#ifdef _DEBUG
	if (!strcmp_c(method, "make_genesis_block"))
		return make_genesis_block(input, output);
	else if (!strcmp_c(method, "init_blocks"))
		return init_blocks(input, output);
	else if (!strcmp_c(method, "compute_last_pos_diff"))
		return compute_last_pos_diff(input, output);
	else if (!strcmp_c(method, "queue_pong_message"))
		return queue_pong_message(input, output);
	else if (!strcmp_c(method, "queue_getdata_message"))
		return queue_getdata_message(input, output);
	else if (!strcmp_c(method, "node_check_chain"))
		return node_check_chain(input, output);
	else if (!strcmp_c(method, "node_add_block_header"))
		return node_add_block_header(input, output);
	else if (!strcmp_c(method, "accept_block"))
		return accept_block(input, output);
	else if (!strcmp_c(method, "compute_pow_diff"))
		return compute_pow_diff(input, output);
	else if (!strcmp_c(method, "stake_get_reward"))
		return stake_get_reward(input, output);
	else if (!strcmp_c(method, "store_block"))
		return store_block(input, output);
	else if (!strcmp_c(method, "node_init_service"))
		return node_init_service(input, output);
	else if (!strcmp_c(method, "get_pow_reward"))
		return get_pow_reward(input, output);
	else if (!strcmp_c(method, "node_list_addrs"))
		return node_list_addrs(input, output);
	else if (!strcmp_c(method, "get_sess_account"))
		return get_sess_account(input, output);
	else if (!strcmp_c(method, "queue_inv_message"))
		return 	queue_inv_message(input, output);
	else if (!strcmp_c(method, "node_get_app"))
		return 	node_get_app(input, output);
	else if (!strcmp_c(method, "node_get_app_types_def"))
		return 	node_get_app_types_def(input, output);
	else if (!strcmp_c(method, "node_get_app_objs"))
		return 	node_get_app_objs(input, output);
	else if (!strcmp_c(method, "check_tx_files"))
		return 	check_tx_files(input, output);
	else if (!strcmp_c(method, "get_scene_list"))
		return 	get_scene_list(input, output);
	else if (!strcmp_c(method, "blog_get_cats"))
		return 	blog_get_cats(input, output);
	else if (!strcmp_c(method, "blog_get_cat_posts"))
		return 	blog_get_cat_posts(input, output);
	else if (!strcmp_c(method, "blog_get_cat"))
		return 	blog_get_cat(input, output);
	else if (!strcmp_c(method, "blog_get_post"))
		return 	blog_get_post(input, output);
	else if (!strcmp_c(method, "blog_get_last_posts"))
		return 	blog_get_last_posts(input, output);
	else if (!strcmp_c(method, "node_add_remote_peers"))
		return 	node_add_remote_peers(input, output);
	else if (!strcmp_c(method, "node_set_bookmark"))
		return 	node_set_bookmark(input, output);
	else if (!strcmp_c(method, "blog_get_accounts"))
		return 	blog_get_accounts(input, output);
	else if (!strcmp_c(method, "blog_get_msgs"))
		return 	blog_get_msgs(input, output);

	
	return -1;
#endif

	return mod_func(input, output);

}

OS_API_C_FUNC(int) execute_script_mod_rcall(tpo_mod_file		*tpo_mod, const char *method, mem_zone_ref_ptr input)
{
	module_rproc_ptr mod_func;
	mod_func = (module_rproc_ptr)get_tpo_mod_exp_addr_name(tpo_mod, method, 0);

	if (mod_func == PTR_NULL)
	{
		log_output("method not found : ");
		log_output(method);
		log_output("\n");
		return -1;
	}

#ifdef _DEBUG
	if (!strcmp_c(method, "init_protocol"))
		return init_protocol(input);
	else if (!strcmp_c(method, "node_init_self"))
		return node_init_self(input);
	else if (!strcmp_c(method, "init_pos"))
		return init_pos(input);
	else if (!strcmp_c(method, "node_set_last_block"))
		return node_set_last_block(input);
	else if (!strcmp_c(method, "store_blk_staking"))
		return store_blk_staking(input);
	else if (!strcmp_c(method, "load_last_pos_blk"))
		return load_last_pos_blk(input);
	else if (!strcmp_c(method, "find_last_pos_block"))
		return find_last_pos_block(input);
	else if (!strcmp_c(method, "node_store_last_pos_hash"))
		return node_store_last_pos_hash(input);
	else if (!strcmp_c(method, "node_log_version_infos"))
		return node_log_version_infos(input);
	else if (!strcmp_c(method, "queue_verack_message"))
		return queue_verack_message(input);
	else if (!strcmp_c(method, "queue_getaddr_message"))
		return queue_getaddr_message(input);
	else if (!strcmp_c(method, "queue_version_message"))
		return queue_version_message(input);
	else if (!strcmp_c(method, "queue_ping_message"))
		return queue_ping_message(input);
	else if (!strcmp_c(method, "set_block_hash"))
		return set_block_hash(input);
	else if (!strcmp_c(method, "add_money_supply"))
		return add_money_supply(input);
	else if (!strcmp_c(method, "node_truncate_chain_to"))
		return node_truncate_chain_to(input);
	else if (!strcmp_c(method, "sub_money_supply"))
		return sub_money_supply(input);
	else if (!strcmp_c(method, "remove_stored_block"))
		return remove_stored_block(input);
	else if (!strcmp_c(method, "block_has_pow"))
		return block_has_pow(input); 
	else if (!strcmp_c(method, "set_next_check"))
		return set_next_check(input);
	else if (!strcmp_c(method, "store_blk_tx_staking"))
		return store_blk_tx_staking(input);
	else if (!strcmp_c(method, "node_is_next_block"))
		return node_is_next_block(input);
	else if (!strcmp_c(method, "connect_peer_node"))
		return connect_peer_node(input);
	else if (!strcmp_c(method, "node_get_script_modules"))
		return node_get_script_modules(input);
	else if (!strcmp_c(method, "node_get_script_msg_handlers"))
		return 	node_get_script_msg_handlers(input);
	else if (!strcmp_c(method, "node_get_mem_pool"))
		return 	node_get_mem_pool(input);
	else if (!strcmp_c(method, "node_add_tx_to_mempool"))
		return 	node_add_tx_to_mempool(input);
	else if (!strcmp_c(method, "node_del_txs_from_mempool"))
		return 	node_del_txs_from_mempool(input);
	else if (!strcmp_c(method, "store_wallet_tx"))
		return 	store_wallet_tx(input);
	else if (!strcmp_c(method, "store_wallet_txs"))
		return 	store_wallet_txs(input);
	else if (!strcmp_c(method, "queue_mempool_message"))
		return 	queue_mempool_message(input);
	else if (!strcmp_c(method, "node_list_accounts"))
		return 	node_list_accounts(input);
	else if (!strcmp_c(method, "node_has_service_module"))
		return 	node_has_service_module(input); 
	else if (!strcmp_c(method, "queue_getblock_hdrs_message"))
		return 	queue_getblock_hdrs_message(input);
	else if (!strcmp_c(method, "node_get_root_app"))
		return 	node_get_root_app(input);
	else if (!strcmp_c(method, "node_get_root_app_addr"))
		return 	node_get_root_app_addr(input);
	else if (!strcmp_c(method, "node_get_mempool_hashes"))
		return 	node_get_mempool_hashes(input);
	else if (!strcmp_c(method, "node_get_root_app_fee"))
		return 	node_get_root_app_fee(input);
	else if (!strcmp_c(method, "node_get_apps"))
		return 	node_get_apps(input);
	else if (!strcmp_c(method, "node_get_types_def"))
		return 	node_get_types_def(input);
	else if (!strcmp_c(method, "node_add_tmp_file"))
		return 	node_add_tmp_file(input);
	else if (!strcmp_c(method, "get_nscene"))
		return 	get_nscene(input);
	else if (!strcmp_c(method, "blog_get_ncats"))
		return 	blog_get_ncats(input);
	else if (!strcmp_c(method, "node_broadcast_addr"))
		return 	node_broadcast_addr(input);

	
	return -1;

#endif

	return mod_func(input);

}

OS_API_C_FUNC(int) execute_script_mod_call(tpo_mod_file		*tpo_mod, const char *method)
{
	module_proc_ptr mod_func;

	mod_func = (module_proc_ptr)get_tpo_mod_exp_addr_name(tpo_mod, method, 0);

	if (mod_func == PTR_NULL)
	{
		log_output("method not found : ");
		log_output(method);
		log_output("\n");
		return -1;
	}
#ifdef _DEBUG

	if (!strcmp_c(method, "node_load_block_indexes"))
		return node_load_block_indexes();
	else if (!strcmp_c(method, "node_load_last_blks"))
		return node_load_last_blks();
	else if (!strcmp_c(method, "node_del_btree_from_mempool"))
		return node_del_btree_from_mempool();
	else if (!strcmp_c(method, "node_load_bookmark"))
		return node_load_bookmark();

	

	

	return -1;
#else
	return mod_func();
#endif
}