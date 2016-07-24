#define LIBC_API C_EXPORT
#include <windows.h>
#include "base/std_def.h"
#include "base/std_mem.h"
#include "base/std_str.h"
#include "base/mem_base.h"

#define KERNEL_API				C_EXPORT
#include "include/mem_stream.h"
#include "include/tpo_mod.h"



unsigned int			debug								=	0xFFFFFFFF;
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
KERNEL_API struct kern_mod_fn_t *KERN_API_FUNC 	tpo_get_fn_entry_name_c(unsigned int mod_idx, unsigned int mod_hash, unsigned int str_idx, unsigned int deco_type);
KERNEL_API unsigned int 		 KERN_API_FUNC	tpo_calc_exp_func_hash_c(unsigned int mod_idx, unsigned int string_id);
KERNEL_API unsigned int 		 KERN_API_FUNC	tpo_calc_exp_func_hash_name_c(const char *func_name, unsigned int deco_type);
KERNEL_API unsigned int 		 KERN_API_FUNC	tpo_calc_imp_func_hash_name_c(const char *func_name, unsigned int src_deco_type, unsigned int deco_type);

//KERNEL_API unsigned int 		 KERN_API_FUNC	sys_add_tpo_mod_func_name(const char *name, const char *fn_name, mem_ptr addr,unsigned int deco );

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
		//allocate_new_empty_zone		(0,&tpo_mod->sections[n].imports_fnc);

		n++;
	}
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
			
			total_size				=	get_zone_size	(&tpo_mod->data_sections);
			new_size				=	total_size+section_size;
			
			if(realloc_zone(&tpo_mod->data_sections,new_size)<0)
			{
				/*
				log_message	(kernel_log_id,"could not realloc ");
				writeptr	(get_zone_ptr(&tpo_mod->data_sections,0));
				writestr	(" size : ");
				writesz		(total_size,16);
				writestr	(" newsize : ");
				writesz		(new_size,16);
				writestr	("\n");
				*/
				return 0xFFFFFFFF;
				
			}
			else
			{

				/*
				new_sec_ptr	=	get_zone_ptr(&tpo_mod->data_sections,0);
				writestr("secion data realloc from ");
				writeptr(cur_sec_ptr);
				writestr("to ");
				writeptr(new_sec_ptr);
				writestr("(");
				writeint(mem_sub(cur_sec_ptr,new_sec_ptr),16);
				writestr(")");
				writestr("\n");
				*/
			}
			
			tpo_mod->sections[n].section_ptr		=	total_size;
			tpo_mod->sections[n].section_img_ofset	=	img_ofset;
			tpo_mod->sections[n].section_size		=	section_size;

			new_sec_ptr								=  get_zone_ptr(&tpo_mod->data_sections,tpo_mod->sections[n].section_ptr);
			memcpy_c								(new_sec_ptr,ptr,section_size);

			
			(*crc_data)=calc_crc32_c(new_sec_ptr,(unsigned int)section_size);

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


OS_API_C_FUNC(mem_ptr)	get_tpo_mod_exp_addr_name(const tpo_mod_file *tpo_mod,const char *name,unsigned int deco_type)
{
	tpo_export			*exports;
	tpo_export			*end_zone;
	mem_ptr				sec_ptr,sym_ptr;
	
	size_t				size;
	unsigned int		n;
	unsigned int		crc_32;

	
	char				func_name[256];
	switch (deco_type)
	{
		case MSVC_STDCALL_32:
			strcpy_cs(func_name,256,"_");
			strcat_cs(func_name,256,name);
		break;
		case GCC_STDCALL_32:
			strcpy_cs(func_name,256,"_");
			strcat_cs(func_name,256,name);
		break;
		default:
			strcpy_cs(func_name,256,name);
		break;
	}
	
	
	crc_32	=	calc_crc32_c(func_name,256);
	

	//crc_32	=	tpo_calc_imp_func_hash_name_c(name,0,tpo_mod->deco_type);
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
					sym_ptr=	mem_add(sec_ptr, exports->sym_addr);
					
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

OS_API_C_FUNC(int) tpo_mod_load_tpo(mem_stream *file_stream,tpo_mod_file *tpo_file,unsigned int imp_func_addr)
{
	char			mod_name[128];
	unsigned int	old;
	
	unsigned int	nsecs;
	mem_ptr			section_remaps[16];
	unsigned int	section_remaps_n[16];
	unsigned int	n;
	size_t			file_start;
	size_t			file_ofset;
	
	

	file_start	=	file_stream->current_ptr;

	mem_stream_read	(file_stream,mod_name,128);
	

	strcpy_cs(tpo_file->name,64,mod_name);
	
	tpo_file->string_buffer_len			=	mem_stream_read_32(file_stream);
	tpo_file->string_buffer_ref.zone	= PTR_NULL;

	/*
	kernel_log	(kernel_log_id,"loading tpo mod '");
	writestr	(mod_name);
	writestr	("' ");
	writeptr	(get_zone_ptr(&file_stream->data,file_stream->current_ptr));
	writestr	(" ");
	writeint	(tpo_file->string_buffer_len,10);
	writestr	("\n");
	*/


	allocate_new_zone		(0,tpo_file->string_buffer_len	,&tpo_file->string_buffer_ref);
	mem_stream_read			(file_stream,get_zone_ptr(&tpo_file->string_buffer_ref,0),tpo_file->string_buffer_len);
	debug=0;
	
	/*
	if(!strcmp_c(mod_name,"hid"))
		debug=3;


	if(!strcmp_c(mod_name,"bus_manager"))
		debug=4;	
	*/		
	
	tpo_file->deco_type	=	mem_stream_read_32(file_stream);
	

	tpo_file->name_hash	=	MOD_HASH(mod_name);
	tpo_file->mod_idx	=	tpo_add_mod_c(tpo_file->name_hash,tpo_file->deco_type,mem_to_uint(get_zone_ptr(&tpo_file->string_buffer_ref,0)));
	
	/*
	kernel_log	(kernel_log_id,"new mod added '");
	writestr	(mod_name);
	writestr	("' ");
	writeint	(tpo_file->mod_idx,10);
	writestr	(" ");
	writeint	(tpo_file->name_hash,16);
	writestr	(" ");
	writeint	(tpo_file->deco_type,10);
	writestr	("\n");
	*/


	nsecs				=	mem_stream_read_32(file_stream);

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
		unsigned int	sec_idx;
		unsigned int	crc_data;
		unsigned int	crc_ndis_sys,crc_hal_sys;
		unsigned int	crc_file;
		unsigned int	n_exps,n_imps;
		size_t			file_pos;
		mem_ptr			sec_data_ptr;

		

		mem_stream_skip(file_stream,8);
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

		
		/*
		if(crc_data!=crc_file)
		{
			kernel_log	(kernel_log_id,"crc do not match section data [");
			writeint	(sec_idx,10);
			writestr	("]");

			writestr	("section start : ");
			writesz		(file_ofset,16);
			writestr	("section size : ");
			writesz		(sec_data_len,16);
			writestr	("\n");
		}
			
		if(sec_idx==0xFFFFFFFF)	
			kernel_log	(kernel_log_id,"could not load tpo section \n");

		*/


		mem_stream_skip			(file_stream,sec_data_len);

		crc_ndis_sys	=	calc_crc32_c("NDIS",64);
		crc_hal_sys		=	calc_crc32_c("HAL",64);

		sec_imps_n		=	mem_stream_read_32(file_stream);
		n_imps			=	0;

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

				if (!strcmp_c(dll_name, "libcon_d"))
					strcpy_cs(dll_name, 64, "libcon");

				if (!strncmp_c(dll_name, "libbase",7))
					strcpy_cs(dll_name, 64, "libbase");
					
				dll_crc		=	calc_crc32_c(dll_name,64);
				ofset		=	mem_stream_read_32		(file_stream);
				

				strcpy_cs		(sym_name,256,get_zone_ptr(&tpo_file->string_buffer_ref,ofset));
				//fn_crc		=	calc_crc32_c(sym_name,256);

				imp_ofs		=	0;

				func_ptr	=	uint_to_mem(0xFFFFFFFF);

				

				while(func_ptr	== uint_to_mem(0xFFFFFFFF))
				{
					unsigned int deco_type;
					str_n		=	0;

					while((dll_name[imp_ofs]!=';')&&(dll_name[imp_ofs]!=0))
					{
						dll_imp_name[str_n]=dll_name[imp_ofs];
						str_n++;
						imp_ofs++;
					}
					dll_imp_name[str_n]	=	0;

					if (!strcmp_c(sym_name, "calc_crc32_c"))
						strcpy_c(dll_imp_name, "libbase");

					if (!strcmp_c(sym_name, "log_file_name"))
						deco_type = 0;
					else
						deco_type = tpo_file->deco_type;

					dll_crc		=	calc_crc32_c(dll_imp_name,64);
					func_ptr = tpo_get_fn_entry_name_c(tpo_file->mod_idx, dll_crc, ofset, deco_type);
					if (func_ptr == PTR_FF)
						printf("import symbol not found %s@%s\n", sym_name, dll_imp_name);
					
					if(dll_name[imp_ofs]==0)break;
					imp_ofs++;
				}
			}

			
			ofs_addr	=	mem_stream_read_32(file_stream);

			if(func_ptr	!= uint_to_mem(0xFFFFFFFF))
			{
				tpo_mod_write_import(tpo_file, sec_idx, ofs_addr, uint_to_mem(func_ptr->func_addr));
			
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
					printf("could not add tpo export %s@%s\n", sym_name, dll_name);
					//kernel_log	(kernel_log_id,"could not add tpo export \n");
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

		while(n_rmp<section_remaps_n[n])
		{
			unsigned int offset;
			mem_ptr		 baseAddr;
				
			baseAddr=uint_to_mem(remap_ptr[n_rmp*2+0]);
			offset	=remap_ptr[n_rmp*2+1];

			if(!tpo_mod_write_reloc		(tpo_file,n,baseAddr,offset))
			{
				printf("error in hard remap \n");
			}
			n_rmp++;
		}

		
		tpo_mod_add_section_c	(tpo_file->mod_idx,mem_to_uint(get_zone_ptr(&tpo_file->data_sections,tpo_file->sections[n].section_ptr)),(unsigned int)tpo_file->sections[n].section_size);
		n++;
	}
	

	VirtualProtect(get_zone_ptr(&tpo_file->data_sections,0), get_zone_size(&tpo_file->data_sections), PAGE_EXECUTE_READWRITE, &old);

	return 1;
}


OS_API_C_FUNC(mem_ptr) tpo_mod_get_exp_addr(mem_stream *file_stream,const char *sym)
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
			mem_ptr			sym_addr;
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

				//mem_stream_read			(file_stream,dll_name,64);
				//mem_stream_read			(file_stream,sym_name,256);



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
			sym_addr	=	mem_add				(sec_data_ptr,sym_ofs);	

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


