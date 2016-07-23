#include <stdio.h>
#include <string.h>
#include "coff.h"
#include "../base/std_def.h"
#include "../base/std_mem.h"

#include <zlib.h>

extern unsigned int __cdecl calc_crc32_c(char *string,int len);

typedef void *mem_ptr;
typedef const void *const_mem_ptr;
typedef unsigned long mem_size;


mem_ptr __stdcall memcpy_c(mem_ptr dst_ptr,const_mem_ptr src_ptr,mem_size size)
{
	const unsigned char *sptr	=src_ptr;
	unsigned char *dptr			=dst_ptr;
	unsigned int	n			=0;;

	while(n<size){dptr[n]=sptr[n];n++;}

	return dst_ptr;
	
}
mem_ptr __stdcall memset_c(mem_ptr ptr,unsigned char v,mem_size size)
{
	unsigned char *cptr=ptr;
	while(size--){cptr[size]=v;  }
	return ptr;
}

void __stdcall free_c(mem_ptr ptr)
{
	free(ptr);
}

mem_ptr __stdcall calloc_c(mem_size sz,mem_size blk)
{
	return calloc(sz,blk);
}

void dump_reloc(PEFile *PE)
{
	int				n,i;
	int				size_relocs;
	unsigned short *blk_ptr;
	Section			*sec;
	
	for(i=0;i<PE->num_section;i++)
	{
		sec=PE->Sections[i];

		
		for(n=0;n<sec->num_remap;n++)
		{
			unsigned int *addr;
			unsigned int value;
			unsigned int			mem_ofset;
			unsigned int			total_ofset;
			unsigned int			remap_section_idx;


			if(sec->RemapList[n].type==2)
			{

				printf("relative relocation, mem ofset %d total ofset %d \n",sec->RemapList[n].base_addr,sec->RemapList[n].offset);

			}
			else
			{
				remap_section_idx	=	FindSectionMem		(PE,sec->RemapList[n].base_addr);
				mem_ofset			=	sec->RemapList[n].base_addr-PE->Sections[remap_section_idx]->SectionHeader.s_vaddr;
				total_ofset			=	sec->RemapList[n].offset+mem_ofset;

				printf("section idx: '%d' mem ofset %d total ofset %d \n",remap_section_idx,mem_ofset,total_ofset);

				addr		=	&sec->Data[total_ofset];
				value		=	*addr;
				printf("section : '%s' (0x%8.8x) [0x%8.8x + %d] = %8.8x (%8.8x) \n",sec->Name,sec->RemapList[n].base_addr,sec->Data,sec->RemapList[n].offset,value,PE->OptionalHeader.ImageBase);
			}

		}
	}
}



void dump_section(PEFile *PE,Section *sec)
{
	int i,n;
	if(sec==NULL)return;
	printf("name : %s \n",sec->Name);
	printf("section header flags : %x \n",sec->SectionHeader.s_flags);

	//http://my.execpc.com/~geezer/osd/exec/runreloc.zip

	printf("relocations : %d \n",sec->SectionHeader.s_nreloc);
	printf("relocations ptr: %d \n",sec->SectionHeader.s_relptr);
	printf("vaddr : %8.8x \n",sec->SectionHeader.s_vaddr);
	printf("paddr : %8.8x \n",sec->SectionHeader.s_paddr);
	printf("size : %d \n",sec->SectionDataLen);

	printf("externs : %d \n",sec->numexterns);
	printf("syms : %d \n",sec->numsyms);

	printf("\nsymboles : \n");
	i=0;
	while(i<sec->numsyms)
	{
		printf("symboles [%d] : %x => %x \n",sec->SymList[i].index,sec->SymList[i].Sym.e_type,sec->SymList[i].Sym.e_value);
		i++;
	}

	printf("\nimports : %d \n",sec->num_sec_imp_ord+sec->num_sec_imp_name);

	i=0;
	while(i<sec->num_sec_imp_name)
	{
		printf("module : %s - function : %s - reloc addr : 0x%8.8x \n",sec->ImportsName[i].dll_name,sec->ImportsName[i].func_name,sec->ImportsName[i].addr_reloc);
		i++;
	}

	i=0;
	while(i<sec->num_sec_imp_ord)
	{
		printf("module : %s - function : %d - reloc addr : 0x%8.8x \n",sec->ImportsOrd[i].dll_name,sec->ImportsOrd[i].ordinal_imp,sec->ImportsOrd[i].addr_reloc);
		i++;
	}
/*
	printf("\ndata : \n");
	i=0;
	while(i<sec->SectionDataLen)
	{
		printf("%2.2x ",sec->Data[i]);
		i++;
	}
*/
}


#if !defined(MAXPATHLEN)
#define MAXPATHLEN  256
#endif

char *dirname(const char *path)
{
    static char *bname;
    const char *endp;

    if (bname == NULL) {
        bname = (char *) malloc(MAXPATHLEN);
        if (bname == NULL)
            return (NULL);
    }

    /* Empty or NULL string gets treated as "." */
    if (path == NULL || *path == '\0') {
        strncpy(bname, ".", MAXPATHLEN);
        return (bname);
    }

    /* Strip trailing slashes */
    endp = path + strlen(path) - 1;
    while (endp > path && *endp == '/')
        endp--;

    /* Find the start of the dir */
    while (endp > path && *endp != '/')
        endp--;

    /* Either the dir is "/" or there are no slashes */
    if (endp == path) {
        strncpy(bname, *endp == '/' ? "/" : ".", MAXPATHLEN);
        return (bname);
    }

    do {
        endp--;
    } while (endp > path && *endp == '/');

    if (endp - path + 2 > MAXPATHLEN) {
        return (NULL);
    }
    strcpy(bname, path);
    bname[(endp - path) + 1] = 0;

    return (bname);
}

char *basename (char* path)
{
	char *ptr = strrchr (path, '/');
	return ptr ? ptr + 1 : (char*)path;
}

typedef struct
{
	string_el			*els;
	unsigned int		num_els;
	unsigned int		num_alloc;
	char				*string_buffer;
	unsigned int		last_ofs;
	unsigned int		buffer_len;

}string_el_list;


void init_list(string_el_list *list)
{
	list->num_els=0;
	list->num_alloc=0;
	list->last_ofs=0;
	list->buffer_len=0;
	

}
int find_string(string_el_list *list,char *str)
{
	int		str_len,n,ret_last;

	str_len=strlen(str);
	if(str_len==0)return -1;

	n=0;
	while(n<list->num_els)
	{
		if(!strcmp(list->els[n].string,str))
		{
			return list->els[n].start_ofs;
		}
		n++;
	}

	return -1;
}
int add_string(string_el_list *list,char *str)
{
	int		str_len,n,ret_last;

	str_len=strlen(str);
	if(str_len==0)return -1;

	n=0;
	while(n<list->num_els)
	{
		if(!strcmp(list->els[n].string,str))
		{
			return list->els[n].start_ofs;
		}
		n++;
	}


	if(list->num_alloc==0)
	{
		list->num_alloc		=	8;
		list->els			=	calloc(list->num_alloc*sizeof(string_el),1);
		
	}
	else if((list->num_els+1)>=list->num_alloc)
	{
		list->num_alloc		*=	2;
		list->els			=	realloc(list->els,list->num_alloc*sizeof(string_el));
	}

	if(list->buffer_len==0)
	{
		list->buffer_len	=	str_len+1;
		list->string_buffer	=	calloc(list->buffer_len,1);
	}
	else if((list->last_ofs+str_len+1)>=list->buffer_len)
	{

		list->buffer_len		=	list->buffer_len+str_len+2;
		list->string_buffer		=	realloc(list->string_buffer,list->buffer_len);


		n=0;
		while(n<list->num_els)
		{
			list->els[n].string		=	&list->string_buffer[list->els[n].start_ofs];
			n++;
		}
	}

	memcpy(&list->string_buffer[list->last_ofs],str,str_len+1);

	list->els[list->num_els].start_ofs	=	list->last_ofs;
	list->els[list->num_els].end_ofs	=	list->last_ofs+str_len+1;
	list->els[list->num_els].string		=	&list->string_buffer[list->last_ofs];
	list->els[list->num_els].section_id	=	0xFFFFFFFF;
	list->num_els++;

	ret_last							=	list->last_ofs;

	list->last_ofs						=	list->last_ofs+str_len+1;


	return ret_last;


}


void BuildStringList(PEFile *PE,string_el_list *list,int write_crc)
{
	int			n,i;
	
	init_list(list);

	n=0;

	while(n<PE->num_section)
	{
		Section *sec;
		sec	=	PE->Sections[n];




		if(write_crc==0)
		{
			i=0;
			while(i<sec->num_sec_imp_name)
			{
				/*
				if(sec->ImportsName[i].func_name[0]=='_')
				{
					unsigned int	fn_str_len;
					fn_str_len=strlen(sec->ImportsName[i].func_name);
					memmove(sec->ImportsName[i].func_name,&sec->ImportsName[i].func_name[1],fn_str_len);
				}
				*/

				add_string(list,sec->ImportsName[i].dll_name);
				add_string(list,sec->ImportsName[i].func_name);


				i++;
			}

			i=0;
			while(i<sec->num_sec_exp_name)
			{
				/*
				if(sec->ExportsName[i].func_name[0]=='_')
				{
					unsigned int	fn_str_len;
					fn_str_len=strlen(sec->ExportsName[i].func_name);
					memmove(sec->ExportsName[i].func_name,&sec->ExportsName[i].func_name[1],fn_str_len);
				}
				*/

				add_string(list,sec->ExportsName[i].dll_name);
				add_string(list,sec->ExportsName[i].func_name);

				i++;
			}


			i=0;
			while(i<sec->num_sec_imp_ord)
			{
				add_string(list,sec->ImportsOrd[i].dll_name);
				i++;
			}

			i=0;
			while(i<sec->num_sec_exp_ord)
			{
				add_string(list,sec->ExportsOrd[i].dll_name);
				i++;
			}
		}

		n++;
	}

}


void WriteTPOFile(PEFile *PE,char *file_name)
{
	FILE			*s;
	int				i,n,nsecs;
	unsigned int	sec_pe_file_start;
	unsigned int	sec_pe_file_end;

	char			module_name[128];
	unsigned int	fofs;
	unsigned int	mod_deco_type;
	unsigned int	entry_point_addr_reloc;
	int				write_crc;
	string_el_list	list_str;
	
	


	memset	(module_name,0,sizeof(module_name));

	strcpy	(module_name,basename(PE->file_name));

	n=strlen(module_name);
	while((module_name[n]!='.')&&(n>0)){n--;}
	module_name[n]=0;

	write_crc	=0;
	
	for(i=0;i<PE->num_section;i++)
	{
		Section *sec;
		sec	=	PE->Sections[i];


		sec_pe_file_start	=sec->v_addr;
		sec_pe_file_end		=sec_pe_file_start+sec->SectionDataLen;

		if( (PE->OptionalHeader.AddressOfEntryPoint>=sec_pe_file_start)&&
			(PE->OptionalHeader.AddressOfEntryPoint<sec_pe_file_end))
		{
				
			//FindSectionMemPtr(
			entry_point_addr_reloc		=	PE->OptionalHeader.AddressOfEntryPoint-sec_pe_file_start;//PE->OptionalHeader.AddressOfEntryPoint;//-sec->SectionHeader.s_vaddr;
			strcpy(sec->ExportsName[sec->num_sec_exp_name].dll_name,module_name);
			strcpy(sec->ExportsName[sec->num_sec_exp_name].func_name,"EntryPoint");
			sec->ExportsName[sec->num_sec_exp_name].addr_reloc=entry_point_addr_reloc;
			sec->num_sec_exp_name++;
		}
	}



	BuildStringList(PE,&list_str,write_crc);
	
	fofs		 =128+4+4;
	fofs		+= 4+list_str.buffer_len;

	


	

	

	for(i=0;i<PE->num_section;i++)
	{
		Section *sec;
		sec	=	PE->Sections[i];

		if((stricmp(sec->Name,".reloc"))&&(sec->SectionDataLen>0))
		{
			fofs	+=	8;
			fofs	+=	16;
			fofs	+=	4;
			

			if((fofs&0x0000000F)!=0)
				fofs=((fofs&0xFFFFFFF0)+16);

			sec->sections_file_data_ptr	=fofs;

			if((sec->SectionDataLen&0x0000000F)!=0)
			{
				int new_size;
				new_size			=((sec->SectionDataLen&0xFFFFFFF0)+16);
				
				if(new_size>sec->SectionDataLen)
				{
					sec->Data			=realloc(sec->Data,new_size);
					memset				(&sec->Data[sec->SectionDataLen],0xFF,new_size-sec->SectionDataLen);
					sec->SectionDataLen	=new_size;
				}
			}

			fofs+=sec->SectionDataLen;




			fofs+=4;
			fofs+=sec->num_sec_imp_name*(4+4+4);

			fofs+=4;
			fofs+=sec->num_sec_imp_ord*(4+4+4);

			fofs+=4;
			fofs+=sec->num_sec_exp_name*(4+4+4);

			fofs+=4;
			fofs+=sec->num_sec_exp_ord*(4+4+4);	
			
			fofs+=4;
			fofs+=sec->num_remap*(4+4);

		}
	}


	for(i=0;i<PE->num_section;i++)
	{
		Section *sec;
		sec	=	PE->Sections[i];

		if((stricmp(sec->Name,".reloc"))&&(sec->SectionDataLen>0))
		{
			printf("num remaps : %d %x %x\n",sec->num_remap,sec->SectionHeader.s_vaddr,sec->SectionHeader.s_vaddr+sec->SectionHeader.s_size);
			for(n=0;n<sec->num_remap;n++)
			{	
				unsigned int *addr;
				unsigned int value;
				unsigned int *target_mem_addr;
				unsigned int target_r_addr;

				unsigned int target_sec_id;
				unsigned int target_data_ptr;
				unsigned int target_data_ofset;


				unsigned int mem_ofset;
				unsigned int total_ofset;
				unsigned int remap_section_idx;

				if(sec->RemapList[n].type	==	2)
				{

				}
				else
				{
					remap_section_idx	=	FindSectionMem		(PE,sec->RemapList[n].base_addr);
					mem_ofset			=	sec->RemapList[n].base_addr-PE->Sections[remap_section_idx]->v_addr;
					total_ofset			=	sec->RemapList[n].offset+mem_ofset;

					
					
					addr				=	&sec->Data[total_ofset];
					value				=	*addr;
					value				=	value-PE->ImageBase;
					value				=	value & 0x0FFFFFFF; //value to relocate
					
					//section of the addresse to relocate
					target_sec_id		=	FindSectionMem		(PE,value);
					
					if(target_sec_id != 0xFFFFFFFF)
					{
						printf(" relocation, section addr %x %8.8x addr final %8.8x\n",sec->RemapList[n].offset,PE->Sections[target_sec_id]->v_addr,value);
						
							
						//offset of the address in the section
						target_r_addr		=   value - PE->Sections[target_sec_id]->v_addr;
						//offset of the address in the file
						target_r_addr		=	PE->Sections[target_sec_id]->sections_file_data_ptr+target_r_addr;

						//replace the addresse to relocate by the addresse of the location in the file
						*addr				=   target_r_addr;
					}
					else
					{
						printf(" relocation not found addr final %x %8.8x\n",sec->RemapList[n].base_addr,value);
					}
				}
		
			}
		}
	}

	s=fopen(file_name,"wb");
	if(s==NULL)return;

	




	fwrite	(module_name,128,1,s);
	fwrite	(&list_str.buffer_len,4,1,s);
	fwrite	(list_str.string_buffer,list_str.buffer_len,1,s);


	


	mod_deco_type	=	0;
	nsecs			=	PE->num_section;

	if(GetPESectionPtr(PE,".reloc"))
		nsecs--;

	for(i=0;i<PE->num_section;i++)
	{
		Section			*sec;

		sec	=	PE->Sections[i];

		if(PE->Sections[i]->SectionDataLen==0)
			nsecs--;

		for(n=0;n<sec->num_sec_exp_name;n++)
		{	
			int ofset;

			if(!strcmp(sec->ExportsName[n].func_name,"mod_name_deco_type"))
			{
				mod_deco_type	=	*((unsigned int	*)(sec->Data+sec->ExportsName[n].addr_reloc));

				printf(" module decoration type found %d \n",mod_deco_type);
			}
		}
	}
	
	fwrite	(&mod_deco_type,4,1,s);
	fwrite	(&nsecs,4,1,s);

	

	for(i=0;i<PE->num_section;i++)
	{
		Section			*sec;
		char			data_tag[4]="DATA";

		sec	=	PE->Sections[i];

		if((stricmp(sec->Name,".reloc"))&&(sec->SectionDataLen>0))
		{
			unsigned int	file_pos;
			unsigned int	align;
			unsigned int	crc32;
			unsigned int	crc32_section;
			unsigned int	section_flags;
			unsigned char	pad[8]={0xFF};

			
			section_flags		=	0;
			
			if(write_crc)
				section_flags |=	0x00000001;


			

			fwrite	(sec->Name						,8,1,s);

			crc32_section	=	calc_crc32_c	(sec->Data,sec->SectionDataLen);

			fwrite	(&sec->SectionHeader.s_flags	,4,1,s);
			fwrite	(&section_flags					,4,1,s);
			fwrite	(&crc32_section					,4,1,s);
			fwrite	(&sec->numreloc					,4,1,s);


			fwrite	(&sec->SectionDataLen		,4,1,s);

			file_pos						=	ftell(s);

			printf("data pos : %d \n",file_pos);
			if((file_pos&0x0000000F)!=0)
			{
				unsigned int aligned_pos;
				unsigned int padding;
				
				aligned_pos	=	((file_pos&0xFFFFFFF0)+16);
				padding		=	aligned_pos-file_pos;

				printf("data padding : %d \n",padding);

				fwrite		(pad,padding,1,s);
			}
			
			fwrite	(sec->Data					, sec->SectionDataLen,1,s);


			printf("write import %d name  \n",sec->num_sec_imp_name);
			fwrite	(&sec->num_sec_imp_name				,4,1,s);
			for(n=0;n<sec->num_sec_imp_name;n++)
			{	
				if(write_crc)
				{
					crc32	=	calc_crc32_c(sec->ImportsName[n].dll_name,64);
					fwrite	(&crc32	,4,1,s);
					crc32	=	calc_crc32_c(sec->ImportsName[n].func_name,256);
					fwrite	(&crc32	,4,1,s);
				}
				else
				{
					int ofset;

					ofset	=	find_string(&list_str,sec->ImportsName[n].dll_name);
					fwrite	(&ofset,4,1,s);

					printf("string index %d => '%s' \n"	,ofset,&list_str.string_buffer[ofset]);

					ofset	=	find_string(&list_str,sec->ImportsName[n].func_name);
					fwrite	(&ofset,4,1,s);

					printf("string index %d => '%s' \n"	,ofset,&list_str.string_buffer[ofset]);


					/*
					fwrite	(sec->ImportsName[n].dll_name	,64,1,s);
					fwrite	(sec->ImportsName[n].func_name	,256,1,s);
					*/
				}
				fwrite	(&sec->ImportsName[n].addr_reloc,4,1,s);

				printf("name : %s[%8.8x]@%s[%8.8x] - func addr: 0x%8.8x => %x \n"	,sec->ImportsName[n].func_name,calc_crc32_c(sec->ImportsName[n].func_name,256),sec->ImportsName[n].dll_name,calc_crc32_c(sec->ImportsName[n].dll_name,64),sec->ImportsName[n].addr_reloc,*((unsigned int *)(&sec->Data[sec->ImportsName[n].addr_reloc])));
				
			}
			fwrite	(&sec->num_sec_imp_ord				,4,1,s);
			for(n=0;n<sec->num_sec_imp_ord;n++)
			{	
				if(write_crc)
				{
					crc32	=	calc_crc32_c(sec->ImportsOrd[n].dll_name,64);
					fwrite	(&crc32	,4,1,s);
				}
				else
				{
					int ofset;

					ofset	=	find_string(&list_str,sec->ImportsOrd[n].dll_name);
					fwrite		(&ofset	,4,1,s);
					
					
					//fwrite	(sec->ImportsOrd[n].dll_name	,64,1,s);
				}
				fwrite	(&sec->ImportsOrd[n].ordinal_imp,4,1,s);
				fwrite	(&sec->ImportsOrd[n].addr_reloc ,4,1,s);
			}
			
			fwrite	(&sec->num_sec_exp_name				,4,1,s);

			printf("write export %d name  \n",sec->num_sec_exp_name);
			
			for(n=0;n<sec->num_sec_exp_name;n++)
			{	
				if(write_crc)
				{
					crc32	=	calc_crc32_c(sec->ExportsName[n].dll_name,64);
					fwrite		(&crc32	,4,1,s);

					crc32	=	calc_crc32_c(sec->ExportsName[n].func_name,256);
					fwrite		(&crc32	,4,1,s);
				}
				else
				{

					int ofset;

					ofset	=	find_string(&list_str,sec->ExportsName[n].dll_name);
					fwrite	(&ofset,4,1,s);

					ofset	=	find_string(&list_str,sec->ExportsName[n].func_name);
					fwrite	(&ofset,4,1,s);


					/*
					fwrite	(sec->ExportsName[n].dll_name	,64,1,s);	
					fwrite	(sec->ExportsName[n].func_name	,256,1,s);
					*/
				}
				fwrite	(&sec->ExportsName[n].addr_reloc,4,1,s);

				printf("name : %s[%8.8x]@%s[%8.8x] - func addr: 0x%8.8x\n"	,sec->ExportsName[n].func_name,calc_crc32_c(sec->ExportsName[n].func_name,256),sec->ExportsName[n].dll_name,calc_crc32_c(sec->ExportsName[n].dll_name,64),sec->ExportsName[n].addr_reloc);
			}
			fwrite	(&sec->num_sec_exp_ord				,4,1,s);
			for(n=0;n<sec->num_sec_exp_ord;n++)
			{	
				if(write_crc)
				{
					crc32	=	calc_crc32_c(sec->ExportsOrd[n].dll_name,64);
					fwrite		(&crc32	,4,1,s);
				}
				else
				{
					int ofset;

					ofset	=	find_string(&list_str,sec->ExportsOrd[n].dll_name);
					fwrite	(&ofset	,4,1,s);

					//fwrite	(sec->ExportsOrd[n].dll_name	,64,1,s);
				}
				fwrite	(&sec->ExportsOrd[n].ordinal_exp,4,1,s);
				fwrite	(&sec->ExportsOrd[n].addr_reloc ,4,1,s);
			}
			fwrite	(&sec->num_remap				,4,1,s);
			for(n=0;n<sec->num_remap;n++)
			{	
	
				unsigned int			remap_section_idx;
				unsigned int			mem_ofset;
				unsigned int			total_ofset;


				remap_section_idx	=	FindSectionMem		(PE,sec->RemapList[n].base_addr);
				mem_ofset			=	sec->RemapList[n].base_addr-PE->Sections[remap_section_idx]->v_addr;

				if(sec->RemapList[n].type==2)
				{
					total_ofset	=	PE->Sections[remap_section_idx]->sections_file_data_ptr+mem_ofset;

					fwrite	(&total_ofset					,4,1,s);
					fwrite	(&sec->RemapList[n].offset		,4,1,s);

				}
				else
				{


					total_ofset			=	sec->RemapList[n].offset+mem_ofset;

					fwrite	(&sec->RemapList[n].base_addr	,4,1,s);
					fwrite	(&total_ofset					,4,1,s);
				}


			}
		}
	}

	fclose(s);
}

void rep_string(char *string)
{
	unsigned int		n;
	n=strlen(string);
	while(n--){ if(string[n]==0)return; if(string[n]=='\\')string[n]='/'; }
}

int main(int argc,char **argv)
{
	int				i,n,n_args;
	char			target_path[512];
	char			path[256];
	char			target_file[256];
	char			module_name[64];
	char			ext[4];
	PEFile			File;
	unsigned int	do_compress,compress_level;


	unsigned char *maped_data;
	

	if(argc>1)
	{
		strcpy(path,argv[1]);
	}
	else
	{
		printf("no file specified\n");
		goto end;
	}
	rep_string(path);

	do_compress		=	0;
	compress_level	=	0;
	n_args			=	2;

	while(n_args<argc)
	{
		if(argv[n_args][0]!='-')break;
		
		if(argv[n_args][1]=='z')
		{
			do_compress		=	1;
			compress_level	=	argv[n_args][2]-48;
		}
		n_args++;
	}

	if(argc>n_args)
	{
		strcpy		(target_path,argv[n_args]);
		rep_string	(target_path);
	}
	else
	{
		strcpy(target_path,dirname(path));
	}

	printf("using file : %s -> %s \n",path,target_path);
	
	
	n	=strlen(path);
	i	=0;
	while((n--)>0)
	{
		if(path[n]=='.')
		{
			ext[i]=0;
			break;
		}
		ext[i]=path[n];
		i++;
	}
	if(!strncmp(ext,"lld",3))
	{
		ReadExeFile		(path,&File);
		ReadPeSections	(&File);
		ReadPEImpExp	(&File);
		BuildPE_RVA		(&File);
	}
	else if(!strncmp(ext,"os",2))
	{
		ReadElfFile		(path,&File);
		ReadElfSections	(&File);
		ReadElfSegments	(&File);
		ReadElfImpExp	(&File);
		BuildElf_RVA	(&File);
	}	



	strcpy	(module_name	,basename(File.file_name));
	n=strlen(module_name);

	while(n--){	if(module_name[n]=='.'){module_name[n]=0;break;}}

	
	strcpy	(target_file	,target_path);
	strcat	(target_file	,"/");
	strcat	(target_file	,module_name);
	strcat	(target_file	,".tpo");


	printf("\n\ntext section : \n");
	dump_section(&File,GetPESectionPtr(&File,".text"));

	printf("\n\nrdata section : \n");
	dump_section(&File,GetPESectionPtr(&File,".rdata"));

	printf("\n\ndata section : \n");
	dump_section(&File,GetPESectionPtr(&File,".data"));

	printf("\n\ninit section : \n");
	dump_section(&File,GetPESectionPtr(&File,"INIT"));

	printf("\n\nres section : \n");
	dump_section(&File,GetPESectionPtr(&File,".rsrc"));

	printf("\n\new section : \n");
	dump_section(&File,GetPESectionPtr(&File,".newsec"));

	printf("\n\nbss section : \n");
	dump_section(&File,GetPESectionPtr(&File,".bss"));
	//maped_data=MapPEFile(&File);

	printf("\n\ncheck relocs : \n");
	dump_reloc(&File);

	

	WriteTPOFile(&File		,target_file);

	/*
	if(do_compress)
	{
		FILE			*orig,*comp;
		unsigned char	*file_data,*comp_data;
		unsigned int	filesz,compsz;
		
		orig=fopen(target_file,"rb");
		fseek(orig,0,SEEK_END);
		filesz=ftell(orig);
		fseek(orig,0,SEEK_SET);
		file_data	=	calloc(filesz,1);
		fread	(file_data,filesz,1,orig);
		fclose	(orig);
		
		comp_data					=	calloc(filesz,1);
		compsz						=	filesz;
		compress2					(comp_data, &compsz, file_data, filesz,compress_level);

		//strcat						(target_file,".z");
		comp					=fopen(target_file,"wb");
		fwrite					("ZCMP" ,4,1,comp);
		fwrite					(&filesz,4,1,comp);
		fwrite					(&compsz,4,1,comp);
		fwrite					(comp_data,compsz,1,comp);
		fclose					(comp);
	}
	*/


end:	
	
return 0;
}