#define LIBC_API C_EXPORT
#include <time.h>
#include <direct.h>
#include <sys/stat.h>
#include <stdio.h>
#include "../base/std_def.h"
#include "../base/std_mem.h"
#include "../base/mem_base.h"
#include "../base/std_str.h"
#include "strs.h"
#include "fsio.h"

#include <windows.h>

struct string log_file_name = { PTR_NULL };

OS_API_C_FUNC(int) set_mem_exe(mem_zone_ref_ptr zone)
{
	unsigned int	old;
	mem_ptr				ptr;
	mem_size			size;
	int					ret;

	ptr = uint_to_mem(mem_to_uint(get_zone_ptr(zone, 0))&(~0xFFF));
	size = (get_zone_size(zone)&(~0xFFF)) + 4096*2;
	return VirtualProtect(get_zone_ptr(zone, 0), get_zone_size(zone), PAGE_EXECUTE_READWRITE, &old);
}

OS_API_C_FUNC(int) stat_file(const char *path)
{
	struct _stat	buf;
	return	_stat(path,&buf);
}
OS_API_C_FUNC(int) create_dir(const char *path)
{
	return CreateDirectory(path, NULL);
}
OS_API_C_FUNC(int) set_ftime(const char *path,ctime_t time)
{
	int ret;
	HANDLE hFile;
	FILETIME ft;
	if ((hFile = CreateFile(path, GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0)) == INVALID_HANDLE_VALUE)
	{
		return 0;
	}
	ft.dwLowDateTime	= (time&0xFFFFFFFF);
	ft.dwHighDateTime	= (time>>32);

	ret = SetFileTime(hFile, &ft, NULL, NULL);
	CloseHandle(hFile);
	return ret;
}

OS_API_C_FUNC(size_t) file_size(const char *path)
{
	OFSTRUCT of;
	size_t size;
	HANDLE h;
	if ((h = OpenFile(path, &of, 0)) == INVALID_HANDLE_VALUE)
		return 0;

	size = GetFileSize(h, NULL);
	CloseHandle(h);

	return size;
}

OS_API_C_FUNC(int) get_ftime(const char *path, ctime_t *time)
{
	int ret;
	OFSTRUCT of;
	HANDLE hFile;
	FILETIME ft;
	if ((hFile = OpenFile(path, &of,0)) == INVALID_HANDLE_VALUE)
		return 0;

	ret = GetFileTime(hFile, &ft, NULL, NULL);
	CloseHandle(hFile);

	if (ret)
		*time = (ft.dwHighDateTime << 32) | (ft.dwLowDateTime);

	return ret;
}
OS_API_C_FUNC(int) del_file(const char *path)
{
	return DeleteFile(path);
}

OS_API_C_FUNC(int) move_file(const char *ipath,const char *opath)
{
	return MoveFile(ipath,opath);
}
OS_API_C_FUNC(int) get_sub_dirs(const char *path, struct string *dir_list)
{
	WIN32_FIND_DATA ffd;
	char			toto[128];
	int				ret=0;
	HANDLE hFind = INVALID_HANDLE_VALUE;

	strcpy_cs	 (toto,128,path);
	strcat_cs	 (toto,128,"\\*");

    hFind = FindFirstFile(toto, &ffd);
   if (INVALID_HANDLE_VALUE == hFind) 
   {
      return ret;
   } 
   
   // List all the files in the directory with some info about them.
   do
   {
      if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
      {
		  if (ffd.cFileName[0] == '.')continue;
		  
		  cat_cstring (dir_list,ffd.cFileName);
		  cat_cstring (dir_list,"\n");
		  ret++;
	  }
   }
   while (FindNextFile(hFind, &ffd) != 0);

   FindClose(hFind);
   return ret;
}
OS_API_C_FUNC(int) get_sub_files(const char *path, struct string *file_list)
{
	WIN32_FIND_DATA ffd;
	char			toto[128];
	int				ret = 0;
	HANDLE hFind = INVALID_HANDLE_VALUE;

	strcpy_cs(toto, 128, path);
	strcat_cs(toto, 128, "\\*");

	hFind = FindFirstFile(toto, &ffd);
	if (INVALID_HANDLE_VALUE == hFind)
	{
		return ret;
	}

	// List all the files in the directory with some info about them.
	do
	{
		if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
		{
			cat_cstring(file_list, ffd.cFileName);
			cat_cstring(file_list, "\n");
			ret++;
		}
	} while (FindNextFile(hFind, &ffd) != 0);

	FindClose(hFind);
	return ret;
}



OS_API_C_FUNC(int) put_file(const char *path, void *data, size_t data_len)
{
	FILE		*f;
	size_t		len;
	int			ret;
	ret	=	fopen_s	(&f,path,"wb");
	if(f==NULL)return 0;
	if (data_len > 0)
		len = fwrite(data, data_len, 1, f);
	else
		len = 1;
	fclose(f);
	return (len>0)?1:0;

}
OS_API_C_FUNC(int) append_file(const char *path, void *data, size_t data_len)
{
	FILE		*f;
	size_t		len;
	int			ret;
	ret = fopen_s(&f, path, "ab+");
	if (f == NULL)return 0;
	fseek(f, 0, SEEK_END);
	len = fwrite(data, data_len, 1, f);
	fclose(f);
	return 1;

}
OS_API_C_FUNC(int) get_hash_idx(const char *path, size_t idx, hash_t hash)
{
	FILE		*f;
	size_t		len = 0;
	int			ret;

	ret = fopen_s(&f, path, "rb");
	if (f == NULL){ return -1; }
	fseek(f, 0, SEEK_END);
	len = ftell(f);
	if ((idx * 32 + 32) <= len)
	{
		fseek(f, idx*sizeof(hash_t), SEEK_SET);
		len = fread(hash, sizeof(hash_t), 1, f);
	}
	else
		len = 0;

	fclose(f);
	return len;
}
OS_API_C_FUNC(int) get_file(const char *path, unsigned char **data, size_t *data_len)
{
	FILE		*f;
	size_t		len=0;
	int			ret;
	ret	=	fopen_s	(&f,path,"rb");
	if(f==NULL){*data_len=0;return -1;}
	fseek(f,0,SEEK_END);
	(*data_len) = ftell(f);
	rewind(f);
	if((*data_len)>0)
	{
		(*data)		= malloc_c((*data_len)+1);
		len			= fread((*data),*data_len,1,f);
		(*data)[*data_len]=0;
	}
	

	fclose(f);


	return (int)len;

}
OS_API_C_FUNC(ctime_t)	 get_time_c()
{
	return time(0);
}

OS_API_C_FUNC(int) daemonize(const char *name)
{
	init_string (&log_file_name);
	make_string	(&log_file_name,name);
	cat_cstring	(&log_file_name,".log");
	return 0;
}

OS_API_C_FUNC(void) console_print(const char *msg)
{
	printf(msg);

}
OS_API_C_FUNC(void	*)kernel_memory_map_c(unsigned int size)
{
	return HeapAlloc(GetProcessHeap(),0,size);
}

 unsigned int 	 get_system_time_c				()
{
	return 0;
}

 OS_API_C_FUNC(int) log_output(const char *data)
 {
	console_print(data);
	if (log_file_name.str != PTR_NULL)
		append_file(log_file_name.str, data, strlen_c(data));
	 return 1;
 }

