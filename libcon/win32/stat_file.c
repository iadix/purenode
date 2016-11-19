//copyright iadix 2016
#define LIBC_API C_EXPORT


#include "../base/std_def.h"
#include "../base/std_mem.h"
#include "../base/mem_base.h"
#include "../base/std_str.h"
#include "strs.h"
#include "fsio.h"

#include <sys_include.h>
#include <time.h>
#include <direct.h>
#include <stdio.h>
#include <io.h>



#include <shlwapi.h>
#include "shlobj.h"

char path_sep='\\';
struct string log_file_name = { PTR_INVALID };
struct string home_path = { PTR_INVALID };
struct string exe_path = { PTR_INVALID };
unsigned int running = 1;
struct tm tmtime = { 0xCD };
struct thread
{
	thread_func_ptr		func;
	mem_zone_ref		params;
	unsigned int		status;
	unsigned int		tree_area_id;
	unsigned int		mem_area_id;
	DWORD				h;
};


struct thread threads[16] = { PTR_INVALID };


OS_API_C_FUNC(int) set_mem_exe(mem_zone_ref_ptr zone)
{
	unsigned int	old;
	mem_ptr				ptr;
	mem_size			size;

	ptr = uint_to_mem(mem_to_uint(get_zone_ptr(zone, 0))&(~0xFFF));
	size = (get_zone_size(zone)&(~0xFFF)) + 4096*2;
	return VirtualProtect(get_zone_ptr(zone, 0), get_zone_size(zone), PAGE_EXECUTE_READWRITE, &old);
}

OS_API_C_FUNC(int) stat_file(const char *path)
{
	struct string t = { 0 };
	int ret;

	ret = PathFileExists(path) ? 0 : -1;
	if ((ret!=0) && (exe_path.len > 0))
	{
		clone_string(&t, &exe_path);
		cat_cstring_p(&t, path);
		ret = PathFileExists(t.str) ? 0 : -1;
		free_string(&t);
	}
	return ret;
}

OS_API_C_FUNC(int) del_dir(const char *path)
{
	return RemoveDirectory(path);
}
OS_API_C_FUNC(int) create_dir(const char *path)
{
	return CreateDirectory(path, NULL);
}
#define TICKS_PER_SECOND 10000000
#define EPOCH_DIFFERENCE 11644473600LL

void UnixTimeToFileTime(time_t t, LPFILETIME pft)
{
	// Note that LONGLONG is a 64-bit value
	LONGLONG ll;

	ll = Int32x32To64(t, 10000000) + 116444736000000000;
	pft->dwLowDateTime = (DWORD)ll;
	pft->dwHighDateTime = ll >> 32;
}

ctime_t FileTime_to_POSIX(FILETIME ft)
{
	struct big64 t;
	uint64_t ti;

	t.m.v[0] = ft.dwLowDateTime;
	t.m.v[1] = ft.dwHighDateTime;
	ti = muldiv64(t.m.v64 - 116444736000000000, 1, 10000000);
	return (ti );
}
OS_API_C_FUNC(int) set_ftime(const char *path,ctime_t time)
{
	int ret;
	HANDLE hFile;
	FILETIME ft;
	if ((hFile = CreateFile(path, FILE_WRITE_ATTRIBUTES, 0, 0, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, 0)) == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	UnixTimeToFileTime(time, &ft);

	ret = SetFileTime(hFile, &ft, &ft, &ft);
	CloseHandle(hFile);
	return ret;
}
OS_API_C_FUNC(int) get_ftime(const char *path, ctime_t *time)
{
	int ret;
	HANDLE hFile;
	FILETIME ft;
	if ((hFile = CreateFile(path, FILE_READ_ATTRIBUTES, 0, 0, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, 0)) == INVALID_HANDLE_VALUE)
		return 0;

	ret = GetFileTime(hFile, &ft, NULL, NULL);
	CloseHandle(hFile);
	
	if (ret)
		*time = FileTime_to_POSIX(ft);

	return ret;
}
OS_API_C_FUNC(size_t) file_size(const char *path)
{
	size_t size;
	HANDLE h;
	if ((h = CreateFile(path, FILE_WRITE_ATTRIBUTES, 0, 0, OPEN_EXISTING, 0, 0)) == INVALID_HANDLE_VALUE)
		return 0;

	size = GetFileSize(h, NULL);
	CloseHandle(h);

	return size;
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



OS_API_C_FUNC(int) get_file(const char *path, unsigned char **data, size_t *data_len)
{
	HANDLE hFile;
	size_t len;

	if ((hFile = CreateFile(path, FILE_READ_DATA|FILE_READ_ATTRIBUTES, 0, 0, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, 0)) == INVALID_HANDLE_VALUE)
	{
		struct string t;
		clone_string		(&t, &exe_path);
		cat_cstring_p		(&t, path);
		hFile = CreateFile	(t.str, FILE_READ_DATA|FILE_READ_ATTRIBUTES, 0, 0, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, 0);
		free_string(&t);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			*data_len = 0;
			return -1;
		}
	}
	
	(*data_len) = GetFileSize(hFile, NULL);

	if ((*data_len)>0)
	{
		(*data) = malloc_c((*data_len) + 1);
		if ((*data) != PTR_NULL)
		{
			SetFilePointer	(hFile, 0, 0, FILE_BEGIN);
			ReadFile		(hFile, (*data), (*data_len), &len, PTR_NULL);
			(*data)[*data_len] = 0;
		}
		else
			len = 0;
	}
	else
		len = 0;
	CloseHandle	(hFile);

	return (int)len;

	/*
	ret	=	fopen_s	(&f,path,"rb");
	if(f==NULL)
	{
		struct string t;
		clone_string(&t, &exe_path);
		cat_cstring_p(&t, path);
		ret = fopen_s(&f, t.str, "rb");
		free_string(&t);
		if (f == NULL)
		{
			*data_len = 0;
			return -1;
		}
	}
	fseek(f,0,SEEK_END);
	(*data_len) = ftell(f);
	rewind(f);
	if((*data_len)>0)
	{
		(*data)		= malloc_c((*data_len)+1);
		if ((*data) != PTR_NULL)
		{
			len = fread((*data), *data_len, 1, f);
			(*data)[*data_len] = 0;
		}
		else
			len = 0;
	}
	fclose(f);
	return (int)len;
	*/

}

OS_API_C_FUNC(int) get_hash_idx(const char *path, size_t idx, hash_t hash)
{

	HANDLE hFile;
	size_t len;

	if ((hFile = CreateFile(path, FILE_READ_ATTRIBUTES | FILE_READ_DATA, 0, 0, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, 0)) == INVALID_HANDLE_VALUE)
		return 0;

	len = GetFileSize(hFile, NULL);

	if ((idx * 32 + 32) <= len)
	{
		SetFilePointer	(hFile, idx*sizeof(hash_t), 0, FILE_BEGIN);
		ReadFile		(hFile, hash,  sizeof(hash_t), &len, PTR_NULL);
	}
	else
		len = 0;
	
	CloseHandle(hFile);

	return (int)len;


}

OS_API_C_FUNC(int) put_file(const char *path, void *data, size_t data_len)
{
	HANDLE		hFile;
	size_t		len;

	if ((hFile = CreateFile(path, FILE_WRITE_ATTRIBUTES | FILE_WRITE_DATA, 0, 0, CREATE_NEW, FILE_FLAG_BACKUP_SEMANTICS, 0)) == INVALID_HANDLE_VALUE)
		return 0;

	if (data_len > 0)
		WriteFile(hFile,data,data_len,&len,PTR_NULL);
	else
		len = 1;

	CloseHandle(hFile);
	return (len>0) ? 1 : 0;

}
OS_API_C_FUNC(int) append_file(const char *path, const void *data, size_t data_len)
{
	HANDLE		hFile;
	size_t		len;


	if ((hFile = CreateFile(path, FILE_APPEND_DATA, 0, 0, OPEN_ALWAYS, FILE_FLAG_BACKUP_SEMANTICS, 0)) == INVALID_HANDLE_VALUE)
		return 0;

	if (data_len > 0)
		WriteFile(hFile, data, data_len, &len, PTR_NULL);
	else
		len = 1;

	CloseHandle(hFile);
	
	return len;

	/*
	ret = fopen_s(&f, path, "ab+");
	if (f == NULL)return 0;
	fseek(f, 0, SEEK_END);
	len = fwrite(data, data_len, 1, f);
	fclose(f);
	return 1;
	*/

}

OS_API_C_FUNC(int) truncate_file(const char *path, size_t ofset, const void *data, size_t data_len)
{
	HANDLE		hFile;
	size_t		len;

	if ((ofset == 0) && (data_len == 0))
	{
		del_file(path);
		return 1;
	}

	if ((hFile = CreateFile(path, FILE_APPEND_DATA, 0, 0, OPEN_ALWAYS, FILE_FLAG_BACKUP_SEMANTICS, 0)) == INVALID_HANDLE_VALUE)
		return 0;

	if (SetFilePointer(hFile, ofset, 0, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
	{
		CloseHandle(hFile);
		return 0;
	}

	if ((data != PTR_NULL) && (data_len > 0))
	{
		WriteFile		(hFile, data, data_len, &len, PTR_NULL);
	}
	else
	{
		SetEndOfFile(hFile);
		len = 1;
	}

	CloseHandle(hFile);


	return 1;

}

OS_API_C_FUNC(ctime_t)	 get_time_c()
{
	SYSTEMTIME st;
	FILETIME   ft;
	GetSystemTime				(&st);
	SystemTimeToFileTime		(&st, &ft);
	return FileTime_to_POSIX	(ft);
}
OS_API_C_FUNC(int) get_home_dir(struct string *path)
{
	char szPath[MAX_PATH];
	if (SUCCEEDED(SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, 0, szPath)))
	{
		// Append product-specific path
		make_string(path, szPath);
		return 1;
	}
	return 0;
}
OS_API_C_FUNC(int) set_exe_path()
{
	char path[512];
	get_cwd(path, 512);
	make_string(&exe_path, path);

	return 1;
}


OS_API_C_FUNC(int) set_home_path(const char *name)
{
	get_home_dir (&home_path);
	cat_cstring_p(&home_path, name);
	create_dir	 (home_path.str);
	set_cwd		 (home_path.str);
	return 1;

}
OS_API_C_FUNC(int) daemonize(const char *name)
{
	set_home_path(name);
	init_string (&log_file_name);
	make_string	(&log_file_name,name);
	cat_cstring	(&log_file_name,".log");
	return 1;
}



void init_threads()
{
	memset_c(threads, 0, sizeof(threads));

}
unsigned int new_thread(unsigned int h)
{
	unsigned int	n;
	n = 0;
	while (n<16)
	{
		if (compare_z_exchange_c(&threads[n].h,h))
			return n;

		n++;
	}
	return 0xFFFFFFFF;
}

unsigned int get_current_thread(unsigned int h)
{
	int n=0;

	while (n < 16)
	{
		if (h == threads[n].h)
			return n;
		n++;
	}
	return 0xFFFFFFFF;

}


OS_API_C_FUNC(int) set_tree_mem_area_id(unsigned int area_id)
{
	DWORD  h;
	unsigned int cur;
	h = GetCurrentThreadId();
	cur = get_current_thread(h);
	if (cur == 0xFFFFFFFF)
		cur = new_thread(h);

	threads[cur].tree_area_id = area_id;
	return 1;
}

OS_API_C_FUNC(int) set_mem_area_id(unsigned int area_id)
{
	DWORD  h;
	unsigned int cur;
	h = GetCurrentThreadId();
	cur = get_current_thread(h);
	if (cur == 0xFFFFFFFF)
		cur = new_thread(h);
	threads[cur].mem_area_id = area_id;
	return 1;
}
OS_API_C_FUNC(unsigned int) get_tree_mem_area_id()
{
	DWORD  h;
	unsigned int cur;
	h = GetCurrentThreadId();
	cur = get_current_thread(h);
	if (cur == 0xFFFFFFFF)
		return cur;

	return threads[cur].tree_area_id;
}
OS_API_C_FUNC(unsigned int) get_mem_area_id()
{
	DWORD  h;
	unsigned int cur;
	h = GetCurrentThreadId();
	cur = get_current_thread(h);
	if (cur == 0xFFFFFFFF)
		return cur;

	return threads[cur].mem_area_id;
}

DWORD WINAPI thread_start(void *p)
{
	thread_func_ptr		func;
	struct thread	    *thread;
	int ret;

	thread			= (struct thread *)p;
	thread->h		= GetCurrentThreadId();
	func			= thread->func;

	init_default_mem_area(4 * 1024 * 1024);
	ret = func			 (&thread->params, &thread->status);
	free_mem_area		 (0);
	
	return ret;
}

unsigned int next_ttid=1;


OS_API_C_FUNC(int) background_func(thread_func_ptr func,mem_zone_ref_ptr params)
{
	unsigned int			cur;

	DWORD					threadid;
	HANDLE					newThread;

	cur = new_thread(next_ttid++);

	copy_zone_ref(&threads[cur].params, params);
	threads[cur].func = func;
	threads[cur].status = 0;

	newThread	= CreateThread(NULL, 4096, thread_start, &threads[cur], 0, &threadid);

	while (threads[cur].status == 0)
	{
		SleepEx(1, 1);
	}

	release_zone_ref(&threads[cur].params);
		
	return 1;
}

OS_API_C_FUNC(void) console_print(const char *msg)
{
	HANDLE OUTPUT_HANDLE;
	size_t wrote;
	/* OutputDebugString(msg); */

	OUTPUT_HANDLE = GetStdHandle(STD_OUTPUT_HANDLE);
	WriteConsole(OUTPUT_HANDLE, msg, strlen_c(msg), &wrote, NULL);

}
OS_API_C_FUNC(void	*)kernel_memory_map_c(unsigned int size)
{
	return HeapAlloc(GetProcessHeap(),0,size);
}
OS_API_C_FUNC(int)kernel_memory_free_c(mem_ptr ptr)
{
	return HeapFree(GetProcessHeap(),0,ptr);
}
 unsigned int 	 get_system_time_c				()
{
	return 0;
}


 OS_API_C_FUNC(int) get_cwd(char *path,size_t len)
 {
	 return GetCurrentDirectory(len,path);
 }


 OS_API_C_FUNC(int) set_cwd(const char *path)
 {
	 return SetCurrentDirectory(path);
 }

 OS_API_C_FUNC(int) log_output(const char *data)
 {
	console_print(data);
	if (log_file_name.str != PTR_NULL)
		append_file(log_file_name.str, data, strlen_c(data));
	 return 1;
 }

 OS_API_C_FUNC(int) rm_dir(const char *dir)
 {
	 char			mdir[512];
	 struct string	dir_list = { PTR_NULL };
	 const char		*ptr, *optr;		
	 unsigned int	dir_list_len;
	 size_t			cur, nfiles;

	 if ((nfiles = get_sub_files(dir, &dir_list)) > 0)
	 {
		 dir_list_len = dir_list.len;
		 optr = dir_list.str;
		 cur = 0;
		 while (cur < nfiles)
		 {
			 size_t			sz;
			 ptr = memchr_c(optr, 10, dir_list_len);
			 sz = mem_sub(optr, ptr);

			 strcpy_cs	(mdir, 512, dir);
			 strncat_c	(mdir, &path_sep, 1);
			 strncat_c	(mdir, optr, sz);
			 del_file	(mdir);
			 cur++;
			 optr = ptr + 1;
			 dir_list_len -= sz;
		 }
	 }
	 free_string(&dir_list);
	 return del_dir(dir);
 }
 int extractDate(const char * s){
	 unsigned int	y, m, d;
	 SYSTEMTIME st;
	 FILETIME ft;
	 struct tm t;

	 y = strtoul_c(s, PTR_NULL, 10);
	 m = strtoul_c(&s[5], PTR_NULL, 10);
	 d = strtoul_c(&s[8], PTR_NULL, 10);

	 st.wYear = y;
	 st.wMonth = m;
	 st.wDay = d;
	 st.wDayOfWeek = 0;
	 st.wHour = 0;
	 st.wMinute = 0;
	 st.wSecond = 0;
	 st.wMilliseconds = 0;
	 SystemTimeToFileTime(&st, &ft);
	 return FileTime_to_POSIX(ft);
	 /*
	 memset_c(&t, 0, sizeof(struct tm));
	t.tm_mday = d;
	t.tm_mon = m - 1;
	t.tm_year = y - 1900;
	t.tm_isdst = -1;
	 // normalize:
	 return mktime(&t);
	 */
 }
 OS_API_C_FUNC(unsigned int) parseDate(const char *date)
 {
	 int			n;
	 n		= strlen_c(date);
	 if (n < 10)return 0;
	
	 return extractDate(date);
 }
 OS_API_C_FUNC(unsigned int) isRunning()
 {
	 return running;
 }
 
 void init_exit()
 {
	 
 }

OS_API_C_FUNC(int) default_RNG(unsigned char *dest, size_t size) 
{
	  HCRYPTPROV prov;
	  if (!CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
		  return 0;
	  }

	  CryptGenRandom(prov, size, (BYTE *)dest);
	  CryptReleaseContext(prov, 0);
	  return 1;
}