#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "../base/std_def.h"
#include "../base/std_mem.h"
#include "../base/mem_base.h"
#include "../base/std_str.h"
#include "strs.h"
#include "../base/tree.h"

#include <sys_include.h>
struct string log_file_name	={PTR_NULL};
FILE			 *log_file	=PTR_NULL;

int stat_file		(const char *path)
{
	struct  stat	fileStat;
	int				ret;

	ret = stat(path,&fileStat);
	if(ret<0)return ret;
	
	if(fileStat.st_mode & S_IXUSR)
	 	return	0;
	else
		return	1;
}


void log_message(const char *fmt,mem_zone_ref_ptr args)
{
	const char					*fmt_ptr;
	const char					*last_fmt_ptr;
	const char					*end_fmt_ptr;
	struct string				line={PTR_NULL};

	fmt_ptr		=fmt;
	last_fmt_ptr=fmt_ptr;
	end_fmt_ptr	=mem_add(fmt,strlen_c(fmt));

	make_string	(&line,"[");
	strcat_int	(&line,time(0));
	cat_cstring	(&line,"] ");

	while((*fmt_ptr)!=0)
	{
		if((*fmt_ptr)=='%')
		{
			int				n;
			char			pname[64];
			struct string	value={PTR_NULL};
			size_t			len;

			if(last_fmt_ptr!=fmt_ptr)
			{
				len			=	mem_sub (last_fmt_ptr,fmt_ptr);
				cat_ncstring (&line,last_fmt_ptr,(unsigned int)len);
			}
			
			fmt_ptr++;
			n=0;
			while(((*fmt_ptr)!='%')&&((*fmt_ptr)!=0)&&(n<63))
			{
				pname[n++]=(*(fmt_ptr++));
			}
			pname[n++]=0;
			fmt_ptr++;

			if(tree_manager_get_child_value_istr	(args,NODE_HASH(pname),&value,10))
			{
				cat_string							(&line,&value);
				free_string							(&value);
			}
			last_fmt_ptr		=	fmt_ptr;
		}
		fmt_ptr++;
	}

	if(last_fmt_ptr<end_fmt_ptr)
		cat_cstring		(&line,last_fmt_ptr);

	cat_cstring		(&line,"\n");

	if(log_file!=PTR_NULL)
	{
		fwrite(line.str,line.len,1,log_file);
		fflush(log_file);
	}

	free_string(&line);
}

int create_dir(const char *path)
{
	return mkdir(path,0775);
}
int get_sub_dirs(const char *path,struct string *dir_list)
{
	struct dirent *direntp;
	int ret=0;
    DIR *dirp;

	if ((dirp = opendir(path)) == NULL) 
	{
		return ret;
	}

	while ((direntp = readdir(dirp)) != NULL)
	{
		if(direntp->d_type!=DT_DIR)continue;
		if(strlen_c(direntp->d_name)>=3)
		{
			cat_cstring (dir_list,direntp->d_name);
			cat_cstring (dir_list,"\n");
			ret++;
		}
	}

   closedir(dirp);
   return ret;
}


int put_file(const char *path,void *data,size_t data_len)
{
	FILE		*f;
	size_t		len;
	
	f	=	fopen	(path,"wb");
	if(f==NULL)return 0;
	len	=	fwrite(data,data_len,1,f);
	fclose(f);
	return 1;

}

int get_file(const char *path,unsigned char **data,size_t *data_len)
{
	FILE		*f;
	size_t		len;

	f	=	fopen	(path,"rb");
	if(f==NULL)return -1;
	fseek(f,0,SEEK_END);
	(*data_len) = ftell(f);
	rewind(f);
	(*data)		= malloc_c((*data_len)+1);
	len			= fread((*data),*data_len,1,f);
	fclose(f);
	(*data)[*data_len]=0;
	return (int)len;

}

void	*kernel_memory_map_c(unsigned int size)
{
	return malloc(size);
}

 unsigned int 	 get_system_time_c				()
{
	return 0;
}


int daemonize(const char *name)
{
   pid_t pid, sid;
   mem_zone_ref log={PTR_NULL};
   
   // Fork off the parent process 
   pid = fork();
   if (pid < 0) {
       return -1;
   }
   // If we got a good PID, then we can exit the parent process. 
   if (pid > 0) {
		exit(EXIT_SUCCESS);
   }
   // Change the file mode mask 
   umask(0);       
   // Open any logs here 
   
   init_string (&log_file_name);
   make_string (&log_file_name,name);
   cat_cstring (&log_file_name,".log");

   log_file=fopen(log_file_name.str,"ab");
   if(log_file==PTR_NULL)
   {
	   printf("could not open log file \n");
	   return -1;
   } 
   
   // Create a new SID for the child process 
   
   sid = setsid();
   if (sid < 0) {
	   log_message("sid failure",PTR_NULL);
	   fclose(log_file);
       // Log any failures here 
       return -1;
   }
   
   
      
   // Change the current working directory 
   if ((chdir("./")) < 0) {
	   log_message("chdir failure",PTR_NULL);
	   fclose(log_file);
       return -1;
   }
   
   tree_manager_create_node("log",NODE_LOG_PARAMS,&log);
   tree_manager_set_child_value_i32(&log,"pid",pid);
   tree_manager_set_child_value_i32(&log,"sid",sid);
   log_message("process started %pid%, %sid%.",&log);
   release_zone_ref(&log);

   // Close out the standard file descriptors 
   /*
   close(STDIN_FILENO);
   close(STDOUT_FILENO);
   close(STDERR_FILENO);
   */

   return 0;
}

time_t get_time_c()
{
	return time(0);
}