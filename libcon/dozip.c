#define LIBC_API C_EXPORT
#include "../../base/std_base.h"
#include "../../base/std_def.h"
#include "../../base/std_mem.h"
#include "../../base/mem_base.h"
#include "../../base/std_str.h"

#include "include/strs.h"
#include "include/fsio.h"

#include "zlib.h"
#include "minizip-master/zip.h"
#include "minizip-master/ioapi_mem.h"

zlib_filefunc_def	my_def = { 0xFF };
ourmemory_t			mem = { 0xFF };

OS_API_C_FUNC(int) do_zip(const char *fileName, const char **files, size_t nFiles,struct string *zipData)
{
	zipFile		myzip;
	zip_fileinfo infos;

	mem.grow = 1;

	fill_memory_filefunc (&my_def, &mem);
	myzip		=	zipOpen2(fileName, 0, PTR_NULL, &my_def);

	while (nFiles--)
	{
		mem_ptr data;
		size_t	size;
		if (get_file(files[nFiles], &data, &size)>0)
		{
			zipOpenNewFileInZip(myzip, files[nFiles], PTR_NULL, PTR_NULL, 0, PTR_NULL, 0, "", Z_DEFLATED, 1);
			zipWriteInFileInZip	(myzip, data, size);
			zipCloseFileInZip	(myzip);
			free_c				(data);
		}
	}
	zipClose(myzip, "Nodix");

	zipData->str = mem.base;
	zipData->len = mem.size;
	zipData->size = mem.limit;
	
}