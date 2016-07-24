CONSRC=libcon/base/utf.c libcon/base/string.c libcon/base/mem_base.c libcon/unix/stat_file.c libcon/unix/connect.c libcon/strs.c libcon/mem_stream.c libcon/tpo_mod.c libcon/exp.c libcon/zlibexp.c
XMLSRC=libcon/expat/xmlparse/xmlparse.c libcon/expat/xmltok/xmltok.c libcon/expat/xmltok/xmlrole.c
ZLIBSRC=libcon/zlib-1.2.8/zutil.c libcon/zlib-1.2.8/uncompr.c libcon/zlib-1.2.8/inftrees.c libcon/zlib-1.2.8/compress.c libcon/zlib-1.2.8/infback.c libcon/zlib-1.2.8/trees.c libcon/zlib-1.2.8/inflate.c libcon/zlib-1.2.8/crc32.c libcon/zlib-1.2.8/inffast.c libcon/zlib-1.2.8/adler32.c libcon/zlib-1.2.8/deflate.c

default: export/libcon.so export/launcher
	echo 'done'

export/launcher:
	gcc -Lexport/ -lcon -Ilibcon -Ilibcon/include -Ilibase/include launcher/main.c -o export/launcher.exe

export/libcon.dll: $(CONSRC) $(XMLSRC) $(ZLIBSRC)
	nasm -f elf32 -DPREFIX libcon/tpo.asm -o tpo.o
	nasm -f elf32 -DPREFIX libcon/runtime.asm -o runtime.o
	gcc -Ilibcon -Ilibcon/include -Ilibcon/unix/include -Ilibcon/expat/xmlparse -Ilibcon/expat/xmltok runtime.o tpo.o $(CONSRC) $(XMLSRC) $(ZLIBSRC) -DIMP_API= --shared -o export/libcon.so
