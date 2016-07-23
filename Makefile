CONSRC=libcon/md5.c libcon/base/utf.c libcon/base/string.c libcon/base/strbuffer.c libcon/base/tree.c libcon/base/mem_base.c libcon/http.c libcon/unix/stat_file.c libcon/unix/connect.c libcon/upnp.c libcon/strs.c
XMLSRC=libcon/expat/xmlparse/xmlparse.c libcon/expat/xmltok/xmltok.c libcon/expat/xmltok/xmlrole.c
ZLIBSRC=libcon/zlib-1.2.8/zutil.c libcon/zlib-1.2.8/uncompr.c libcon/zlib-1.2.8/inftrees.c libcon/zlib-1.2.8/compress.c libcon/zlib-1.2.8/infback.c libcon/zlib-1.2.8/trees.c libcon/zlib-1.2.8/inflate.c libcon/zlib-1.2.8/crc32.c libcon/zlib-1.2.8/inffast.c libcon/zlib-1.2.8/adler32.c libcon/zlib-1.2.8/deflate.c

export/libcon.so: $(CONSRC) $(XMLSRC) $(ZLIBSRC)
	nasm -f elf32 libcon/base/acrc32.asm -o acrc32.o
	gcc -g -Ilibcon/include -Ilibcon/unix/include -Ilibcon/expat/xmlparse -Ilibcon/expat/xmltok acrc32.o $(CONSRC) $(XMLSRC) $(ZLIBSRC) -DIMP_API= --shared -o export/libcon.so

stratum: export/libcon.so
	gcc -g -Ilibcon/include  -Ilibcon/base/ -Ilibcon/unix/include -Lexport/ -lcon -DIMP_API= sync/site_api.c stratum/main.c -o export/stratum
