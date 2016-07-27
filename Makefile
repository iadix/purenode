CONSRC=libcon/base/utf.c libcon/base/string.c libcon/base/mem_base.c libcon/unix/stat_file.c libcon/unix/connect.c libcon/strs.c libcon/mem_stream.c libcon/tpo_mod.c libcon/exp.c libcon/zlibexp.c
XMLSRC=libcon/expat/xmlparse/xmlparse.c libcon/expat/xmltok/xmltok.c libcon/expat/xmltok/xmlrole.c
ZLIBSRC=libcon/zlib-1.2.8/zutil.c libcon/zlib-1.2.8/uncompr.c libcon/zlib-1.2.8/inftrees.c libcon/zlib-1.2.8/compress.c libcon/zlib-1.2.8/infback.c libcon/zlib-1.2.8/trees.c libcon/zlib-1.2.8/inflate.c libcon/zlib-1.2.8/crc32.c libcon/zlib-1.2.8/inffast.c libcon/zlib-1.2.8/adler32.c libcon/zlib-1.2.8/deflate.c
BASESRC=libbase/http.c libbase/main.c libbase/tree.c libbase/md5.c libbase/sha256.c libbase/strbuffer.c libbase/upnp.c
CFLAG=-m32

default: export/libcon.so export/launcher
	echo 'done'

export/launcher: launcher/main.c export/libcon.so
	gcc $(CFLAGS) -Lexport -lcon -Ilibcon -Ilibcon/include -Ilibbase/include launcher/main.c -o export/launcher

export/libiadixcoin.so:export/libbase.so export/libcon.so purenode/main.c
	gcc $(CFLAGS) -Lexport -lcon -lbase -Ilibcon -Ilibcon/include -Ilibbase/include -Ilibcon/zlib-1.2.8 purenode/main.c --shared -o export/libiadixcoin.so

export/libblock_adx.so:block_adx/main.c block_adx/block.c block_adx/scrypt.c export/libprotocol_adx.so export/libbase.so export/libcon.so
	gcc $(CFLAGS) -Lexport -lcon -lbase -lprotocol_adx  -Ilibcon -Ilibcon/include -Ilibbase/include block_adx/main.c block_adx/block.c block_adx/scrypt.c --shared -o export/libblock_adx.so

export/libprotocol_adx.so:protocol_adx/main.c protocol_adx/protocol.c export/libbase.so export/libcon.so
	gcc $(CFLAGS) -Lexport -lbase -lcon -Ilibcon -Ilibcon/include -Ilibbase/include protocol_adx/main.c protocol_adx/protocol.c --shared -o export/libprotocol_adx.so

export/libbase.so:libbaseimpl/funcs.c
	gcc $(CFLAGS) -Ilibcon -Ilibcon/include -Ilibbase/include  libbaseimpl/funcs.c --shared -o export/libbase.so

export/libcon.so: $(CONSRC) $(XMLSRC) $(ZLIBSRC)
	nasm -f elf32 libcon/tpo.asm -o tpo.o
	nasm -f elf32 libcon/runtime.asm -o runtime.o
	gcc -g -Ilibcon -Ilibcon/include -Ilibcon/unix/include -Ilibcon/expat/xmlparse -Ilibcon/expat/xmltok runtime.o tpo.o $(CONSRC) $(XMLSRC) $(ZLIBSRC) -DIMP_API= --shared -o export/libcon.so

clean:
	rm -f export/libcon.so export/libprotocol_adx.so export/libblock_adx.so export/libiadixcoin.so export/launcher
