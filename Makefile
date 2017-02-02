CONSRC=libcon/base/utf.c libcon/base/string.c libcon/base/mem_base.c libcon/unix/stat_file.c libcon/unix/connect.c libcon/strs.c libcon/mem_stream.c libcon/tpo_mod.c libcon/exp.c libcon/zlibexp.c
XMLSRC=libcon/expat/xmlparse/xmlparse.c libcon/expat/xmltok/xmltok.c libcon/expat/xmltok/xmlrole.c
ZLIBSRC=libcon/zlib-1.2.8/zutil.c libcon/zlib-1.2.8/uncompr.c libcon/zlib-1.2.8/inftrees.c libcon/zlib-1.2.8/compress.c libcon/zlib-1.2.8/infback.c libcon/zlib-1.2.8/trees.c libcon/zlib-1.2.8/inflate.c libcon/zlib-1.2.8/crc32.c libcon/zlib-1.2.8/inffast.c libcon/zlib-1.2.8/adler32.c libcon/zlib-1.2.8/deflate.c
CFLAGS=-m32 #-O2 -std=c99 -pedantic -D_DEFAULT_SOURCE

default: export/libcon.a export/launcher
	@echo 'done'

export/launcher: launcher/main.c export/libcon.a
	gcc $(CFLAGS) -lc -lm -pthread -Ilibcon  -Ilibcon/zlib-1.2.8/ -Ilibcon/include -Ilibbase/include launcher/main.c export/libcon.a -o export/launcher

export/raytrace: raytrace/main.c export/libcon.a
	gcc $(CFLAGS) -lc -lm -pthread -Ilibcon  -Ilibcon/zlib-1.2.8/ -Ilibcon/include -Ilibbase/include raytrace/main.c export/libcon.a -o export/raytrace

export/libiadixcoin.so:export/libbase.so export/libcon.so purenode/main.c
	gcc $(CFLAGS)  -Lexport -lcon -lblock_adx -lbase -Ilibcon  -Ilibcon/zlib-1.2.8/ -Ilibcon/include -Ilibbase/include -Ilibcon/zlib-1.2.8 purenode/main.c  -nodefaultlibs -nostdlib -Wl,--export-dynamic,-soname,libiadixcoin.so,-melf_i386 -shared -o export/libiadixcoin.so

export/libstake_pos2.so:export/libbase.so export/libcon.so stake_pos2/kernel.c
	gcc $(CFLAGS)  -Lexport -lcon -lbase -Ilibcon  -Ilibcon/zlib-1.2.8/ -lblock_adx -Ilibcon/include -Ilibbase/include -Ilibcon/zlib-1.2.8 stake_pos2/kernel.c -nodefaultlibs -nostdlib -Wl,--export-dynamic,-soname,libstake_pos2.so,-melf_i386 -shared -o export/libstake_pos2.so

export/libstake_pos3.so:export/libbase.so export/libcon.so stake_pos3/kernel.c
	gcc $(CFLAGS)  -Lexport -lcon -lbase -Ilibcon  -Ilibcon/zlib-1.2.8/ -lblock_adx -Ilibcon/include -Ilibbase/include -Ilibcon/zlib-1.2.8 stake_pos3/kernel.c  -nodefaultlibs -nostdlib -Wl,--export-dynamic,-soname,libstake_pos3.so,-melf_i386 -shared -o export/libstake_pos3.so

export/libblock_explorer.so:export/libblock_adx.so export/libbase.so export/libcon.so block_explorer/block_explorer.c
	gcc $(CFLAGS)  -Lexport -lcon -lbase -lblock_adx -Ilibcon  -Ilibcon/zlib-1.2.8/ -lblock_adx -Ilibcon/include -Ilibbase/include -Ilibcon/zlib-1.2.8 block_explorer/block_explorer.c  -nodefaultlibs -nostdlib -Wl,--export-dynamic,-soname,libstake_pos3.so,-melf_i386 -shared -o export/libblock_explorer.so

export/libblock_adx.so:block_adx/main.c block_adx/script.c block_adx/block.c block_adx/scrypt.c export/libprotocol_adx.so export/libbase.so export/libcon.so
	gcc $(CFLAGS)  -Lexport -lcon -lbase -lprotocol_adx  -Ilibcon/zlib-1.2.8/ -Ilibcon -Ilibcon/include -Ilibbase/include block_adx/main.c block_adx/block.c block_adx/script.c block_adx/scrypt.c -nodefaultlibs -nostdlib  -Wl,--export-dynamic,-soname,libblock_adx.so,-melf_i386 -shared -o export/libblock_adx.so

export/libprotocol_adx.so:protocol_adx/main.c protocol_adx/protocol.c export/libbase.so export/libcon.so
	gcc $(CFLAGS)  -Lexport -lcon -lbase -Ilibcon  -Ilibcon/zlib-1.2.8/ -Ilibcon/include -Ilibbase/include protocol_adx/main.c protocol_adx/protocol.c -nodefaultlibs -nostdlib -Wl,--export-dynamic,-soname,libprotocol_adx.so,-melf_i386 -shared -o export/libprotocol_adx.so

export/libbase.so:libbaseimpl/funcs.c
	gcc $(CFLAGS) -Ilibcon  -Ilibcon/zlib-1.2.8/ -Ilibcon/include -Ilibbase/include  libbaseimpl/funcs.c -shared -o export/libbase.so

modz:export/modz/protocol_adx.tpo export/modz/block_adx.tpo export/modz/iadixcoin.tpo export/modz/stake_pos3.tpo export/modz/block_explorer.tpo
	@echo "modz ok"

export/modz/block_explorer.tpo:export/mod_maker export/libblock_explorer.so
	export/mod_maker export/libblock_explorer.so ./export/modz
	mv export/modz/libblock_explorer.tpo export/modz/block_explorer.tpo

export/modz/stake_pos2.tpo:export/mod_maker export/libstake_pos2.so
	export/mod_maker export/libstake_pos2.so ./export/modz
	mv export/modz/libstake_pos2.tpo export/modz/stake_pos2.tpo

export/modz/stake_pos3.tpo:export/mod_maker export/libstake_pos3.so
	export/mod_maker export/libstake_pos3.so ./export/modz
	mv export/modz/libstake_pos3.tpo export/modz/stake_pos3.tpo

export/modz/iadixcoin.tpo:export/mod_maker export/libiadixcoin.so
	export/mod_maker export/libiadixcoin.so ./export/modz
	mv export/modz/libiadixcoin.tpo export/modz/iadixcoin.tpo

export/modz/block_adx.tpo:export/mod_maker export/libblock_adx.so
	export/mod_maker ./export/libblock_adx.so ./export/modz
	mv export/modz/libblock_adx.tpo export/modz/block_adx.tpo
	
export/modz/protocol_adx.tpo:export/mod_maker export/libprotocol_adx.so
	export/mod_maker ./export/libprotocol_adx.so ./export/modz
	mv export/modz/libprotocol_adx.tpo export/modz/protocol_adx.tpo

export/mod_maker:  export/libcon.so
	gcc -m32 -Lexport  -lpthread -Ilibcon -Ilibcon/zlib-1.2.8/ -Ilibcon/include mod_maker/coff.c mod_maker/main.c mod_maker/elf.c export/libcon.a -o export/mod_maker
	
export/libcon.a: $(CONSRC) $(XMLSRC) $(ZLIBSRC)
	nasm -f elf32 libcon/tpo.asm -o tpo.o
	nasm -f elf32 libcon/runtime.asm -o runtime.o
	gcc $(CFLAGS) -Ilibcon -Ilibcon/zlib-1.2.8/ -Ilibcon/include -Ilibcon/unix/include -Ilibcon/expat/xmlparse -Ilibcon/expat/xmltok $(CONSRC) $(XMLSRC) $(ZLIBSRC) -c
	ld *.o -shared -melf_i386 -soname libcon.so -o export/libcon.so
	ar -cvq export/libcon.a *.o

clean:
	rm -f export/libcon.a export/libcon.so export/launcher *.o

clean_mod:
	rm -f export/mod_maker export/libblock_explorer.so export/libprotocol_adx.so export/libblock_adx.so export/libiadixcoin.so export/libstake_pos3.so export/libstake_pos2.so export/modz/protocol_adx.tpo export/modz/block_adx.tpo export/modz/iadixcoin.tpo export/modz/stake_pos3.tpo  export/modz/stake_pos2.tpo export/modz/block_explorer.tpo

