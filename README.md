Building instruction :


git clone https://github.com/iadix/purenode


cd purenode


Libcon and launcher:

	make 


Modules:

	make modz


Running:

	cd export
	./launcher (use /root/purenode)


No dependencies, all is included.

	purenode/export# ldd libcon.so 

        linux-gate.so.1 (0xf772d000)
        libm.so.6 => /lib/i386-linux-gnu/libm.so.6 (0xf7651000)
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf749a000)
        /lib/ld-linux.so.2 (0x565ed000)


	purenode/export# ldd launcher

        linux-gate.so.1 (0xf779a000)
        libcon.so => /mnt/freebox/purenode/export/libcon.so (0xf7713000)
        libm.so.6 => /lib/i386-linux-gnu/libm.so.6 (0xf76be000)
        libpthread.so.0 => /lib/i386-linux-gnu/libpthread.so.0 (0xf76a1000)
        libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xf74ea000)
        /lib/ld-linux.so.2 (0x565e5000)


Enjoy ! :-)
