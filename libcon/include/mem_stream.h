#ifndef LIBC_API
#define LIBC_API C_IMPORT
#endif

typedef struct
{
	mem_zone_ref		data;
	mem_size			current_ptr;
	mem_size			buf_ofs;
}mem_stream;

typedef struct
{
	mem_zone_const_ref		data;
	mem_size				current_ptr;
}const_mem_stream;


LIBC_API void			C_API_FUNC	mem_stream_init(mem_stream *stream, mem_zone_ref *stream_zone, mem_size buffer_ofset);
LIBC_API int			C_API_FUNC	mem_stream_decomp(mem_stream *stream, unsigned int comp_size, unsigned int decomp_size);
LIBC_API unsigned char	C_API_FUNC	mem_stream_read_8(mem_stream *stream);
LIBC_API unsigned char	C_API_FUNC	mem_stream_peek_8(mem_stream *stream);
LIBC_API unsigned short	C_API_FUNC	mem_stream_read_16(mem_stream *stream);
LIBC_API unsigned int	C_API_FUNC	mem_stream_read_32(mem_stream *stream);
LIBC_API unsigned int	C_API_FUNC	mem_stream_peek_32(mem_stream *stream);
LIBC_API size_t			C_API_FUNC	mem_stream_read(mem_stream *stream, char *data, size_t len);
LIBC_API size_t			C_API_FUNC	mem_stream_skip(mem_stream *stream, unsigned int len);
LIBC_API size_t			C_API_FUNC	mem_stream_skip_to(mem_stream *stream, size_t position);
LIBC_API size_t			C_API_FUNC	mem_stream_write(mem_stream *stream, char *data, size_t len);
LIBC_API void			C_API_FUNC	mem_stream_close(mem_stream *stream);

