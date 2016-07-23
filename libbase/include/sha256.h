
typedef struct
{
	unsigned int total[2];          /*!< number of bytes processed  */
	unsigned int state[8];          /*!< intermediate digest state  */
	unsigned char buffer[64];   /*!< data block being processed */
	int is224;                  /*!< 0 => SHA-256, else SHA-224 */
}
mbedtls_sha256_context;

#ifndef LIBBASE_API
#define LIBBASE_API C_IMPORT
#endif


LIBBASE_API void C_API_FUNC mbedtls_sha256_init(mbedtls_sha256_context *ctx);
LIBBASE_API void C_API_FUNC mbedtls_sha256_starts(mbedtls_sha256_context *ctx, int is224);
LIBBASE_API void C_API_FUNC mbedtls_sha256_update(mbedtls_sha256_context *ctx, const unsigned char *input, size_t ilen);
LIBBASE_API void C_API_FUNC mbedtls_sha256_free(mbedtls_sha256_context *ctx);
LIBBASE_API void C_API_FUNC mbedtls_sha256_finish(mbedtls_sha256_context *ctx, unsigned char output[32]);
LIBBASE_API void C_API_FUNC mbedtls_sha256(const unsigned char *input, size_t ilen, unsigned char output[32], int is224);