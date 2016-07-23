/* Read one byte from stream, convert to unsigned char, then int, and
   return. return EOF on end of file. This corresponds to the
   behaviour of fgetc(). */
typedef int (*get_func)(void *data);

typedef int64_t json_int_t;

typedef struct {
    //char *value;
	//mem_zone_ref	value_ref;
	char			value_ptr[1024];
    size_t length;   /* bytes used */
    size_t size;     /* bytes allocated */
} strbuffer_t;

typedef struct
{
    const char *data;
    size_t len;
    size_t pos;
} buffer_data_t;

typedef struct {
    get_func get;
    void *data;
    char buffer[5];
    size_t buffer_pos;
    int state;
    int line;
    int column, last_column;
    size_t position;
} stream_t;


typedef struct {
    stream_t	stream;
    strbuffer_t saved_text;
	char		value_buffer[1024];
    int			token;
    union {
        char		*string;
        json_int_t	integer;
        double		real;
    } value;
} lex_t;


int strbuffer_init(strbuffer_t *strbuff);
void strbuffer_close(strbuffer_t *strbuff);

void strbuffer_clear(strbuffer_t *strbuff);

const char *strbuffer_value(const strbuffer_t *strbuff);

/* Steal the value and close the strbuffer */
char *strbuffer_steal_value(strbuffer_t *strbuff);

int strbuffer_append(strbuffer_t *strbuff, const char *string);
int strbuffer_append_byte(strbuffer_t *strbuff, char byte);
int strbuffer_append_bytes(strbuffer_t *strbuff, const char *data, size_t size);

char strbuffer_pop(strbuffer_t *strbuff);

int  lex_init		(lex_t *lex,  void *data);
void lex_close		(lex_t *lex);
int  lex_scan		(lex_t *lex);
extern int  parse_value	(lex_t *lex,mem_zone_ref_ptr out);



