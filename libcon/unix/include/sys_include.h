#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <netdb.h>
#include <fcntl.h>

struct con
{
	struct host_def		host;
	struct string		error;
	struct string		lastLine;
	int					sock;   
	struct	sockaddr_in peer;
	size_t				last_rd;
	int					is_bc;
	fd_set				con_set;
	
};
struct stream_write
{
	volatile int			active;
	unsigned int			paid;
	long unsigned int		ThreadId;
	struct	stream_track	*my_track;
	struct con				*mycon;
	struct string			txid;
	time_t					start_time;
};

