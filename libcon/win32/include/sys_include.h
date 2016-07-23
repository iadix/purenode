#include <direct.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

struct con
{
	struct host_def		host;
	struct string		error;
	struct string		lastLine;
	SOCKET				sock;    
	struct	sockaddr_in peer;
	size_t				last_rd;
	fd_set				con_set;
};


struct stream_write
{
	volatile int			active;
	unsigned int			paid;
	DWORD					ThreadId;
	struct	stream_track	*my_track;
	struct con				*mycon;
	struct string			txid;
	time_t					start_time;
};
