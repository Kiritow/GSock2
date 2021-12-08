#pragma once

#include "gsock.h"

#ifdef GSOCK_DEBUG
#pragma message("GSock Debug mode compiled in")
#include <cstdio>
#define myliblog(fmt,...) printf("<GSock|%s> " fmt,__func__,##__VA_ARGS__)
#define myliblog_ex(cond,fmt,...) do{if(cond){myliblog(fmt,##__VA_ARGS__);}}while(0)
#else
#define myliblog(fmt,...)
#define myliblog_ex(cond,fmt,...)
#endif

#ifdef _WIN32
/* _WIN32_WINNT defines
Windows XP = 0x0501
Windows Server 2003 = 0x0502
Windows Vista, Windows Server 2008 = 0x0600
Windows 7 = 0x0601
Windows 8 = 0x0602
Windows 8.1 = 0x0603
Windows 10 = 0x0A00
*/

// Using Win10 by default
#define _WIN32_WINNT 0x0A00
#include <winsock2.h>
#include <ws2tcpip.h>
#ifdef _MSC_VER
#pragma comment(lib,"ws2_32.lib")
#endif

#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <cstring>  // strerror_r
#define closesocket close
using BYTE = unsigned char;
#define WSAGetLastError() errno

#endif

int socket_native_init();
std::string socket_native_lasterror();
int socket_set_nonblocking(int fd);
int socket_get_sendtime(int fd, int& sec, int& usec);
int socket_set_sendtime(int fd, int sec, int usec);
int socket_get_recvtime(int fd, int& sec, int& usec);
int socket_set_recvtime(int fd, int sec, int usec);

class basic_sock::_impl
{
public:
	int fd;
	bool nb, inited;
	int af_protocol, sock_type;

	_impl();
	~_impl();
	int create();
	int connect_v4(const char* ip, int port);
	int connect_v6(const char* ip, int port);
	int _create_and_connect(int af_protocol, const sockaddr* paddr, int szaddr);
};

struct NBConnectResult::_impl
{
	int sfd;
	struct sockaddr_in saddr;
	struct sockaddr_in6 saddr6;
	bool isv4;

	// 0: Not used.
	// 1: running
	// 2: finished, connected.
	// 3: finished, failed. 
	int status;

	gerrno errcode;

	void update();
};


struct NBSendResult::_impl
{
	int sfd;
	const char* ptr;
	int total;
	int done;

	// When work together with epoll at ET mode, 
	//   setting this flag can avoid infinite EAGAIN send loop. 
	//   (caused by buffer full or something else)
	bool stopAtEdge;

	// 0: Not started.
	// 1: Data is being sent
	// 2: Data sent without error.
	// 3: Error occurs.
	int status;

	gerrno errcode;

	void update();
};

struct NBRecvResult::_impl
{
	int sfd;
	char* ptr;
	int maxsz;
	int done;

	// When work together with epoll at ET mode, setting this flag can avoid infinite EAGAIN recv loop.
	bool stopAtEdge;

	// 0: Not started.
	// 1: Data is being sent
	// 2: Data sent without error.
	// 3: Error occurs.
	int status;

	gerrno errcode;

	void update();
};

struct NBAcceptResult::_impl
{
	int sfd, sproto;
	sock c;

	bool stopAtEdge;

	// 0 Not started.
	// 1 Accepting
	// 2 Accept success.
	// 3 Accept failed.
	int status;
	gerrno errcode;

	void update();
};
