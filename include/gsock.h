/** General Socket Wrapper
*   Created By Kiritow. (https://github.com/kiritow)
*   Licensed under MIT
*/

#ifndef _gsock_h
#define _gsock_h

#include <cstdint>
#include <string>
#include <vector>
#include <memory>

int InitGSock();

enum
{
	GSOCK_OK = 0,
	GSOCK_API_ERROR = -1, // API call failed, See Errno
	GSOCK_INVALID_SOCKET = -2, // Invalid socket
	GSOCK_ERROR_CREAT = -3, // Socket cannot be created, See Errno
	GSOCK_INVALID_IP = -4, // Invalid IP Address (IPv4,IPv6)
	GSOCK_UNKNOWN_PROTOCOL = -5, // Unknown Protocol
	GSOCK_ERROR_NTOP = -6, // inet_ntop failed.
	GSOCK_MISMATCH_PROTOCOL = -7, // Protocol mismatch.
	GSOCK_BAD_PROTOCOL = -8, // Bad protocol. 
	GSOCK_ERROR_SETMODE = -9, // Failed to set nonblocking
	GSOCK_MISMATCH_MODE = -10, // Example: calling blocking method on a non-blocking socket. 
};

// Internal Socket Call Errcode
// Values of all errors are positive number.
enum class gerrno
{
	OK = 0,
	UnknownError,
	WouldBlock,
	InProgress,
	Already,
	IsConnected,
	Interrupted,
};

// For Debug purpose.
int GetNativeErrCode();
gerrno TranslateNativeErrToGErr(int native_errcode);
std::string GetLastNativeError();

class basic_sock
{
public:
	basic_sock();
	operator bool() const;

	class _impl;
	std::shared_ptr<_impl> _vp;
};

class NBConnectResult
{
public:
	NBConnectResult();

	bool isFinished();
	// Wait until the connection is finished. (via while loop)
	void wait();
	bool isSuccess();
	// ErrCode is only usable when the connection is finished and failed.
	gerrno getErrCode();

	struct _impl;
	std::shared_ptr<_impl> _p;
};

class sock : public basic_sock
{
public:
	// Return:
	// GSOCK_OK: Connection Established. No Error.
	// GSOCK_API_ERROR: connect() call error. See errno.
	// GSOCK_INVALID_SOCKET: This socket has been connected before.
	// GSOCK_ERROR_CREAT
	// GSOCK_INVALID_IP
	// GSOCK_ERROR_SETMODE: Failed to set socket to non-blocking.
	int connect(const std::string& ip, int port);

	// Return:
	// return what send() and recv() call returns.
	int send(const void* Buffer, int Length);
	int recv(void* Buffer, int MaxToRecv);

	// Return:
	// GSOCK_OK
	// GSOCK_API_ERROR
	int getSendTime(int& _out_Second, int& _out_uSecond);
	int getRecvTime(int& _out_Second, int& _out_uSecond);
	int setSendTime(int Second, int Millisecond);
	int setRecvTime(int Second, int Millisecond);
	int setKeepalive(bool op);

	// Return:
	// 0: Success. No Error. IPv4
	// 1: Success. No Error. IPv6
	// GSOCK_API_ERROR: getlocalname() or getpeername() call error. See errno.
	// GSOCK_INVALID_SOCKET: Socket not created.
	int getPeer(std::string& ip, int& port);
	int getLocal(std::string& ip, int& port);
};

class NBSendResult
{
public:
	NBSendResult();

	void setStopAtEdge(bool flag);

	// Is the operation finished.
	bool isFinished();

	// Wait until all data is sent.
	void wait();

	// Is all data sent successfully.
	bool isSuccess();
	int getBytesDone();

	// If connection is closed while sending data,
	// the state changes to [Finished,Failed]. And errcode will be 0.
	gerrno getErrCode();

	struct _impl;
	std::shared_ptr<_impl> _p;
};

class NBRecvResult
{
public:
	NBRecvResult();

	void setStopAtEdge(bool flag);

	bool isFinished();
	void wait();
	bool isSuccess();
	int getBytesDone();

	// If connection is closed while receiving data,
	// the state changes to [Finished,Failed]. And errcode will be 0.
	// If setStopAtEdge(true) is called and there's no more data while isFinished() is called,
	// the state changes to [Finished,Failed]. And errcode will be gerrno::WouldBlock
	gerrno getErrCode();

	struct _impl;
	std::shared_ptr<_impl> _p;
};

class nbsock : public sock
{
public:
	nbsock();
	NBConnectResult connect(const std::string& IPStr, int Port);
	NBSendResult send(const void* Buffer, int Length);
	NBRecvResult recv(void* Buffer, int MaxToRecv);
};

class NBAcceptResult
{
public:
	NBAcceptResult();

	void stopAtEdge(bool flag);

	bool isFinished();
	bool isSuccess();

	sock get();

	gerrno getErrCode();

	struct _impl;
	std::shared_ptr<_impl> _sp;
};

class serversock : public basic_sock
{
public:
	// use_family:
	// 0: Auto (Undecided now) (default)
	// 1: IPv4 (If family cannot be automatically decided, then IPv4 will be the default option)
	// 2: IPv6
	serversock(int use_family = 0);

	// Notice that bind() should be called before setNonblocking()
	// Return:
	// GSOCK_OK: Bind Succeed. No Error.
	// GSOCK_API_ERROR: bind() call error. See errno.
	// GSOCK_INVALID_SOCKET: This socket has been created before.
	// GSOCK_ERROR_CREAT
	int bind(int port);
	int bind(const std::string& ip, int port);

	// Return:
	// GSOCK_OK
	// GSOCK_ERROR_CREAT
	// GSOCK_API_ERROR: setsockopt() call error.
	int setReuse();

	// Notice that listen() should be called before setNonblocking()
	// Return:
	// GSOCK_OK
	// GSOCK_API_ERROR: listen() call error.
	// GSOCK_INVALID_SOCKET
	int listen(int backlog);

	// Return:
	// GSOCK_OK: Accept Succeed. No Error. _out_s holds the new socket.
	// GSOCK_API_ERROR: accept() call error. See errno.
	// GSOCK_INVALID_SOCKET: _out_s is not an empty socket, which should not be passed in.
	int accept(sock&);

	struct _impl;
	std::shared_ptr<_impl> _p;
};

class nbserversock : public serversock
{
public:
	// Notice that bind() and listen() should be called before setNonBlocking()
	NBAcceptResult accept();
};

class udpsock : public basic_sock
{
public:
	// use_family:
	// 0: Auto (Undecided now) (default)
	// 1: IPv4 (If family cannot be automatically decided, then IPv4 will be the default option)
	// 2: IPv6
	udpsock(int use_family = 0);

	// Use udp socket as tcp socket. (but of course it is not).
	// connect call just copy the target socket data to kernel. See connect() for more info.
	// Return:
	// GSOCK_OK: data copied.
	// GSOCK_API_ERROR: connect() call error.
	// GSOCK_INVALID_IP
	// GSOCK_MISMATCH_PROTOCOL
	// GSOCK_INVALID_SOCKET
	// GSOCK_ERROR_CREAT
	int connect(const std::string& ip, int port);

	// Must be called in broadcast mode before any broadcasting.
	// Return:
	// GSOCK_OK
	// GSOCK_MISMATCH_PROTOCOL
	// GSOCK_INVALID_SOCKET
	// GSOCK_ERROR_CREAT
	int set_broadcast();

	// Explict bind() call is only need when you have to receive data.
	// Return:
	// GSOCK_OK
	// GSOCK_MISMATCH_PROTOCOL
	// GSOCK_INVALID_SOCKET
	// GSOCK_ERROR_CREAT
	// GSOCK_BAD_PROTOCOL: broadcast is not supported. (ipv6)
	int bind(int port);
	int bind(const std::string& ip, int port);

	// Return:
	// ret>=0: sendto() returns
	// GSOCK_API_ERROR(-1): sendto() call error.
	// GSOCK_INVALID_IP
	// GSOCK_MISMATCH_PROTOCOL
	// GSOCK_INVALID_SOCKET
	// GSOCK_ERROR_CREAT
	int sendto(const std::string& ip, int port, const void* buffer, int length);
	
	// Return:
	// Besides all returns of sendto(...), adding the following:
	// GSOCK_BAD_PROTOCOL: broadcast is not supported.
	int broadcast(int port, const void* buffer, int length);

	// Must call bind() before calling recvfrom().
	// Return:
	// ret>=0: recvfrom() returns
	// GSOCK_API_ERROR(-1): recvfrom() call error.
	// GSOCK_ERROR_NTOP
	// GSOCK_UNKNOWN_PROTOCOL
	// GSOCK_MISMATCH_PROTOCOL
	// GSOCK_INVALID_SOCKET
	// GSOCK_ERROR_CREAT
	int recvfrom(std::string& fromIP, int& fromPort, void* buffer, int bufferLength);

	// send() and recv() should only be called after connect(). Or it will fail.
	// Return:
	// ret>=0: send(), recv() returns.
	// GSOCK_API_ERROR(-1): send(), recv() call error.
	// GSOCK_INVALID_SOCKET: socket not created, and connect() has not been called yet.
	int send(const void* buffer, int length);
	int recv(void* buffer, int bufferLength);

	struct _impl;
	std::shared_ptr<_impl> _p;
};

/// Select
class selector
{
public:
	selector();

	void clear();

	// Socket should remain valid during selector lifetime.
	void listenRead(const basic_sock&);
	void listenWrite(const basic_sock&);
	void listenError(const basic_sock&);

	int wait_for(int second, int ms = 0);
	int wait();

	bool isReadable(const basic_sock&);
	bool isWritable(const basic_sock&);
	bool isError(const basic_sock&);

	struct _impl;
	std::shared_ptr<_impl> _pp;
};

#ifdef WIN32 // Windows: IOCP. Coming soon...

#else // Linux: epoll
#include <sys/epoll.h>
#include <functional>

class epoll
{
public:
	epoll(int MaxListen);
	// EPOLLIN, EPOLLOUT, ...
	// Use EPOLLET to set Edge Trigger Mode
	int add(vsock& v, int event);
	int mod(vsock& v, int event);
	int del(vsock& v);

	// >0: Event counts.
	// =0: Timeout.
	// <0: Error.
	// Set timeout to -1 for infinity waiting.
	// Call handle() to handle events
	int wait(int timeout);

	// callback: void event_handler(basic_sock& s,int event)
	void handle(const std::function<void(vsock&, int)>& callback);

	~epoll();
private:
	std::vector<struct epoll_event> _evec;
	int _n;
	int _fd;
};
#endif // End of Platform specific

/// Net Tools

// Return:
// >=0: Number of fetched results from getaddrinfo() call.
// -1: getaddrinfo() call failed.
int DNSResolve(const std::string& HostName, std::vector<std::string>& _out_IPStrVec);

// A wrapper of the vector version of DNSResolve. 
// _out_IPStr will be assigned with the first result in vector.
// Return:
// 0: Success.
// -1: getaddrinfo() call failed.
// -2: Failed to resolve. (No results in vector)
int DNSResolve(const std::string& HostName, std::string& _out_IPStr);

#endif // _gsock_h