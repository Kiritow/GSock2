/** General Socket Wrapper
*   Created By Kiritow. (https://github.com/kiritow)
*   Licensed under MIT
*/

/** See VERSION for version information */

#include "includes.h"

#include <cstring> /// memset
#include <string>
#include <stdexcept>
#include <vector>

int InitGSock()
{
	myliblog("sockaddr %d sockaddr_in %d sockaddr_in6 %d\n", sizeof(sockaddr), sizeof(sockaddr_in), sizeof(sockaddr_in6));
	return socket_native_init();
}

static inline const char* get_family_name(int family)
{
	switch (family)
	{
	case AF_INET:
		return "AF_INET";
	case AF_INET6:
		return "AF_INET6";
	default:
		return "Unknown";
	}
}

int GetNativeErrCode()
{
#ifdef _WIN32
	return WSAGetLastError();
#else
	return errno;
#endif
}

gerrno TranslateNativeErrToGErr(int native_errcode)
{
	switch (native_errcode)
	{
#ifdef _WIN32
	case WSAEWOULDBLOCK:
		return gerrno::WouldBlock;
	case WSAEINPROGRESS:
		return gerrno::InProgress;
	case WSAEALREADY:
		return gerrno::Already;
	case WSAEISCONN:
		return gerrno::IsConnected;
	case WSAEINTR:
		return gerrno::Interrupted;
#else
	case EWOULDBLOCK: // EAGAIN == EWOULDBLOCK
		return gerrno::WouldBlock;
	case EINPROGRESS:
		return gerrno::InProgress;
	case EALREADY:
		return gerrno::Already;
	case EISCONN:
		return gerrno::IsConnected;
	case EINTR:
		return gerrno::Interrupted;
#endif
	default:
		myliblog("Unknown Error Code: %d\n", native_errcode);
		return gerrno::UnknownError;
	}
}

std::string GetLastNativeError()
{
	return socket_native_lasterror();
}


basic_sock::_impl::_impl() : fd(-1), nb(false), inited(false), af_protocol(0), sock_type(SOCK_STREAM) {}
basic_sock::_impl::~_impl()
{
	if (fd >= 0)
	{
		closesocket(fd);
	}
}

int basic_sock::_impl::create()
{
	if (inited) return GSOCK_INVALID_SOCKET;
	inited = true;
		
	fd = socket(af_protocol, sock_type, 0);
	if (fd < 0)
	{
		myliblog("socket() returns %d. WSAGetLastError: %d\n", fd, WSAGetLastError());
		return GSOCK_ERROR_CREAT;
	}

	if (nb && socket_set_nonblocking(fd) < 0)
	{
		myliblog("Socket@%p failed to set nonblocking flag\n", this);
		closesocket(fd);
		return GSOCK_ERROR_SETMODE;
	}

	myliblog("Socket@%p created: fd: %d, protocol: %s, nonblocking: %d\n", 
		this, fd,
		af_protocol == AF_INET ? "IPv4" : "IPv6",
		nb ? "yes" : "no");

	return 0;
}

int basic_sock::_impl::connect_v4(const char* ip, int port)
{
	struct sockaddr_in saddr;

	memset(&saddr, 0, sizeof(saddr));
	if (inet_pton(AF_INET, ip, &(saddr.sin_addr.s_addr)) != 1)
	{
		return GSOCK_INVALID_IP;
	}
	saddr.sin_port = htons(port);
	saddr.sin_family = AF_INET;

	return _create_and_connect(AF_INET, (sockaddr*)&saddr, sizeof(saddr));
}

int basic_sock::_impl::connect_v6(const char* ip, int port)
{
	struct sockaddr_in6 saddr;

	memset(&saddr, 0, sizeof(saddr));
	if (inet_pton(AF_INET6, ip, &(saddr.sin6_addr)) != 1)
	{
		return GSOCK_INVALID_IP;
	}
	saddr.sin6_port = htons(port);
	saddr.sin6_family = AF_INET6;

	return _create_and_connect(AF_INET6, (sockaddr*)&saddr, sizeof(saddr));
}

int basic_sock::_impl::_create_and_connect(int protocol, const sockaddr* paddr, int szaddr)
{
	af_protocol = protocol;
	if (int ret = create(); ret < 0) return ret;
	return ::connect(fd, paddr, szaddr);
}

basic_sock::basic_sock() : _vp(new _impl) {}

basic_sock::operator bool() const
{
	return _vp->inited && _vp->fd >= 0;
}

bool basic_sock::operator==(const basic_sock& s) const
{
	return _vp == s._vp;
}

int sock::connect(const std::string& ip, int port)
{
	myliblog("sock::connect() %p\n", this);

	if (ip.find(":") != std::string::npos)
	{
		// Maybe IPv6
		return _vp->connect_v6(ip.c_str(), port);
	}
	else
	{
		// Maybe IPv4
		return _vp->connect_v4(ip.c_str(), port);
	}
}

int sock::send(const void* Buffer, int Length)
{
	return ::send(_vp->fd, (const char*)Buffer, Length, 0);
}

int sock::recv(void* Buffer, int MaxToRecv)
{
	return ::recv(_vp->fd, (char*)Buffer, MaxToRecv, 0);
}

int sock::getSendTime(int& sec, int& usec)
{
	return socket_get_sendtime(_vp->fd, sec, usec);
}

int sock::getRecvTime(int& sec, int& usec)
{
	return socket_get_recvtime(_vp->fd, sec, usec);
}

int sock::setSendTime(int sec, int usec)
{
	return socket_set_sendtime(_vp->fd, sec, usec);
}

int sock::setRecvTime(int sec, int usec)
{
	return socket_set_recvtime(_vp->fd, sec, usec);
}

int sock::setKeepalive(bool op)
{
	int option = op ? 1 : 0;
	return setsockopt(_vp->fd, SOL_SOCKET, SO_KEEPALIVE, (const char*)&option, sizeof(option));
}

static int socket_getname_call(int sfd, std::string& ip, int& port, decltype(getsockname) scall)
{
	union
	{
		sockaddr saddr;
		sockaddr_in saddr4;
		sockaddr_in6 saddr6;
	} pack;

	socklen_t saddrlen = sizeof(pack);
	memset(&pack, 0, saddrlen);

	int ret = scall(sfd, &pack.saddr, &saddrlen);

	if (ret < 0) return ret; //don't bother errno. stop here.

	char ip_buff[128] = { 0 };
	if (pack.saddr.sa_family == AF_INET)
	{
		struct sockaddr_in* paddr = &pack.saddr4;
		const char* pret = inet_ntop(AF_INET, &(paddr->sin_addr), ip_buff, 128);
		if (pret)
		{
			ip = std::string(ip_buff);
			port = ntohs(paddr->sin_port);
			return 0;
		}
		else
		{
			// inet_ntop call failed.
			return GSOCK_ERROR_NTOP;
		}
	}
	else if (pack.saddr.sa_family == AF_INET6)
	{
		struct sockaddr_in6* paddr = &pack.saddr6;
		const char* pret = inet_ntop(AF_INET6, &(paddr->sin6_addr), ip_buff, 128);
		if (pret)
		{
			ip = std::string(ip_buff);
			port = ntohs(paddr->sin6_port);
			return 1;
		}
		else
		{
			// inet_ntop call failed.
			return GSOCK_ERROR_NTOP;
		}
	}
	else
	{
		// protocol not supported.
		return GSOCK_UNKNOWN_PROTOCOL;
	}
}

int sock::getLocal(std::string& ip, int& port)
{
	if (!_vp->inited) return GSOCK_INVALID_SOCKET;
	return socket_getname_call(_vp->fd, ip, port, getsockname);
}

int sock::getPeer(std::string& ip, int& port)
{
	if (!_vp->inited) return GSOCK_INVALID_SOCKET;
	return socket_getname_call(_vp->fd, ip, port, getpeername);
}

struct serversock::_impl
{
public:
	static int create(serversock& ss)
	{
		if (ss._vp->af_protocol == 0)
		{
			ss._vp->af_protocol = AF_INET;
			myliblog("Protocol decided to %s in serversock %p\n", get_family_name(ss._vp->af_protocol), this);
		}

		return ss._vp->create();
	}

	static int ensure(serversock& ss)
	{
		if (ss._vp->inited) return ss ? 0 : GSOCK_INVALID_SOCKET;
		return create(ss);
	}
};

serversock::serversock(int use_family)
{
	if (use_family == 1)
	{
		_vp->af_protocol = AF_INET;
		myliblog("Protocol decided to %s in serversock %p\n", get_family_name(_pp->protocol), this);
	}
	else if (use_family == 2)
	{
		_vp->af_protocol = AF_INET6;
		myliblog("Protocol decided to %s in serversock %p\n", get_family_name(_pp->protocol), this);
	}
}

int serversock::bind(int port)
{
	myliblog("serversock::bind(%d) %p\n", port, this);
	if (int ret = serversock::_impl::ensure(*this); ret < 0) return ret;

	if (_vp->af_protocol == AF_INET)
	{
		sockaddr_in saddr;

		memset(&saddr, 0, sizeof(saddr));
		saddr.sin_addr.s_addr = INADDR_ANY;
		saddr.sin_port = htons(port);
		saddr.sin_family = AF_INET;
		return ::bind(_vp->fd, (sockaddr*)&saddr, sizeof(saddr));
	}
	else
	{
		sockaddr_in6 saddr;

		memset(&saddr, 0, sizeof(saddr));
		saddr.sin6_addr = in6addr_any;
		saddr.sin6_port = htons(port);
		saddr.sin6_family = AF_INET6;
		return ::bind(_vp->fd, (sockaddr*)&saddr, sizeof(saddr));
	}
}

int serversock::bind(const std::string& ip, int port)
{
	myliblog("serversock::bind(%s, %d) %p\n", ip.c_str(), port, this);
	if (int ret = serversock::_impl::ensure(*this); ret < 0) return ret;

	if (_vp->af_protocol == AF_INET)
	{
		sockaddr_in saddr;

		memset(&saddr, 0, sizeof(saddr));
		if (inet_pton(AF_INET, ip.c_str(), &(saddr.sin_addr.s_addr)) != 1)
		{
			return GSOCK_INVALID_IP;
		}
		saddr.sin_addr.s_addr = INADDR_ANY;
		saddr.sin_port = htons(port);
		saddr.sin_family = AF_INET;
		return ::bind(_vp->fd, (sockaddr*)&saddr, sizeof(saddr));
	}
	else
	{
		sockaddr_in6 saddr;

		memset(&saddr, 0, sizeof(saddr));
		if (inet_pton(AF_INET6, ip.c_str(), &(saddr.sin6_addr)) != 1)
		{
			return GSOCK_INVALID_IP;
		}
		saddr.sin6_port = htons(port);
		saddr.sin6_family = AF_INET6;
		return ::bind(_vp->fd, (sockaddr*)&saddr, sizeof(saddr));
	}
}

int serversock::setReuse()
{
	if (int ret = serversock::_impl::ensure(*this); ret < 0) return ret;
	socklen_t opt = 1;
	return setsockopt(_vp->fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
}

int serversock::listen(int backlog)
{
	if (int ret = serversock::_impl::ensure(*this); ret < 0) return ret;
	return ::listen(_vp->fd, backlog);
}

int serversock::accept(sock& outs)
{
	// failed if `outs` has been connected.
	if (!*this || outs) return GSOCK_INVALID_SOCKET;

	sock c; /// empty socket.

	sockaddr_in saddr;
	sockaddr_in6 saddr6;
	socklen_t saddrsz = (_vp->af_protocol == AF_INET) ? sizeof(saddr) : sizeof(saddr6);

	int ret;
	if (_vp->af_protocol == AF_INET)
	{
		ret = ::accept(_vp->fd, (sockaddr*)&(saddr), &saddrsz);
	}
	else
	{
		ret = ::accept(_vp->fd, (sockaddr*)&(saddr6), &saddrsz);
	}

	if (ret < 0)
	{
		/// accept() call failed.
		myliblog("accept() returns %d. WSAGetLastError: %d\n", ret, WSAGetLastError());
		return GSOCK_API_ERROR;
	}
	
	c._vp->inited = true;
	c._vp->fd = ret;

	myliblog("Socket opened: [%d] as sock::_vp %p by serversock::_vp: %p\n", c._vp->sfd, c._vp, _vp);
	
	outs = c;

	return 0;
}

NBAcceptResult nbserversock::accept()
{
	NBAcceptResult res;

	res._sp->sfd = _vp->fd;
	res._sp->sproto = _vp->af_protocol;
	res._sp->update();

	return res;
}

struct udpsock::_impl
{
	static int create(udpsock& s)
	{
		if (s._vp->af_protocol == 0)
		{
			s._vp->af_protocol = AF_INET;
			myliblog("Protocol decided to %s in serversock %p\n", get_family_name(s._vp->af_protocol), this);
		}

		return s._vp->create();
	}

	static int ensure(udpsock& s, int want_protocol)
	{
		if (s._vp->inited)
		{
			if (s)
			{
				if (want_protocol && s._vp->af_protocol != want_protocol) return GSOCK_MISMATCH_PROTOCOL;
				return 0;
			}

			return GSOCK_INVALID_SOCKET;
		}

		s._vp->af_protocol = want_protocol;
		return create(s);
	}
};

udpsock::udpsock(int use_family)
{
	_vp->sock_type = SOCK_DGRAM;

	if (use_family == 1)
	{
		_vp->af_protocol = AF_INET;
		myliblog("Protocol decided to %s in udpsock %p\n", get_family_name(_p->protocol), this);
	}
	else if (use_family == 2)
	{
		_vp->af_protocol = AF_INET6;
		myliblog("Protocol decided to %s in udpsock %p\n", get_family_name(_p->protocol), this);
	}
	else
	{
		_vp->af_protocol = 0;
	}
}

// Convert from ip to sockaddr
// Return:
// -1: inet_pton() call failed.
// 0: Success, IPv4
// 1: Success, IPv6
static int convert_ipv46(const std::string& ip, int port,
	struct sockaddr*& paddr, socklen_t& szaddr,
	struct sockaddr_in& addr, struct sockaddr_in6& addr6, int protocol)
{
	if (protocol == AF_INET6 || (!protocol && ip.find(":") != std::string::npos))
	{
		// Maybe IPv6
		memset(&addr6, 0, sizeof(addr6));
		if (inet_pton(AF_INET6, ip.c_str(), &(addr6.sin6_addr)) != 1)
		{
			return GSOCK_INVALID_IP;
		}
		addr6.sin6_port = htons(port);
		addr6.sin6_family = AF_INET6;

		paddr = (sockaddr*)&addr6;
		szaddr = sizeof(addr6);
		return 1;
	}
	else if (protocol == AF_INET || (!protocol && ip.find(":") == std::string::npos))
	{
		// Maybe IPv4
		memset(&addr, 0, sizeof(addr));
		if (inet_pton(AF_INET, ip.c_str(), &(addr.sin_addr)) != 1)
		{
			return GSOCK_INVALID_IP;
		}
		addr.sin_port = htons(port);
		addr.sin_family = AF_INET;

		paddr = (sockaddr*)&addr;
		szaddr = sizeof(addr);
		return 0;
	}
	else
	{
		return GSOCK_MISMATCH_PROTOCOL;
	}
}

// Convert from sockaddr to ip
// Return:
// -1: inet_ntop() call failed.
// 0: Success, IPv4
// 1: Success, IPv6
static int convertback_ipv46(const sockaddr* paddr, std::string& ip)
{
	char buff[128] = { 0 };
	if (paddr->sa_family == AF_INET)
	{
		if (inet_ntop(AF_INET, &(((const sockaddr_in*)paddr)->sin_addr), buff, 128) != NULL)
		{
			ip = std::string(buff);
			return 0;
		}
		return -1;
	}
	else if (paddr->sa_family == AF_INET6)
	{
		if (inet_ntop(AF_INET6, &(((const sockaddr_in6*)paddr)->sin6_addr), buff, 128) != NULL)
		{
			ip = std::string(buff);
			return 1;
		}
		return -1;
	}
	else return GSOCK_MISMATCH_PROTOCOL;
}

int udpsock::connect(const std::string& ip, int port)
{
	sockaddr_in saddr;
	sockaddr_in6 saddr6;
	sockaddr* paddr;
	socklen_t addrsz;

	int ret = convert_ipv46(ip, port, paddr, addrsz, saddr, saddr6, _vp->af_protocol);
	if (ret < 0) return ret;

	if (ret == 0)
	{
		ret = udpsock::_impl::ensure(*this, AF_INET);
	}
	else
	{
		ret = udpsock::_impl::ensure(*this, AF_INET6);
	}

	if (ret < 0)
	{
		return ret;
	}

	return ::connect(_vp->fd, (const sockaddr*)paddr, addrsz);
}

int udpsock::set_broadcast()
{
	if (int ret = udpsock::_impl::ensure(*this, 0); ret < 0) return ret;

	socklen_t opt = 1;
	return ::setsockopt(_vp->fd, SOL_SOCKET, SO_BROADCAST, (const char*)&opt, sizeof(opt));
}

int udpsock::bind(int port)
{
	if (int ret = udpsock::_impl::ensure(*this, 0); ret < 0) return ret;

	if (_vp->af_protocol == AF_INET)
	{
		sockaddr_in saddr;
		memset(&saddr, 0, sizeof(saddr));
		saddr.sin_family = AF_INET;
		saddr.sin_port = htons(port);
		saddr.sin_addr.s_addr = INADDR_ANY;

		return ::bind(_vp->fd, (const sockaddr*)&saddr, sizeof(saddr));
	}
	else
	{
		sockaddr_in6 saddr;
		memset(&saddr, 0, sizeof(saddr));
		saddr.sin6_family = AF_INET6;
		saddr.sin6_port = htons(port);
		saddr.sin6_addr = in6addr_any;

		return ::bind(_vp->fd, (const sockaddr*)&saddr, sizeof(saddr));
	}
}

int udpsock::bind(const std::string& ip, int port)
{
	if (int ret = udpsock::_impl::ensure(*this, 0); ret < 0) return ret;

	if (_vp->af_protocol == AF_INET)
	{
		sockaddr_in saddr;
		memset(&saddr, 0, sizeof(saddr));
		saddr.sin_family = AF_INET;
		saddr.sin_port = htons(port);
		if (inet_pton(AF_INET, ip.c_str(), &(saddr.sin_addr.s_addr)) != 1)
		{
			return GSOCK_INVALID_IP;
		}

		return ::bind(_vp->fd, (const sockaddr*)&saddr, sizeof(saddr));
	}
	else
	{
		sockaddr_in6 saddr;
		memset(&saddr, 0, sizeof(saddr));
		saddr.sin6_family = AF_INET6;
		saddr.sin6_port = htons(port);
		if (inet_pton(AF_INET6, ip.c_str(), &(saddr.sin6_addr)) != 1)
		{
			return GSOCK_INVALID_IP;
		}

		return ::bind(_vp->fd, (const sockaddr*)&saddr, sizeof(saddr));
	}
}

int udpsock::sendto(const std::string& ip, int port, const void* buffer, int length)
{
	sockaddr_in saddr;
	sockaddr_in6 saddr6;
	sockaddr* paddr;
	socklen_t addrsz;

	int ret = convert_ipv46(ip, port, paddr, addrsz, saddr, saddr6, _vp->af_protocol);
	if (ret < 0) return ret;

	ret = udpsock::_impl::ensure(*this, ret == 0 ? AF_INET : AF_INET6);
	if (ret < 0) return ret;

	return ::sendto(_vp->fd, (const char*)buffer, length, 0, (const sockaddr*)paddr, addrsz);
}

int udpsock::broadcast(int port, const void* buffer, int length)
{
	if (int ret = udpsock::_impl::ensure(*this, 0); ret < 0) return ret;

	if (_vp->af_protocol == AF_INET)
	{
		sockaddr_in saddr;
		memset(&saddr, 0, sizeof(saddr));
		saddr.sin_family = AF_INET;
		saddr.sin_port = htons(port);
		saddr.sin_addr.s_addr = INADDR_BROADCAST;
		return ::sendto(_vp->fd, (const char*)buffer, length, 0, (const sockaddr*)&saddr, sizeof(saddr));
	}
	else
	{
		myliblog("IPv6 does not support broadcast!\n");
		return GSOCK_BAD_PROTOCOL;
	}
}

int udpsock::recvfrom(std::string& ip, int& port, void* buffer, int bufferLength)
{
	if (int ret = udpsock::_impl::ensure(*this, 0); ret < 0) return ret;

	if (_vp->af_protocol == AF_INET)
	{
		sockaddr_in saddr;
		socklen_t saddrlen = sizeof(saddr);
		int ret = ::recvfrom(_vp->fd, (char*)buffer, bufferLength, 0, (sockaddr*)&saddr, &saddrlen);

		if (ret < 0) return ret;

		ret = convertback_ipv46((const sockaddr*)&saddr, ip);
		if (ret < 0) return ret;

		port = ntohs(saddr.sin_port);
		return 0;
	}
	else
	{
		sockaddr_in6 saddr;
		socklen_t saddrlen = sizeof(saddr);
		int ret = ::recvfrom(_vp->fd, (char*)buffer, bufferLength, 0, (sockaddr*)&saddr, &saddrlen);

		if (ret < 0) return ret;

		ret = convertback_ipv46((const sockaddr*)&saddr, ip);
		if (ret < 0) return ret;

		port = ntohs(saddr.sin6_port);
		return ret;
	}
}

int udpsock::send(const void* buffer, int length)
{
	if (*this)
	{
		return ::send(_vp->fd, (const char*)buffer, length, 0);
	}

	// if protocol is not decided, then socket is invalid. (Not Created)
	return GSOCK_INVALID_SOCKET;
}

int udpsock::recv(void* buffer, int length)
{
	if (*this)
	{
		return ::recv(_vp->fd, (char*)buffer, length, 0);
	}

	// if protocol is not decided, then socket is invalid. (Not Created)
	return GSOCK_INVALID_SOCKET;
}

// Select
struct selector::_impl
{
	fd_set readset, writeset, errorset;
	int readsz, writesz, errorsz;
};

selector::selector() : _pp(new _impl)
{
	clear();
}

void selector::clear()
{
	FD_ZERO(&_pp->readset);
	FD_ZERO(&_pp->writeset);
	FD_ZERO(&_pp->errorset);
	_pp->readsz = _pp->writesz = _pp->errorsz = 0;
}

void selector::listenRead(const basic_sock& v)
{
	if (v)
	{
		FD_SET(v._vp->fd, &_pp->readset);
		++_pp->readsz;
	}
}

void selector::listenWrite(const basic_sock& v)
{
	if (v)
	{
		FD_SET(v._vp->fd, &_pp->writeset);
		++_pp->writesz;
	}
}

void selector::listenError(const basic_sock& v)
{
	if (v)
	{
		FD_SET(v._vp->fd, &_pp->errorset);
		++_pp->errorsz;
	}
}

int selector::wait_for(int second, int ms)
{
	fd_set* pread = (_pp->readsz) ? (&_pp->readset) : NULL;
	fd_set* pwrite = (_pp->writesz) ? (&_pp->writeset) : NULL;
	fd_set* perr = (_pp->errorsz) ? (&_pp->errorset) : NULL;

	if (!(pread || pwrite || perr))
	{
		return 0;
	}

	struct timeval tval;
	tval.tv_sec = second;
	tval.tv_usec = ms;

	int nfds = 0;
	return ::select(nfds, pread, pwrite, perr, &tval);
}

int selector::wait()
{
	fd_set* pread = (_pp->readsz) ? (&_pp->readset) : NULL;
	fd_set* pwrite = (_pp->writesz) ? (&_pp->writeset) : NULL;
	fd_set* perr = (_pp->errorsz) ? (&_pp->errorset) : NULL;

	if (!(pread || pwrite || perr))
	{
		return 0;
	}

	int nfds = 0;
	return ::select(nfds, pread, pwrite, perr, NULL);
}

bool selector::isReadable(const basic_sock& v)
{
	return FD_ISSET(v._vp->fd, &_pp->readset);
}

bool selector::isWritable(const basic_sock& v)
{
	return FD_ISSET(v._vp->fd, &_pp->writeset);
}

bool selector::isError(const basic_sock& v)
{
	return FD_ISSET(v._vp->fd, &_pp->errorset);
}

int DNSResolve(const std::string& HostName, std::vector<std::string>& _out_IPStrVec)
{
	std::vector<std::string> vec;

	/// Use getaddrinfo instead
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	struct addrinfo* result = nullptr;

	int ret = getaddrinfo(HostName.c_str(), NULL, &hints, &result);
	if (ret != 0)
	{
		return GSOCK_API_ERROR;/// API Call Failed.
	}

	int cnt = 0;
	for (struct addrinfo* ptr = result; ptr != nullptr; ptr = ptr->ai_next)
	{
		cnt++;
		switch (ptr->ai_family)
		{
		case AF_INET:
		{
			sockaddr_in* paddr = (struct sockaddr_in*)(ptr->ai_addr);
			char ip_buff[64] = { 0 };
			const char* ptr = inet_ntop(AF_INET, &(paddr->sin_addr), ip_buff, 64);
			if (ptr != NULL)
			{
				vec.push_back(ptr);
			}
			break;
		}
		case AF_INET6:
		{
			sockaddr_in6* paddr = (struct sockaddr_in6*)(ptr->ai_addr);
			char ip_buff[128] = { 0 };
			const char* ptr = inet_ntop(AF_INET6, &(paddr->sin6_addr), ip_buff, 128);
			if (ptr != NULL)
			{
				vec.push_back(ptr);
			}
			break;
		}
		}// End of switch
	}

	freeaddrinfo(result);

	_out_IPStrVec = std::move(vec);

	// if(cnt!=(int)_out_IPStrVec.size()),
	// then (cnt-(int)_out_IPStrVec.size()) errors happend while calling inet_ntop().
	return cnt;
}

int DNSResolve(const std::string& HostName, std::string& _out_IPStr)
{
	std::vector<std::string> vec;
	int ret = DNSResolve(HostName, vec);
	if (ret < 0)
	{
		return -1;
	}
	if (vec.empty())
	{
		return -2;
	}
	_out_IPStr = vec[0];
	return 0;
}
