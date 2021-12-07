#include "includes.h"

#ifndef _WIN32

int socket_set_nonblocking(int fd)
{
	int flag = fcntl(fd, F_GETFL, 0);
	if (flag < 0) return -1;
	flag |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flag) < 0) return -1;
	return 0;
}

int socket_get_sendtime(int fd, int& sec, int& usec)
{
	struct timeval outtime;
	socklen_t _not_used_t = sizeof(outtime);
	int ret = getsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char*)&outtime, &_not_used_t);
	if (ret < 0) return ret;
	sec = outtime.tv_sec;
	usec = outtime.tv_usec;
	return 0;
}

int socket_set_sendtime(int fd, int sec, int usec)
{
	struct timeval outtime;
	outtime.tv_sec = sec;
	outtime.tv_usec = usec;
	return setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&outtime, sizeof(outtime));
}

int socket_get_recvtime(int fd, int& sec, int& usec)
{
	struct timeval outtime;
	socklen_t _not_used_t = sizeof(outtime);
	int ret = getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char*)&outtime, &_not_used_t);
	if (ret < 0) return ret;
	sec = outtime.tv_sec;
	usec = outtime.tv_usec;
	return 0;
}

int socket_set_recvtime(int fd, int sec, int usec)
{
	struct timeval outtime;
	outtime.tv_sec = sec;
	outtime.tv_usec = usec;
	return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&outtime, sizeof(outtime));
}

int socket_native_init()
{
	return 0;
}

std::string socket_native_lasterror()
{
	char buff[1024] = { 0 };
	return strerror_r(errno, buff, 1024);
}

#include <functional>

epoll::epoll(int MaxListen) : _evec(MaxListen)
{
	_fd = epoll_create(MaxListen); // this parameter is useless.
}
epoll::~epoll()
{
	close(_fd);
}
int epoll::add(basic_sock& v, int event)
{
	struct epoll_event ev;
	ev.events = event;
	ev.data.ptr = &v;
	return epoll_ctl(_fd, EPOLL_CTL_ADD, v._vp->fd, &ev);
}
int epoll::mod(basic_sock& v, int event)
{
	struct epoll_event ev;
	ev.events = event;
	ev.data.ptr = &v;
	return epoll_ctl(_fd, EPOLL_CTL_MOD, v._vp->fd, &ev);
}
int epoll::del(basic_sock& v)
{
	return epoll_ctl(_fd, EPOLL_CTL_DEL, v._vp->fd, NULL);
}
int epoll::wait(int timeout)
{
	return _n = epoll_wait(_fd, _evec.data(), _evec.size(), timeout);
}
void epoll::handle(const std::function<void(basic_sock&, int)>& callback)
{
	if (_n > 0)
	{
		for (int i = 0; i < _n; i++)
		{
			callback(*((basic_sock*)(_evec[i].data.ptr)), (int)(_evec[i].events));
		}
	}
}

#endif
