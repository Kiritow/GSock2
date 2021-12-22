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

struct epoll::_impl
{
	int fd;
	int n;
	std::vector<epoll_event> vec;
	basic_sock not_used;

	_impl(int size) : vec(size)
	{
		fd = epoll_create(size);
	}

	~_impl()
	{
		if (fd >= 0)
		{
			close(fd);
		}
	}
};

epoll::epoll(int size) : _p(std::make_shared<_impl>(size))
{
	
}

int epoll::add(basic_sock& v, int event)
{
	struct epoll_event ev;
	ev.events = event;
	ev.data.ptr = v._vp.get();
	return epoll_ctl(_p->fd, EPOLL_CTL_ADD, v._vp->fd, &ev);
}

int epoll::mod(basic_sock& v, int event)
{
	struct epoll_event ev;
	ev.events = event;
	ev.data.ptr = v._vp.get();
	return epoll_ctl(_p->fd, EPOLL_CTL_MOD, v._vp->fd, &ev);
}

int epoll::del(basic_sock& v)
{
	return epoll_ctl(_p->fd, EPOLL_CTL_DEL, v._vp->fd, NULL);
}

int epoll::wait(int timeout)
{
	return _p->n = epoll_wait(_p->fd, _p->vec.data(), _p->vec.size(), timeout);
}

void epoll::handle(const std::function<void(basic_sock&, int)>& callback)
{
	if (_p->n > 0)
	{
		for (int i = 0; i < _p->n; i++)
		{
			callback(*((basic_sock*)(_p->vec[i].data.ptr)), (int)(_p->vec[i].events));
		}
	}
}

epoll::iterator_data::iterator_data(const basic_sock& bs) : s(bs), events(0) {}

epoll::base_iterator::base_iterator(std::vector<epoll_event>& vec, basic_sock& holder, int i, int n) :
	_data(holder), _vec(vec), _i(i), _n(n)
{
	if (_i < _n)
	{
		_data.s._vp.reset((basic_sock::_impl*)_vec[_i].data.ptr, [](basic_sock::_impl*) {});
		_data.events = _vec[_i].events;
	}
}

bool epoll::base_iterator::operator!=(const epoll::base_iterator& iter)
{
	return _i != iter._i;
}

void epoll::base_iterator::operator++()
{
	if (_i < _n)
	{
		++_i;
		if (_i < _n)
		{
			_data.s._vp.reset((basic_sock::_impl*)_vec[_i].data.ptr, [](basic_sock::_impl*) {});
			_data.events = _vec[_i].events;
		}
	}
}

epoll::iterator_data& epoll::base_iterator::operator * ()
{
	return _data;
}

epoll::iterator_data* epoll::base_iterator::operator -> ()
{
	return &_data;
}

epoll::base_iterator epoll::begin()
{
	return base_iterator(_p->vec, _p->not_used, 0, _p->n);
}

epoll::base_iterator epoll::end()
{
	return base_iterator(_p->vec, _p->not_used, _p->n, _p->n);
}

#endif
