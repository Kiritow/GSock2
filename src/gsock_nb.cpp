#include "includes.h"

void NBConnectResult::_impl::update()
{
	// Already finished.
	if (status > 1) return;

	int ret;
	if (isv4)
	{
		ret = connect(sfd, (sockaddr*)&saddr, sizeof(saddr));
	}
	else
	{
		ret = connect(sfd, (sockaddr*)&saddr6, sizeof(saddr6));
	}

	if (ret == 0)
	{
		status = 2;
	}
	else // ret == -1
	{
		gerrno err = TranslateNativeErrToGErr(GetNativeErrCode());
		errcode = err;

		if (err == gerrno::InProgress || err == gerrno::WouldBlock || err == gerrno::Already)
		{
			status = 1;
		}
		else if (err == gerrno::IsConnected)
		{
			status = 2;
		}
		else
		{
			status = 3;
		}
	}

	myliblog("NBConnectResult Status updated to %d\n", status);
}

NBConnectResult::NBConnectResult() : _p(new _impl)
{
	_p->status = 0;
}

bool NBConnectResult::isFinished()
{
	_p->update();
	return (_p->status > 1);
}

bool NBConnectResult::isSuccess()
{
	return (_p->status == 2);
}

gerrno NBConnectResult::getErrCode()
{
	return _p->errcode;
}

void NBConnectResult::wait()
{
	while (!isFinished());
}

void NBSendResult::_impl::update()
{
	if (status > 1) return;

	int ret = send(sfd, ptr + done, total - done, 0);
	if (ret > 0)
	{
		done += ret;
		if (done == total)
		{
			status = 2;
		}
		else
		{
			status = 1;
		}
	}
	else if (ret == 0)
	{
		status = 3;
		errcode = gerrno::OK;
	}
	else // ret == -1
	{
		gerrno err = TranslateNativeErrToGErr(GetNativeErrCode());
		errcode = err;

		if (err == gerrno::WouldBlock)
		{
			if (stopAtEdge)
			{
				status = 3;
			}
			else
			{
				status = 1;
			}
		}
		else
		{
			status = 3;
		}
	}

	myliblog("NBSendResult status updated to %d\n", status);
}

NBSendResult::NBSendResult() : _p(new _impl)
{
	_p->status = 0;
	_p->stopAtEdge = false;
}

void NBSendResult::setStopAtEdge(bool flag)
{
	_p->stopAtEdge = true;
}

bool NBSendResult::isFinished()
{
	_p->update();
	return (_p->status > 1);
}

void NBSendResult::wait()
{
	while (!isFinished());
}

bool NBSendResult::isSuccess()
{
	return (_p->status == 2);
}

int NBSendResult::getBytesDone()
{
	return _p->done;
}

gerrno NBSendResult::getErrCode()
{
	return _p->errcode;
}

void NBRecvResult::_impl::update()
{
	if (status > 1) return;

	int ret = recv(sfd, ptr + done, maxsz - done, 0);
	if (ret > 0)
	{
		done += ret;
		if (done == maxsz)
		{
			status = 2;
		}
		else
		{
			status = 1;
		}
	}
	else if (ret == 0)
	{
		status = 3;
		errcode = gerrno::OK;
	}
	else // ret == -1
	{
		gerrno err = TranslateNativeErrToGErr(GetNativeErrCode());
		errcode = err;

		if (err == gerrno::WouldBlock)
		{
			if (stopAtEdge)
			{
				status = 3;
			}
			else
			{
				status = 1;
			}
		}
		else
		{
			status = 3;
		}
	}

	myliblog("NBRecvResult status updated to %d\n", status);
}

NBRecvResult::NBRecvResult() : _p(new _impl)
{
	_p->status = 0;
	_p->stopAtEdge = false;
}

void NBRecvResult::setStopAtEdge(bool flag)
{
	_p->stopAtEdge = flag;
}

bool NBRecvResult::isFinished()
{
	_p->update();
	return (_p->status > 1);
}

void NBRecvResult::wait()
{
	while (!isFinished());
}

bool NBRecvResult::isSuccess()
{
	return (_p->status == 2);
}

int NBRecvResult::getBytesDone()
{
	return _p->done;
}

gerrno NBRecvResult::getErrCode()
{
	return _p->errcode;
}

NBConnectResult nbsock::connect(const std::string& ip, int port)
{
	NBConnectResult res;
	int ret = sock::connect(ip, port);

	if (ret == 0)
	{
		// Socket is connected immediately! Amazing!!
		res._p->status = 2;
	}
	else if (ret == -1)
	{
		res._p->status = 1;
	}
	else // ret is a GSock error
	{
		// Failed
		res._p->status = 3;
		res._p->errcode = (gerrno)ret;
	}
	return res;
}

nbsock::nbsock()
{
	_vp->nb = true;
}

NBSendResult nbsock::send(const void* Buffer, int Length)
{
	NBSendResult res;
	res._p->ptr = (const char*)Buffer;
	res._p->total = Length;
	res._p->done = 0;
	res._p->sfd = _vp->fd;

	res._p->update();
	return res;
}

NBRecvResult nbsock::recv(void* Buffer, int MaxToRecv)
{
	NBRecvResult res;
	res._p->ptr = (char*)Buffer;
	res._p->maxsz = MaxToRecv;
	res._p->done = 0;
	res._p->stopAtEdge = false;
	res._p->sfd = _vp->fd;

	res._p->update();
	return res;
}

void NBAcceptResult::_impl::update()
{
	if (status > 1) return;

	sockaddr_in saddr;
	sockaddr_in6 saddr6;
	socklen_t saddrsz = 0;

	int ret;
	if (sproto == AF_INET)
	{
		ret = accept(sfd, (sockaddr*)&saddr, &saddrsz);
	}
	else
	{
		ret = accept(sfd, (sockaddr*)&saddr6, &saddrsz);
	}

	if (ret >= 0)
	{
		c._vp->inited = true;
		c._vp->fd = ret;
		status = 2;
		return;
	}

	gerrno err = TranslateNativeErrToGErr(GetNativeErrCode());
	errcode = err;
	if (err == gerrno::InProgress || err == gerrno::Already)
	{
		status = 1;
	}
	else if (err == gerrno::WouldBlock)
	{
		status = stopAtEdge ? 3 : 1;
	}
	else
	{
		status = 3;
	}

	myliblog("NBAcceptResult status updated to %d\n", status);
}

NBAcceptResult::NBAcceptResult() : _sp(new _impl)
{
	_sp->status = 0;
	_sp->stopAtEdge = false;
}

void NBAcceptResult::stopAtEdge(bool flag)
{
	_sp->stopAtEdge = flag;
}

bool NBAcceptResult::isFinished()
{
	_sp->update();
	return (_sp->status > 1);
}

bool NBAcceptResult::isSuccess()
{
	return (_sp->status == 2);
}

sock NBAcceptResult::get()
{
	return _sp->c;
}

gerrno NBAcceptResult::getErrCode()
{
	return _sp->errcode;
}
