#include "includes.h"
#include <iostream>

#ifdef _WIN32
int socket_set_nonblocking(int fd)
{
	u_long mode = 1;
	return ioctlsocket(fd, FIONBIO, &mode) == 0 ? 0 : -1;
}

int socket_set_sendtime(int fd, int sec, int usec)
{
	int outtime = sec * 1000 + usec % 1000;
	return setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&outtime, sizeof(outtime));
}

int socket_get_sendtime(int fd, int& sec, int& usec)
{
	int result;
	socklen_t _not_used_t = sizeof(result);
	int ret = getsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char*)&result, &_not_used_t);
	if (ret < 0) return ret;
	sec = result / 1000;
	usec = result % 1000;
	return 0;
}

int socket_get_recvtime(int fd, int& sec, int& usec)
{
	int result;
	socklen_t _not_used_t = sizeof(result);
	int ret = getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char*)&result, &_not_used_t);
	if (ret < 0) return ret;
	sec = result / 1000;
	usec = result % 1000;
	return 0;
}

int socket_native_init()
{
	/// Windows Platform need WinSock2.DLL initialization.
	WORD wd;
	WSAData wdt;
	wd = MAKEWORD(2, 2);
	int ret = WSAStartup(wd, &wdt);

	myliblog("WSAStartup() Returns: %d\n", ret);

	if (ret < 0)
	{
		myliblog("WSAGetLastError: %d\n", WSAGetLastError());
		return -1;
	}

	return 0;
}

std::string socket_native_lasterror()
{
	DWORD dwError = GetLastError();
	if (dwError == 0)
	{
		return std::string();
	}
	LPSTR buffer = NULL;
	size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dwError, MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), (LPSTR)&buffer, 0, NULL);
	if (size <= 0)
	{
		return std::string();
	}

	std::string str(buffer, size);
	LocalFree(buffer);
	return str;
}

int socket_set_recvtime(int fd, int sec, int usec)
{
	int outtime = sec * 1000 + usec % 1000;
	return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&outtime, sizeof(outtime));
}

DWORD WINAPI IOCPRunner(LPVOID completionPortID);

struct iocp::_impl
{
	HANDLE hIocp;
	std::vector<serversock> vec;

	_impl(int threadCount)
	{
		hIocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
		if (hIocp == NULL)
		{
			auto err = socket_native_lasterror();
			myliblog("CreateIoCompletionPort error: %s", err.c_str());
			return;
		}
		
		if (threadCount <= 0)
		{
			SYSTEM_INFO sysInfo;
			GetSystemInfo(&sysInfo);

			threadCount = sysInfo.dwNumberOfProcessors * 2 + 1;
		}

		for (int i = 0; i < threadCount; i++)
		{
			DWORD threadID;
			HANDLE hThread;

			hThread = CreateThread(NULL, 0, IOCPRunner, hIocp, 0, &threadID);
			if (hThread == NULL)
			{
				auto err = socket_native_lasterror();
				myliblog("CreateThread error: %s", err.c_str());
				return;
			}
			CloseHandle(hThread);
		}
	}

	~_impl()
	{
		CloseHandle(hIocp);
	}
};

iocp::iocp(int threads) : _p(new _impl(threads))
{

}

serversock iocp::newTCPServer(int use_family)
{
	serversock ss;
	ss._vp->lp = true;
	ss._vp->af_protocol = use_family == 2 ? AF_INET6 : AF_INET;
	ss._vp->fd = WSASocket(ss._vp->af_protocol, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	ss._vp->inited = true;

	return ss;
}

struct iocp_handle_data
{
	iocp_connection* conn;
};

struct iocp_io_data
{
	OVERLAPPED overlapped;
	WSABUF wsabuf;

	char buffer[10240];
	int type;
	DWORD totalSize;
	DWORD bytesDone;
};

void iocp_conn_close(iocp_connection* conn)
{
	conn->onClose();
	closesocket(conn->_s);
	delete conn;

	// TODO...
}

int iocp_submit_read(iocp_io_data* ioData, HANDLE hIocp, iocp_connection* conn)
{
	iocp_io_data* pIoData = ioData;
	if (!pIoData)
	{
		pIoData = (iocp_io_data*)GlobalAlloc(GPTR, sizeof(iocp_io_data));
		if (!pIoData) return -1;

		pIoData->type = 0;
		pIoData->totalSize = sizeof(pIoData->buffer);
	}

	pIoData->bytesDone = 0;

	ZeroMemory(&(pIoData->overlapped), sizeof(pIoData->overlapped));
	pIoData->wsabuf.buf = pIoData->buffer;
	pIoData->wsabuf.len = pIoData->totalSize;

	DWORD flags = 0;
	if (WSARecv(conn->_s, &(pIoData->wsabuf), 1, &pIoData->bytesDone, &flags, &(pIoData->overlapped), NULL) < 0)
	{
		if (WSAGetLastError() != ERROR_IO_PENDING)
		{
			conn->onError();
		}
	}

	return 0;
}

int iocp_submit_write(iocp_io_data* ioData, HANDLE hIocp, iocp_connection* conn)
{
	iocp_io_data* pIoData = ioData;
	if (!pIoData)
	{
		pIoData = (iocp_io_data*)GlobalAlloc(GPTR, sizeof(iocp_io_data));
		if (!pIoData) return -1;

		pIoData->type = 1;
		pIoData->totalSize = 0;
	}

	// try load more data
	{
		std::unique_lock<std::mutex> ulk(conn->_m);
		int leftSize = sizeof(pIoData->buffer) - pIoData->totalSize;
		int loadSize = min(conn->_data.size(), leftSize);
		if (loadSize > 0)
		{
			memcpy(pIoData->buffer + pIoData->totalSize, conn->_data.data(), loadSize);
			conn->_data.erase(conn->_data.begin(), conn->_data.begin() + loadSize);
			pIoData->totalSize += loadSize;
		}
	}

	if (pIoData->totalSize < 1)
	{
		// All data are sent.
		if (conn->_c)
		{
			closesocket(conn->_s);
		}
		return 0;
	}

	pIoData->bytesDone = 0;

	ZeroMemory(&(pIoData->overlapped), sizeof(pIoData->overlapped));
	pIoData->wsabuf.buf = pIoData->buffer;
	pIoData->wsabuf.len = pIoData->totalSize;

	if (WSASend(conn->_s, &(pIoData->wsabuf), 1, &pIoData->bytesDone, NULL, &(pIoData->overlapped), NULL) < 0)
	{
		if (WSAGetLastError() != ERROR_IO_PENDING)
		{
			conn->onError();
		}
	}

	return 0;
}

int iocp_connection::send(const void* buffer, int size)
{
	_data.insert(_data.end(), (const char*)buffer, (const char*)buffer + size);
	iocp_submit_write(NULL, _controller->_p->hIocp, this);
	return size;
}

void iocp_connection::close()
{
	_c = true;
}

int iocp::run(const basic_sock& ss, const std::function<iocp_connection*(iocp*)> onConnection)
{
	if (!ss._vp->lp) return GSOCK_INVALID_SOCKET;

	while (1)
	{
		SOCKET newSocket = WSAAccept(ss._vp->fd, NULL, NULL, NULL, 0);
		if (newSocket == SOCKET_ERROR)
		{
			return -1;
		}

		iocp_connection* conn = onConnection(this);
		conn->_c = false;
		conn->_controller = this;
		conn->_s = newSocket;

		iocp_handle_data* pHandleData = (iocp_handle_data*)GlobalAlloc(GPTR, sizeof(iocp_handle_data));
		if (pHandleData == NULL)
		{
			iocp_conn_close(conn);
			return -1;
		}

		pHandleData->conn = conn;

		if (CreateIoCompletionPort((HANDLE)newSocket, _p->hIocp, (ULONG_PTR)pHandleData, 0) == NULL)
		{
			GlobalFree(pHandleData);
			iocp_conn_close(conn);
			return -1;
		}

		iocp_submit_read(NULL, _p->hIocp, conn);
	}

	return 0;
}

DWORD WINAPI IOCPRunner(LPVOID lphIocp)
{
	HANDLE hIocp = (HANDLE)lphIocp;

	while (1)
	{
		DWORD bytesTransferred;
		iocp_handle_data* pHandleData = nullptr;
		iocp_io_data* pIoData = nullptr;

		if (GetQueuedCompletionStatus(hIocp, &bytesTransferred, (PULONG_PTR)&pHandleData, (LPOVERLAPPED*)&pIoData, INFINITE) == 0)
		{
			auto err = socket_native_lasterror();
			printf("GetQueuedCompletionStatus: %s\n", err.c_str());
			return 0;
		}
		
		std::cout << "bytesTransferred: " << bytesTransferred << " pHandleData " << pHandleData << " pIoData " << pIoData << std::endl;

		if (!bytesTransferred)
		{
			// close only on read
			if (!pIoData->type)
			{
				iocp_conn_close(pHandleData->conn);
				GlobalFree(pHandleData);
			}
			GlobalFree(pIoData);
			continue;
		}

		if (pIoData->type)
		{
			// Continue write
			memmove(pIoData->buffer + bytesTransferred, pIoData->buffer, pIoData->totalSize - bytesTransferred);
			pIoData->totalSize -= bytesTransferred;
			iocp_submit_write(pIoData, hIocp, pHandleData->conn);
		}
		else
		{
			// Continue read
			pHandleData->conn->onData(pIoData->buffer, bytesTransferred);
			iocp_submit_read(pIoData, hIocp, pHandleData->conn);
		}
	}
}

#endif
