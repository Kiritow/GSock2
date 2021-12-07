#include "includes.h"

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

#endif
