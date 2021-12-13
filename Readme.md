# General Socket Wrapper Version 2

Licensed under MIT

## Features

- TCP blocking/non-blocking socket

- UDP socket, broadcast

- Seamless IPv4 and IPv6 support

- select() support on all platform.

- IOCP (Windows only)

- Epoll (Linux only)

- (Optional) SSL/TLS socket

## Compile

### External dependency

If `GSOCK_NO_SSL` is not defined, GSock requires OpenSSL library to build.

[libreSSL](https://www.libressl.org/) is recommended on Windows platform. Please configure libreSSL with `cmake -G"Visual Studio 16 2019" .. -DBUILD_SHARED_LIBS=ON` and add `crypto`, `ssl`, `tls` libs and dlls to your linker after build.

On linux systems like Ubuntu, simply use `apt install libssl-dev`.

Download [CA certificates extracted from Mozilla](https://curl.se/docs/caextract.html)

## Relation with GSock v1

[GSock v1](https://github.com/Kiritow/GSock) is quite stable and has been used in a bunch of projects. However its code is not very intutive and a lot of advanced features are missing in the previous version. Thus we strongly recommend upgrade to GSock v2.

## Examples

*Disclaimer: These are just lines of fancy code, don't use it in production environment*

### TCP

```cpp
int main()
{
    sock s;
	cout << "connect: " << s.connect("127.0.0.1", 8082) << endl;
	cout << GetLastNativeError() << endl;

	string buffer = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
	s.send(buffer.data(), buffer.size());

	char buf[1024];
	while (1)
	{
		if (int ret = s.recv(buf, 1024); ret > 0)
		{
			cout << string(buf, ret);
		}
		else break;
	}
	cout << endl;
	return 0;
}
```

### IOCP

```cpp
class my_iocp : public iocp_connection
{
public:
	string str;

	void onData(const char* buffer, int size)
	{
		str += string(buffer, size);
		if (str.find("\r\n\r\n") != string::npos)
		{
			cout << "got full request: " << str << endl;
			cout << "sending response " << endl;
			string buffer = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nHi";
			send(buffer.c_str(), buffer.size());
			close();
		}
	}
	
	void onClose()
	{
		cout << this << " onClose" << endl;
	}

	void onError()
	{
		cout << this << " onError " << GetLastNativeError() << endl;
	}
};

int main()
{
	iocp looper;
	serversock ss = looper.newTCPServer();
	cout << "bind: " << ss.bind(12345) << " error: " << GetLastNativeError() << endl;
	cout << "listen: " << ss.listen(10) << " error: " << GetLastNativeError() << endl;

	auto fn = [](iocp*) {
		return new my_iocp;
	};

	int ret = looper.run(ss, fn);
	cout << "looper.run: " << ret << " error: " << GetLastNativeError() << endl;

	return ret;
}
```

### TLS client

```cpp
int main()
{
    int ret;
	sslsock s;
	ret = s.loadVerifyLocation("cacert.pem");
	cout << "sslsock loadVerifyLocation " << ret << endl;
	ret = s.connect("github.com", 443);
	cout << "sslsock connect " << ret << endl;

	string str = "GET / HTTP/1.1\r\nHost: github.com\r\nConnection: close\r\n\r\n";
	ret = s.send(str.c_str(), str.size());
	cout << "sslsock send: " << ret << endl;

	char buffer[10240] = { 0 };
	ret = s.recv(buffer, 10240);
	cout << buffer << endl;
	cout << "sslsock recv: " << ret << endl;

	return 0;
}
```
