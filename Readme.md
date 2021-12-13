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
