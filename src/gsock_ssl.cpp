#include "includes.h"

#ifndef GSOCK_NO_SSL
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

void print_ssl_error(const std::string& str)
{
	printf("%s: ", str.c_str());
	ERR_print_errors_fp(stdout);
	printf("\n");
}

struct sslsock::_impl
{
	SSL_CTX* ctx;
	SSL* ssl;

	_impl()
	{
		ctx = SSL_CTX_new(TLS_client_method());
		if (SSL_CTX_set_default_verify_paths(ctx) != 1)
		{
			print_ssl_error("SSL_CTX_set_default_verify_paths");
		}

		ssl = nullptr;
	}

	~_impl()
	{
		SSL_free(ssl);
		SSL_CTX_free(ctx);
	}
};

sslsock::sslsock() : _p(new _impl)
{

}

int sslsock::loadVerifyLocation(const std::string& path)
{
	return SSL_CTX_load_verify_locations(_p->ctx, path.c_str(), NULL);
}

int sslsock::connect(const std::string& ip, int port)
{
	if (int ret = sock::connect(ip, port); ret < 0)
	{
		return ret;
	}

	_p->ssl = SSL_new(_p->ctx);
	SSL_set_fd(_p->ssl, _vp->fd);
	SSL_set_tlsext_host_name(_p->ssl, ip.c_str()); // TODO: replace with hostname

	if (SSL_connect(_p->ssl) != 1)
	{
		return -2;
	}

	// verify certificate
	int err = SSL_get_verify_result(_p->ssl);
	if (err != X509_V_OK)
	{
		const char* msg = X509_verify_cert_error_string(err);
		fprintf(stderr, "X509_verify_cert_error_string: (%d) %s\n", err, msg);
		return -3;
	}

	return 0;
}

int sslsock::send(const void* buffer, int length)
{
	int ret = SSL_write(_p->ssl, buffer, length);
	if (ret < 0)
	{
		print_ssl_error("BIO_write");
	}
	return ret;
}

int sslsock::recv(void* buffer, int length)
{
	int ret = SSL_read(_p->ssl, buffer, length);
	if (ret < 0)
	{
		print_ssl_error("BIO_read");
	}
	return ret;
}

std::string sslsock::getSubjectName()
{
	X509* cert = SSL_get_peer_certificate(_p->ssl);
	if (!cert)
	{
		fprintf(stderr, "no cert found on peer server\n");
		return std::string();
	}

	char buff[10240] = { 0 };
	X509_NAME_oneline(X509_get_subject_name(cert), buff, 10240);
	X509_free(cert);

	return std::string(buff);
}

std::string sslsock::getIssuerName()
{
	X509* cert = SSL_get_peer_certificate(_p->ssl);
	if (!cert)
	{
		fprintf(stderr, "no cert found on peer server\n");
		return std::string();
	}

	char buff[10240] = { 0 };
	X509_NAME_oneline(X509_get_issuer_name(cert), buff, 10240);
	X509_free(cert);

	return std::string(buff);
}

struct sslserversock::_impl
{
	SSL_CTX* ctx;

	_impl()
	{
		ctx = SSL_CTX_new(TLS_method());
		SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
	}

	~_impl()
	{
		SSL_CTX_free(ctx);
	}
};

sslserversock::sslserversock() : _p(new _impl)
{

}

int sslserversock::useCAFile(const std::string& path)
{
	return SSL_CTX_use_certificate_file(_p->ctx, path.c_str(), SSL_FILETYPE_PEM);
}

int sslserversock::usePKFile(const std::string& path)
{
	return SSL_CTX_use_PrivateKey_file(_p->ctx, path.c_str(), SSL_FILETYPE_PEM);
}

int sslserversock::accept(sslsock& outs)
{
	// failed if `outs` has been connected.
	if (!*this || outs) return GSOCK_INVALID_SOCKET;

	sslsock c;  // empty sslsock
	if (int ret = serversock::accept(c); ret < 0)
	{
		return ret;
	}
	// c._vp->fd has already been set and managed, so we don't need to call close.

	// Do ssl handshake
	c._p->ssl = SSL_new(_p->ctx);
	SSL_set_fd(c._p->ssl, c._vp->fd);

	if (SSL_accept(c._p->ssl) <= 0)
	{
		return -2;
	}

	outs = c;
	return 0;
}

#endif
