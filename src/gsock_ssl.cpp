#include "includes.h"

#ifndef GSOCK_NO_SSL
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

void print_ssl_error(const std::string& str)
{
	fprintf(stderr, "%s: ", str.c_str());
	ERR_print_errors_fp(stderr);
	fprintf(stderr, "\n");
}

struct sslsock::_impl
{
	SSL_CTX* ctx;
	BIO* bio;

	_impl()
	{
		ctx = SSL_CTX_new(TLS_client_method());
		if (SSL_CTX_set_default_verify_paths(ctx) != 1)
		{
			print_ssl_error("SSL_CTX_set_default_verify_paths");
		}

		bio = nullptr;
	}

	~_impl()
	{
		BIO_free_all(bio);
		SSL_CTX_free(ctx);
	}

	SSL* getSSL()
	{
		SSL* p = nullptr;
		BIO_get_ssl(bio, &p);
		return p;
	}

	void update_vp(sslsock& s)
	{
		BIO_get_fd(bio, &(s._vp->fd));

		sockaddr addr;
		socklen_t slen = sizeof(addr);
		getpeername(s._vp->fd, &addr, &slen);
		s._vp->af_protocol = addr.sa_family;  // AF_INET, AF_INET6

		s._vp->inited = true;
	}
};

sslsock::sslsock() : _p(new _impl)
{

}

int sslsock::loadVerifyLocation(const std::string& path)
{
	return SSL_CTX_load_verify_locations(_p->ctx, path.c_str(), NULL);
}

int sslsock::connect(const std::string& host, int port)
{
	std::string bioHost = host + ":" + std::to_string(port);

	_p->bio = BIO_new_connect(bioHost.c_str());
	if (!_p->bio)
	{
		print_ssl_error("BIO_new_connect");
		return -1;
	}

	if (BIO_do_connect(_p->bio) <= 0)
	{
		print_ssl_error("BIO_do_connect");
		return -1;
	}

	_p->bio = BIO_push(BIO_new_ssl(_p->ctx, 1), _p->bio);
	SSL_set_tlsext_host_name(_p->getSSL(), host.c_str());
	
	if (BIO_do_handshake(_p->bio) <= 0)
	{
		print_ssl_error("BIO_do_handshake");
		return -1;
	}

	// verify certificate
	int err = SSL_get_verify_result(_p->getSSL());
	if (err != X509_V_OK)
	{
		const char* msg = X509_verify_cert_error_string(err);
		fprintf(stderr, "X509_verify_cert_error_string: (%d) %s\n", err, msg);
		return -1;
	}

	_p->update_vp(*this);
	return 0;
}

int sslsock::send(const void* buffer, int length)
{
	int ret = BIO_write(_p->bio, buffer, length);
	if (ret < 0)
	{
		print_ssl_error("BIO_write");
	}
	return ret;
}

int sslsock::recv(void* buffer, int length)
{
	int ret = BIO_read(_p->bio, buffer, length);
	if (ret < 0)
	{
		print_ssl_error("BIO_read");
	}
	return ret;
}

std::string sslsock::getSubjectName()
{
	X509* cert = SSL_get_peer_certificate(_p->getSSL());
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
	X509* cert = SSL_get_peer_certificate(_p->getSSL());
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
	BIO* bio;

	_impl()
	{
		ctx = SSL_CTX_new(TLS_method());
		SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

		bio = nullptr;
	}

	~_impl()
	{
		BIO_free_all(bio);
		SSL_CTX_free(ctx);
	}

	void update_vp(sslserversock& s)
	{
		BIO_get_fd(bio, &(s._vp->fd));

		sockaddr addr;
		socklen_t slen = sizeof(addr);
		getpeername(s._vp->fd, &addr, &slen);
		s._vp->af_protocol = addr.sa_family;  // AF_INET, AF_INET6

		s._vp->inited = true;
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

int sslserversock::bind(int port)
{
	std::string str = std::to_string(port);
	_p->bio = BIO_new_accept(str.c_str());
	if (int ret = BIO_do_accept(_p->bio); ret < 0)
	{
		print_ssl_error("BIO_do_accept");
		return ret;
	}

	_p->update_vp(*this);
}

sslsock sslserversock::accept()
{
	int ret = BIO_do_accept(_p->bio);
	if (ret < 0)
	{
		return sslsock();
	}
	
	BIO* newBio = BIO_pop(_p->bio);

	sslsock client;
	SSL_CTX_free(client._p->ctx);
	client._p->ctx = nullptr;
	client._p->bio = BIO_push(BIO_new_ssl(_p->ctx, 0), newBio);
	client._p->update_vp(client);

	// Do handshake here in case you want to send before recv.
	if (BIO_do_handshake(client._p->bio) <= 0)
	{
		return sslsock();
	}

	return client;
}

#endif
