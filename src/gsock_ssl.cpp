#include "gsock.h"

#ifndef GSOCK_NO_SSL
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

void print_ssl_error(const std::string& str)
{
	fprintf(stderr, "%s: ", str.c_str());
	ERR_print_errors_fp(stderr);
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

	X509* cert = SSL_get_peer_certificate(_p->getSSL());
	if (!cert)
	{
		fprintf(stderr, "no cert found on peer server\n");
		return -1;
	}
	char buff[10240] = { 0 };
	X509_NAME_oneline(X509_get_subject_name(cert), buff, 10240);
	printf("Subject: %s\n", buff);
	X509_NAME_oneline(X509_get_issuer_name(cert), buff, 10240);
	printf("Issuer: %s\n", buff);
	X509_free(cert);

	// verify certificate
	int err = SSL_get_verify_result(_p->getSSL());
	if (err != X509_V_OK)
	{
		const char* msg = X509_verify_cert_error_string(err);
		fprintf(stderr, "X509_verify_cert_error_string: (%d) %s\n", err, msg);
		return -1;
	}

	

	return 0;
}

int sslsock::send(const void* buffer, int length)
{
	int ret = BIO_write(_p->bio, buffer, length);
	// BIO_flush(_p->bio);
	return ret;
}

int sslsock::recv(void* buffer, int length)
{
	return BIO_read(_p->bio, buffer, length);
}

#endif
