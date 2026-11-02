#include <fcntl.h>
#include <poll.h>
#include <strings.h>
#include <time.h>
#include <openssl/x509v3.h>

#include "gs-common.h"
#include <gsocket/gsocket.h>
#include "gs-externs.h"

#include "picohttpparser.h"
#define JSMN_STATIC
#include "jsmn.h"


#define GS_DOH_PORT             (443)
#define GS_DOH_TIMEOUT_SEC      (5)
#define GS_DOH_HTTP_BUF_SIZE    (16 * 1024)
#define GS_DOH_MAX_HEADERS      (32)

struct gs_doh_provider
{
	const char *ip; 
	const char *host;
	const char *path;
};

// DoH Connection will be made using IP no need to resolve hostname 
static const struct gs_doh_provider doh_providers[] = {
	{"1.1.1.1",       "cloudflare-dns.com",         "/dns-query"},
	{"8.8.8.8",       "dns.google",                 "/resolve"},
	{"1.0.0.1",       "cloudflare-dns.com",         "/dns-query"},
	{"8.8.4.4",       "dns.google",                 "/resolve"},
	{"223.5.5.5",     "dns.alidns.com",             "/resolve"},
	{"94.140.14.140", "unfiltered.adguard-dns.com", "/resolve"},
};

static const char *doh_ca_files[] = {
	"/etc/ssl/certs/ca-certificates.crt",                   /* Debian, Ubuntu, Alpine, Arch, Gentoo, OpenWrt */
	"/etc/pki/tls/certs/ca-bundle.crt",                     /* Fedora, RHEL */
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",    /* RHEL/CentOS 7+ */
	"/etc/ssl/ca-bundle.pem",                               /* openSUSE */
	"/etc/ssl/cert.pem",                                    /* macOS, OpenBSD, Alpine */
	"/usr/local/etc/ssl/cert.pem",                          /* FreeBSD */
	"/usr/local/share/certs/ca-root-nss.crt",               /* FreeBSD */
	"/etc/openssl/certs/ca-certificates.crt",               /* NetBSD */
	"/etc/pki/tls/cacert.pem",                              /* OpenELEC */
};

static const char *doh_ca_dirs[] = {
	"/etc/ssl/certs",
	"/etc/pki/tls/certs",
};

struct doh_conn
{
	int fd;
	SSL *ssl;
	BIO *net_BIO;
	int is_eof;
	uint64_t deadline;
};

static uint64_t
doh_now_ms(void)
{
	return GS_usec() / 1000;
}

static int
doh_valid_hostname(const char *name)
{
	size_t len = strlen(name);

	return (len > 0) 
		&& (len <= 253) // hostname should not be larger than this 
		&& (strspn(name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_") == len);
}

/* Case-insensitive compare of a header name or value (not NUL terminated) */
static int
doh_eq(const char *s, size_t len, const char *str)
{
	return (strlen(str) == len) && (strncasecmp(s, str, len) == 0);
}

// Poll for events on the tcp socket
static int
doh_poll(int fd, short events, uint64_t deadline)
{
	struct pollfd pfd;
	uint64_t now;
	int ret;

	while (1)
	{
		now = doh_now_ms();
		
		if (now >= deadline)
			return -1;

		pfd.fd = fd;
		pfd.events = events;
		pfd.revents = 0;
		ret = poll(&pfd, 1, (int)(deadline - now));	/* At most 5000 ms, fits an int */
		
		if (ret > 0)
			return 0;	/* Errors show up in the next recv()/send()/getsockopt() */
		
		if ((ret < 0) && (errno != EINTR))
			return -1;
	}
}

static int
doh_tcp_connect(uint32_t ip, uint64_t deadline)
{
	struct sockaddr_in addr;
	socklen_t len;
	int flags;
	int err = 0;
	int fd;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;

	flags = fcntl(fd, F_GETFL, 0);
	if ((flags == -1) || (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1))
		goto err;
#ifdef SO_NOSIGPIPE
	flags = 1;
	setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &flags, sizeof flags);
#endif

	memset(&addr, 0, sizeof addr);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(GS_DOH_PORT);
	addr.sin_addr.s_addr = ip;

	if (connect(fd, (struct sockaddr *)&addr, sizeof addr) == 0)
		return fd;
	if ((errno != EINPROGRESS) && (errno != EINTR))
		goto err;
	if (doh_poll(fd, POLLOUT, deadline) != 0)
		goto err;

	len = sizeof err;
	if ((getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0) || (err != 0))
		goto err;

	return fd;
err:
	close(fd);
	return -1;
}

static void
doh_conn_close(struct doh_conn *c)
{
	if (c->ssl != NULL)
		SSL_free(c->ssl);
	if (c->net_BIO != NULL)
		BIO_free(c->net_BIO);
	if (c->fd >= 0)
		close(c->fd);

	c->ssl = NULL;
	c->net_BIO = NULL;
	c->fd = -1;
}


// Write everything in net_BIO to socket
static int
doh_ssl_flush(struct doh_conn *c)
{
	char buf[4096];
	ssize_t n;
	int len;
	int off;
	int send_flags = 0;

	/* 
		when MSG_NOSIGNAL is not set, SO_NOSIGPIPE is set on c->fd instead,
		this is required for mac systems. 
	 */
	#ifdef MSG_NOSIGNAL
		send_flags = MSG_NOSIGNAL;
	#endif


	while ((len = BIO_read(c->net_BIO, buf, sizeof buf)) > 0)
	{
		off = 0;
		while (off < len)
		{
			n = send(c->fd, buf + off, len - off, send_flags);
			if (n > 0)
			{
				off += n;
				continue;
			}
			if ((n < 0) && (errno == EINTR))
				continue;
			if ((n < 0) && ((errno == EAGAIN) || (errno == EWOULDBLOCK)) && (doh_poll(c->fd, POLLOUT, c->deadline) == 0))
				continue;
			return -1;
		}
	}

	return 0;
}

// Read from socket and write to net_BIO
static int
doh_fill(struct doh_conn *c)
{
	char buf[4096];
	size_t room;
	ssize_t n;

	if (c->is_eof)
		return -1;

	room = BIO_ctrl_get_write_guarantee(c->net_BIO);
	if (room == 0)
		return -1;
	if (room > sizeof buf)
		room = sizeof buf;

	while (1)
	{
		n = recv(c->fd, buf, room, 0);
		if (n > 0)
			return (BIO_write(c->net_BIO, buf, (int)n) == n) ? 0 : -1;
		if (n == 0)
		{
			/* OpenSSL sees the EOF on its next read */
			BIO_shutdown_wr(c->net_BIO);
			c->is_eof = 1;
			return 0;
		}
		if (errno == EINTR)
			continue;
		if ((errno != EAGAIN) && (errno != EWOULDBLOCK))
			return -1;
		if (doh_poll(c->fd, POLLIN, c->deadline) != 0)
			return -1;
	}
}

/*
 * Called after an SSL function returned <= 0, with err = SSL_get_error().
 * Return 0 to call the SSL function again, or -1 on error.
 */
static int
doh_ssl_retry(struct doh_conn *c, int err)
{
	/* Also bounds a peer that keeps sending without ever making us wait */
	if (doh_now_ms() >= c->deadline)
		return -1;

	/* OpenSSL may have queued output (e.g. handshake messages) before it needs input */
	if (doh_ssl_flush(c) != 0)
		return -1;
	if (err == SSL_ERROR_WANT_READ)
		return doh_fill(c);
	if (err == SSL_ERROR_WANT_WRITE)
		return 0;

	return -1;
}

static SSL_CTX *
doh_ssl_ctx_new(void)
{
	const char *file;
	SSL_CTX *ctx;
	size_t i;

	ctx = SSL_CTX_new(SSLv23_client_method());
	if (ctx == NULL)
		return NULL;

	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
	SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

	/* SSL_CERT_FILE/SSL_CERT_DIR or OpenSSL's compiled-in location */
	SSL_CTX_set_default_verify_paths(ctx);

	file = getenv(X509_get_default_cert_file_env());
	if (file == NULL)
		file = X509_get_default_cert_file();
	if (access(file, R_OK) == 0)
		return ctx;

	/* No CA bundle where OpenSSL expects it. Try where the OS keeps it. */
	for (i = 0; i < sizeof doh_ca_files / sizeof *doh_ca_files; i++)
	{
		if (access(doh_ca_files[i], R_OK) != 0)
			continue;
		if (SSL_CTX_load_verify_locations(ctx, doh_ca_files[i], NULL) == 1)
			break;
	}

	/* Only searched when a certificate is checked, so a missing one does no harm */
	for (i = 0; i < sizeof doh_ca_dirs / sizeof *doh_ca_dirs; i++)
		SSL_CTX_load_verify_locations(ctx, NULL, doh_ca_dirs[i]);

	return ctx;
}

/* TLS handshake on a connected socket. The certificate must be valid for 'host'. */
static int
doh_ssl_connect(SSL_CTX *ctx, struct doh_conn *c, const char *host)
{
	X509_VERIFY_PARAM *param;
	BIO *internal_BIO;
	int ret;

	c->ssl = SSL_new(ctx);
	if (c->ssl == NULL)
		return -1;
	if (BIO_new_bio_pair(&internal_BIO, 0, &c->net_BIO, 0) != 1)
		return -1;
	SSL_set_bio(c->ssl, internal_BIO, internal_BIO);

	if (SSL_set_tlsext_host_name(c->ssl, host) != 1)
		return -1;

	param = SSL_get0_param(c->ssl);
	X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
	if (X509_VERIFY_PARAM_set1_host(param, host, 0) != 1)
		return -1;

	/* SSL_VERIFY_PEER: the handshake fails unless the certificate verifies */
	while ((ret = SSL_connect(c->ssl)) != 1)
	{
		if (doh_ssl_retry(c, SSL_get_error(c->ssl, ret)) != 0)
		{
			DEBUGF_R("SSL_connect() failed (verify: %s)\n", X509_verify_cert_error_string(SSL_get_verify_result(c->ssl)));
			return -1;
		}
	}

	return doh_ssl_flush(c);
}

static int
doh_ssl_write_all(struct doh_conn *c, const char *buf, size_t len)
{
	int n;

	/* Without SSL_MODE_ENABLE_PARTIAL_WRITE, SSL_write() writes all or nothing */
	while ((n = SSL_write(c->ssl, buf, (int)len)) <= 0)
	{
		if (doh_ssl_retry(c, SSL_get_error(c->ssl, n)) != 0)
			return -1;
	}

	return doh_ssl_flush(c);
}

/*
 * Return number of bytes read, 0 on a clean TLS close (close_notify) or -1 on
 * error, timeout or when the buffer is full.
 */
static int
doh_ssl_read(struct doh_conn *c, char *buf, size_t size)
{
	int err;
	int n;

	if (size == 0)
		return -1;

	while (1)
	{
		n = SSL_read(c->ssl, buf, (int)size);
		if (n > 0)
			return n;
		err = SSL_get_error(c->ssl, n);
		if (err == SSL_ERROR_ZERO_RETURN)
			return 0;
		if (doh_ssl_retry(c, err) != 0)
			return -1;
	}
}



/* Content-Length. Anything that does not fit into our buffer is an error. */
static int
doh_parse_content_length(const struct phr_header *h, size_t *out)
{
	size_t val = 0;
	size_t i;

	if (h->value_len == 0)
		return -1;

	for (i = 0; i < h->value_len; i++)
	{
		if ((h->value[i] < '0') || (h->value[i] > '9'))
			return -1;
		val = val * 10 + (h->value[i] - '0');
		if (val > GS_DOH_HTTP_BUF_SIZE)
			return -1;
	}
	*out = val;

	return 0;
}

/*
 * Send the JSON API query and read the response into 'buf', which must hold
 * GS_DOH_HTTP_BUF_SIZE + 1 bytes. On success '*body' points into 'buf' and is
 * NUL terminated.
 */
static int
doh_https_get(struct doh_conn *c, const struct gs_doh_provider *p, const char *name, char *buf, char **body, size_t *body_len)
{
	struct phr_header headers[GS_DOH_MAX_HEADERS];
	struct phr_chunked_decoder decoder;
	const struct phr_header *h;
	char req[1024]; // enough space to hold the GET request
	const char *msg;
	size_t msg_len;
	size_t num_headers;
	size_t content_len = 0;
	size_t prev_len;
	size_t len = 0;
	size_t blen;
	size_t val;
	size_t sz;
	char *bptr;
	int has_content_len = 0;
	int is_chunked = 0;
	int minor_version;
	int status;
	int hdr_len;
	ssize_t ret;
	size_t i;
	int n;

	n = snprintf(req, sizeof req,
		"GET %s?name=%s&type=A HTTP/1.1\r\n"
		"Host: %s\r\n"
		"Accept: application/dns-json\r\n"
		"Accept-Encoding: identity\r\n"
		"Connection: close\r\n"
		"\r\n", p->path, name, p->host);
	if ((n < 0) || ((size_t)n >= sizeof req))
		return -1;
	if (doh_ssl_write_all(c, req, n) != 0)
		return -1;

	/* Read until the status line and all headers have arrived */
	while (1)
	{
		n = doh_ssl_read(c, buf + len, GS_DOH_HTTP_BUF_SIZE - len);
		if (n <= 0)
			return -1;
		prev_len = len;
		len += n;

		num_headers = GS_DOH_MAX_HEADERS;
		hdr_len = phr_parse_response(buf, len, &minor_version, &status, &msg, &msg_len, headers, &num_headers, prev_len);
		if (hdr_len > 0)
			break;
		if (hdr_len == -1)
			return -1;
		/* -2: Incomplete */
	}

	if (status != 200)
	{
		DEBUGF_R("HTTP status %d\n", status);
		return -1;
	}

	for (i = 0; i < num_headers; i++)
	{
		h = &headers[i];
		/* Obsolete line folding (RFC 9112 5.2). Could hide a coding from the checks below. */
		if (h->name == NULL)
			goto bad;

		if (doh_eq(h->name, h->name_len, "Content-Length"))
		{
			/* Duplicates must agree */
			if ((doh_parse_content_length(h, &val) != 0) || ((has_content_len) && (val != content_len)))
				goto bad;
			content_len = val;
			has_content_len = 1;
		} else if (doh_eq(h->name, h->name_len, "Transfer-Encoding")) {
			/* Only 'chunked', and only once */
			if ((is_chunked) || (!doh_eq(h->value, h->value_len, "chunked")))
				goto bad;
			is_chunked = 1;
		} else if (doh_eq(h->name, h->name_len, "Content-Encoding")) {
			/* We asked for Accept-Encoding: identity */
			if (!doh_eq(h->value, h->value_len, "identity"))
				goto bad;
		}
	}

	/* RFC 9112 6.3: Both indicate request smuggling or response splitting */
	if ((is_chunked) && (has_content_len))
		goto bad;

	bptr = buf + hdr_len;
	blen = len - hdr_len;	/* Body bytes already received */

	if (is_chunked)
	{
		/* Decode in place. New data is appended right after the decoded data. */
		memset(&decoder, 0, sizeof decoder);
		decoder.consume_trailer = 1;
		sz = blen;
		blen = 0;
		while (1)
		{
			ret = phr_decode_chunked(&decoder, bptr + blen, &sz);
			if (ret == -1)
				return -1;
			blen += sz;
			if (ret >= 0)
				break;
			/* -2: Incomplete */
			n = doh_ssl_read(c, bptr + blen, buf + GS_DOH_HTTP_BUF_SIZE - (bptr + blen));
			if (n <= 0)
				return -1;
			sz = n;
		}
	} else {
		/* Content-Length bytes, or until the server closes the connection */
		while ((!has_content_len) || (blen < content_len))
		{
			n = doh_ssl_read(c, buf + len, GS_DOH_HTTP_BUF_SIZE - len);
			if ((n < 0) || ((n == 0) && (has_content_len)))
				return -1;
			if (n == 0)
				break;
			len += n;
			blen += n;
		}
		if (has_content_len)
			blen = content_len;	/* Ignore anything after the announced length */
	}

	bptr[blen] = '\0';
	*body = bptr;
	*body_len = blen;

	return 0;
bad:
	DEBUGF_R("Response headers rejected\n");
	return -1;
}


/*
	Docs for JSMN json parser: https://github.com/zserge/jsmn
*/

static int
json_eq(const char *js, const jsmntok_t *t, jsmntype_t type, const char *str)
{
	size_t len = strlen(str);

	if (t->type != type)
		return 0;

	return ((size_t)(t->end - t->start) == len) && (memcmp(js + t->start, str, len) == 0);
}

/* Return the index of the token that follows token 'i' and all its children */
static int
json_skip(const jsmntok_t *t, int n, int i)
{
	int end = t[i].end;

	for (i++; i < n; i++)
	{
		if (t[i].start >= end)
			break;
	}

	return i;
}


// Return first A record from JSON API response or 0xFFFFFFFF when no usable answer is received
static uint32_t
doh_json_get_a(const char *js, size_t len)
{
	char ipstr[INET_ADDRSTRLEN];
	struct in_addr addr;
	jsmn_parser parser;
	jsmntok_t *t;
	uint32_t ip = 0xFFFFFFFF;
	int is_noerror = 0;
	int answer = -1;
	int is_a;
	int data;
	int end;
	int n;
	int i;
	int k;

	/* Count the tokens first */
	jsmn_init(&parser);
	n = jsmn_parse(&parser, js, len, NULL, 0);
	if (n < 1)
		return 0xFFFFFFFF;

	t = calloc(n, sizeof *t);
	if (t == NULL)
		return 0xFFFFFFFF;

	jsmn_init(&parser);
	n = jsmn_parse(&parser, js, len, t, n);
	if ((n < 1) || (t[0].type != JSMN_OBJECT))
		goto done;


	/*
		Sample JSON response looks like this:

		{
			"Status": 0,							<-------- 0 means query was successfull
			"TC": false,
			"RD": true,
			"RA": true,
			"AD": false,
			"CD": false,
			"Question": [
				{
				"name": "thc.org.",
				"type": 1
				}
			],
			"Answer": [
				{
				"name": "thc.org.",
				"type": 1,
				"TTL": 1290,
				"data": "185.199.109.153"				<---- We want this, JSON path would be .Answer[0].data 
				}
			],
			"Comment": "Response from 217.160.81.227."
		}

	*/


	/* Top level "key": value pairs, in any order */
	for (i = 1; (i + 1 < n) && (t[i].start < t[0].end); i = json_skip(t, n, i + 1))
	{
		if (json_eq(js, &t[i], JSMN_STRING, "Status"))
			is_noerror = json_eq(js, &t[i + 1], JSMN_PRIMITIVE, "0");
		else if (json_eq(js, &t[i], JSMN_STRING, "Answer") && (t[i + 1].type == JSMN_ARRAY))
			answer = i + 1;
	}

	if ((!is_noerror) || (answer < 0))
	{
		DEBUGF_R("Status not NOERROR or no Answer\n");
		goto done;
	}

	/* Answer is an array of records. CNAMEs come before the A record. */
	end = t[answer].end;
	for (i = answer + 1; (i < n) && (t[i].start < end); i = json_skip(t, n, i))
	{
		if (t[i].type != JSMN_OBJECT)
			continue;

		is_a = 0;
		data = -1;
		for (k = i + 1; (k + 1 < n) && (t[k].start < t[i].end); k = json_skip(t, n, k + 1))
		{
			if (json_eq(js, &t[k], JSMN_STRING, "type"))
				is_a = json_eq(js, &t[k + 1], JSMN_PRIMITIVE, "1");
			else if (json_eq(js, &t[k], JSMN_STRING, "data") && (t[k + 1].type == JSMN_STRING))
				data = k + 1;
		}

		// Ignore non A records
		if ((!is_a) || (data < 0))
			continue;
		
		// IP address sanity check
		if ((size_t)(t[data].end - t[data].start) >= sizeof ipstr)
			continue;

		// Parse IP
		memcpy(ipstr, js + t[data].start, t[data].end - t[data].start);
		ipstr[t[data].end - t[data].start] = '\0';
		if (inet_pton(AF_INET, ipstr, &addr) == 1)
		{
			ip = addr.s_addr;
			break;
		}
	}

	if ((ip == 0) || ((ip != 0xFFFFFFFF) && ((ntohl(ip) >> 24) == 127)))
	{
		DEBUGF_R("Sinkhole address %s\n", ipstr);
		ip = 0xFFFFFFFF;
	}

done:
	free(t);
	return ip;
}

/*
 * Resolve 'hostname' to an IPv4 address (network byte order) using DNS over HTTPS. Return 0xFFFFFFFF on failure.
 */
uint32_t
GS_hton_doh(const char *hostname)
{
	const struct gs_doh_provider *p;
	struct doh_conn c;
	SSL_CTX *ctx;
	char *body;
	char *buf;
	size_t body_len;
	uint32_t ip;
	size_t i;
	int ret;

	/* If hostname is a IP parse and return */
	ip = inet_addr(hostname);
	if (ip != 0xFFFFFFFF)
		return ip;

	if (!doh_valid_hostname(hostname))
		return 0xFFFFFFFF;

	buf = malloc(GS_DOH_HTTP_BUF_SIZE + 1);
	if (buf == NULL)
		return 0xFFFFFFFF;

	// TODO: cache SSL context and reuse it across calls
	ctx = doh_ssl_ctx_new();
	if (ctx == NULL)
	{
		free(buf);
		return 0xFFFFFFFF;
	}

	for (i = 0; i < sizeof doh_providers / sizeof *doh_providers; i++)
	{
		p = &doh_providers[i];

		memset(&c, 0, sizeof c);
		c.deadline = doh_now_ms() + (uint64_t)GS_DOH_TIMEOUT_SEC * 1000;

		c.fd = doh_tcp_connect(inet_addr(p->ip), c.deadline);
		ret = -1;
		if ((c.fd >= 0) && (doh_ssl_connect(ctx, &c, p->host) == 0))
			ret = doh_https_get(&c, p, hostname, buf, &body, &body_len);
		doh_conn_close(&c);

		if (ret == 0)
			ip = doh_json_get_a(body, body_len);
		if (ip != 0xFFFFFFFF)
		{
			DEBUGF_G("DoH %s (%s): %s = %s\n", p->host, p->ip, hostname, inet_ntoa(*(struct in_addr *)&ip));
			break;
		}
		DEBUGF_R("DoH %s (%s): failed (connect, TLS, HTTP or no usable answer)\n", p->host, p->ip);
	}

	SSL_CTX_free(ctx);
	free(buf);
	/* Don't leave errors behind for SSL_get_error() on other connections */
	ERR_clear_error();

	return ip;
}