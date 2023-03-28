
#include "gs-common.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <gsocket/gsocket.h>
#include "gsocket-engine.h"
#include "gs-externs.h"

#ifdef DEBUG
// # define DEBUG_SELECT	(1)
#endif

#ifdef DEBUG
FILE *gs_dout;		/* DEBUG OUTPUT */
int gs_did;         // debug ID
int gs_debug_level;
fd_set *gs_debug_rfd;
fd_set *gs_debug_wfd;
fd_set *gs_debug_r;
fd_set *gs_debug_w;
#endif // DEBUG
FILE *gs_errfp;
gs_cb_log_t gs_func_log;
static struct _gs_log_info gs_log_info;


#define GS_NET_DEFAULT_HOST			"gs.thc.org"
#define GS_SOCKS_DFL_IP				"127.0.0.1"
#define GS_SOCKS_DFL_PORT			9050
#define GS_GS_HTON_DELAY			(12 * 60 * 60)	// every 12h 
#ifdef DEBUG_SELECT
//# define GS_DEFAULT_PING_INTERVAL	(30)
# define GS_RECONNECT_DELAY			(3)
#else
//# define GS_DEFAULT_PING_INTERVAL	(2*60)	// Every 2 minutes
# define GS_RECONNECT_DELAY			(15)	// connect() not more than every 15s
# define GS_WARN_SLOWCONNECT        (4)     // Warn about slow connect() after 4 seconds...
#endif

// #define STRESSTEST	1
#ifdef STRESSTEST
//# define GS_DEFAULT_PING_INTERVAL	(1)
#endif

static const char unit[] = "BKMGT";    /* Up to Exa-bytes. */

static int gs_pkt_listen_write(GS *gsocket, struct gs_sox *sox);
static int gs_pkt_connect_write(GS *gsocket, struct gs_sox *sox);
static int gs_pkt_connect_socks(GS *gsocket, struct gs_sox *sox);
static void gs_close(GS *gsocket);
static void gs_listen_add_gs_select_by_sox(GS_SELECT_CTX *ctx, gselect_cb_t func, int fd, void *arg, int val);
static void gs_net_try_reconnect_by_sox(GS *gs, struct gs_sox *sox);
static void gs_net_init_by_sox(GS_CTX *ctx, struct gs_sox *sox);
static int gs_net_connect_new_socket(GS *gs, struct gs_sox *sox);

#ifndef int_ntoa
const char *
int_ntoa(uint32_t ip)
{
	struct in_addr in;

	in.s_addr = ip;
	return inet_ntoa(in);
}
#endif

#define gs_set_error(gs_ctx, a...)	do { \
	snprintf(gs_ctx->err_buf, sizeof (gs_ctx)->err_buf, a); \
} while (0)

void
gs_fds_out_fd(fd_set *fdset, char id, int fd)
{
#ifdef DEBUG_SELECT
	if (FD_ISSET(fd, fdset))
		DEBUGF("fd=%d %c (set)\n", fd, id);
	else
		DEBUGF("fd=%d %c (not set)\n", fd, id);
#endif
}

static int gs_lib_init_called;

void
gs_fds_out(fd_set *fdset, int max, char id)
{
#ifdef DEBUG_SELECT
	char buf[max + 1 + 1];

	memset(buf, ' ', sizeof buf);
	int i;

	for (i = 0; i <= max; i++)
		buf[i] = '0' + i % 10;
	buf[i] = '\0';
	xfprintf(gs_dout, "%s (max = %d)\n", buf, max);
	int n = 0;
	memset(buf, '.', sizeof buf);
	for (i = 0; i <= max; i++)
	{
		if (FD_ISSET(i, fdset))
		{
			n++;
			buf[i] = id;
		}

	}
	buf[i] = '\0';
	xfprintf(gs_dout, "%s (Tracking: %d, max = %d)\n", buf, n, max);
#endif
}

void
gs_fds_out_rwfd(GS_SELECT_CTX *ctx)
{
#ifdef DEBUG_SELECT
	int i;
	char buf[ctx->max_fd + 1 + 1];

	for (i = 0; i <= ctx->max_fd; i++)
		buf[i] = '0' + i % 10;
	buf[i] = '\0';
	xfprintf(gs_dout, "%s (max = %d)\n", buf, ctx->max_fd);

	memset(buf, ' ', sizeof buf);
	buf[sizeof buf - 1] = '\0';

	int c;
	int n = 0;
	for (i = 0; i <= ctx->max_fd; i++)
	{
		c = 0;
		if (FD_ISSET(i, ctx->rfd))
			c = 1;
		if (FD_ISSET(i, ctx->wfd))
			c += 2;

		if (c == 0)
		{
			buf[i] = '.';
			continue;
		}
		else if (c == 1)
			buf[i] = 'R';
		else if (c == 2)
			buf[i] = 'W';
		else if (c == 3)
			buf[i] = 'X';	// Set of Reading _and_ Writing
		else
			buf[i] = 'E';	// Cant happen.
		n++;
	}
	buf[i] = '\0';
	xfprintf(gs_dout, "%s (Tracking: %d, max = %d)\n", buf, n, ctx->max_fd);
#endif
}

void
GS_library_init(FILE *err_fp, FILE *dout_fp, gs_cb_log_t func_log)
{
	if (gs_lib_init_called != 0)
		return;
	gs_lib_init_called = 1;

	/* Initialize SSL */
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	XASSERT(RAND_status() == 1, "RAND_status()");

	if (func_log != NULL)
	{
		gs_log_info.msg = calloc(1, GS_LOG_INFO_MSG_SIZE);
		XASSERT(gs_log_info.msg != NULL, "calloc: %s\n", strerror(errno));
	}

	gs_errfp = err_fp;
	gs_func_log = func_log;
#ifdef DEBUG
	gs_dout = dout_fp;
#endif
}

int
GS_CTX_init(GS_CTX *ctx, fd_set *rfd, fd_set *wfd, fd_set *r, fd_set *w, struct timeval *tv_now)
{
	GS_library_init(stderr, stderr, NULL);

	memset(ctx, 0, sizeof *ctx);

	ctx->rfd = rfd;
	ctx->wfd = wfd;
	ctx->r = r;
	ctx->w = w;
	ctx->tv_now = tv_now;
#ifdef DEBUG_SELECT
	gs_debug_rfd = rfd;
	gs_debug_wfd = wfd;
	gs_debug_r = r;
	gs_debug_w = w;
#endif

	if (ctx->rfd == NULL)
	{
		ERREXIT("Is this still being used? how about r and w == NULL?\n");
		ctx->rfd = calloc(1, sizeof *ctx->rfd);
		ctx->wfd = calloc(1, sizeof *ctx->wfd);
		ctx->flags |= GS_CTX_FL_RFD_INTERNAL;
	} 

	ctx->socks_port = htons(GS_SOCKS_DFL_PORT);
	char *ptr;
	ptr = GS_getenv("GSOCKET_SOCKS_IP");
	if ((ptr != NULL) && (*ptr != '\0'))
		ctx->socks_ip = inet_addr(ptr);

	ptr = GS_getenv("GSOCKET_SOCKS_PORT");
	if (ptr != NULL)
		ctx->socks_port = htons(atoi(ptr));

	ctx->gs_flags |= GSC_FL_USE_SRP;		// Encryption by default
	ctx->gs_flags |= GSC_FL_NONBLOCKING;	// Non-blocking by default
	ctx->flags_proto |= GS_FL_PROTO_FAST_CONNECT;

	return 0;
}

/*
 * Make use of GS_select() subsystem.
 */
void
GS_CTX_use_gselect(GS_CTX *ctx, GS_SELECT_CTX *gselect_ctx)
{
	ctx->gselect_ctx = gselect_ctx;
}

int
GS_CTX_free(GS_CTX *ctx)
{
	if (ctx->flags & GS_CTX_FL_RFD_INTERNAL)
	{
		XFREE(ctx->rfd);
		XFREE(ctx->wfd);
	}

	memset(ctx, 0, sizeof *ctx);

	return 0;
}

/*
 * Copy over all elements of a GS to gs_new
 * but increment gs-specific counters.
 * This is typically used to create a GS from a listening GS.
 */
static void
gs_instantiate(GS *gsocket, GS *new_gs, int new_fd)
{

		new_gs->ctx = gsocket->ctx;
		new_gs->fd = new_fd;
		new_gs->flags = gsocket->flags;
		new_gs->ctx->gsocket_success_count++;
		new_gs->id = new_gs->ctx->gsocket_success_count;

#ifdef WITH_GSOCKET_SSL
		new_gs->ssl_ctx = gsocket->ssl_ctx;
		new_gs->srpData = gsocket->srpData;
		memcpy(new_gs->srp_sec, gsocket->srp_sec, sizeof new_gs->srp_sec);
		if (new_gs->ssl != NULL)
			DEBUGF("*** WARNING ***: old SSL found???\n");
		new_gs->ssl = NULL;
#endif
}

static int
gs_set_ip_by_hostname(GS *gs, const char *hostname)
{
	/* No hostname specified. Perhaps using env var GSOCKET_IP */
	if (hostname == NULL)
		return GS_SUCCESS;

	/* When Socks5 is used then TCP goes to Socks5 server */
	if (gs->ctx->socks_ip != 0)
		return GS_SUCCESS;

	/* HERE: Socks5 not used */
	uint32_t gs_ip;
	gs_ip = GS_hton(hostname);
	if (gs_ip == 0xFFFFFFFF)
	{
		GS_LOG_ERR("Cannot resolve '%s'. Re-trying in %d seconds...\n", hostname, GS_RECONNECT_DELAY);
		return GS_ERROR;
	}
	DEBUGF_B("Setting hostname=%s\n", hostname);

	gs->net.tv_gs_hton = GS_TV_TO_USEC(gs->ctx->tv_now);
	gs->net.addr = gs_ip;

	return GS_SUCCESS;
}

// Call callback to pass log message from library to calling programm
void
GS_log(int type, int level, char *fmt, ...)
{
	if (gs_func_log == NULL)
		return;

	va_list ap;
	va_start(ap, fmt);
	vsnprintf(gs_log_info.msg, GS_LOG_INFO_MSG_SIZE, fmt, ap);
	va_end(ap);

	gs_log_info.level = level;
	gs_log_info.type = type;

	(*gs_func_log)(&gs_log_info);
}

GS *
GS_new(GS_CTX *ctx, GS_ADDR *addr)
{
	GS *gsocket = NULL;
	char *ptr;
	char *hostname;

	gsocket = calloc(1, sizeof *gsocket);
	XASSERT(gsocket != NULL, "calloc(): %s\n", strerror(errno));

	gsocket->ctx = ctx;
	gsocket->fd = -1;

	uint16_t gs_port;
	ptr = GS_getenv("GSOCKET_PORT");
	if (ptr == NULL)
		ptr = GS_getenv("GS_PORT");
	if (ptr != NULL)
		gs_port = htons(atoi(ptr));
	else
		gs_port = htons(GSRN_DEFAULT_PORT);

	ctx->gs_port = gs_port;	// Socks5 needs to know
	gsocket->net.port = gs_port;

	ptr = GS_getenv("GSOCKET_IP");
	if (ptr != NULL)
	{
		gsocket->net.addr = inet_addr(ptr);
	}

	if ((ctx->socks_ip != 0) || (gsocket->net.addr == 0))
	{
		/* HERE: Use Socks5 -or- GSOCKET_IP not available */
		char buf[256];
		hostname = GS_getenv("GSOCKET_HOST");
		if (hostname == NULL)
			hostname = GS_getenv("GS_HOST");
		if (hostname == NULL)
		{
			if (gsocket->net.addr != 0)
			{
				// Socks5 is used and GSOCKET_IP is set. Connect
				// to GSOCKET_IP via Socks5.
				hostname = strdup(int_ntoa(gsocket->net.addr));
			} else {
				uint8_t hostname_id;
				hostname_id = GS_ADDR_get_hostname_id(addr->addr);
				// Connect to [a-z].gsocket.io depending on GS-address
				const char *domain;
				domain = GS_getenv("GSOCKET_DOMAIN");
				if (domain == NULL)
					domain = GS_NET_DEFAULT_HOST;

				snprintf(buf, sizeof buf, "%c.%s", 'a' + hostname_id, domain);
				hostname = buf;
			}
		}
		gsocket->net.hostname = strdup(hostname);

		gs_set_ip_by_hostname(gsocket, gsocket->net.hostname);
	}

	if (ctx->socks_ip != 0)
	{
		// HERE: Socks5 is used
		gsocket->net.addr = ctx->socks_ip;
		gsocket->net.port = ctx->socks_port;
		XASSERT(gsocket->net.hostname != NULL, "Socks5 but hostname not set\n");
	}
	gsocket->net.fd_accepted = -1;

	gsocket->net.n_sox = 1;
	int i;
	for (i = 0; i < gsocket->net.n_sox; i++)
	{
		gsocket->net.sox[i].fd = -1;
	}
	gsocket->flags = ctx->gs_flags;

	memcpy(&gsocket->gs_addr, addr, sizeof gsocket->gs_addr);

	GS_srp_setpassword(gsocket, gsocket->gs_addr.srp_password);

	GS_set_token(gsocket, NULL, 0);

	return gsocket;
}

static void
gs_net_connect_complete(GS *gs, struct gs_sox *sox)
{
	int vlevel = GS_LOG_LEVEL_VERBOSE;

	// If we warned about a slow connection then also say when we succeeded...
	if (sox->flags & GS_SOX_FL_WARN_SLOWCONNECT)
		vlevel = GS_LOG_LEVEL_NONE;

	if (gs->ctx->socks_ip != 0)
		GS_log(GS_LOG_TYPE_NORMAL, vlevel, "GSRN connection established [via TOR to %s:%d].\n", gs->net.hostname, ntohs(gs->ctx->gs_port));
	else
		GS_log(GS_LOG_TYPE_NORMAL, vlevel, "GSRN connection established [%s:%d].\n", int_ntoa(gs->net.addr), ntohs(gs->ctx->gs_port));

	if (gs->flags & GS_FL_IS_CLIENT)
		gs_pkt_connect_write(gs, sox);
	else
		gs_pkt_listen_write(gs, sox);

	if (gs->net.conn_count >= gs->net.n_sox)
		gs->flags |= GS_FL_TCP_CONNECTED;	// All TCP (APP) are now connected

	sox->flags &= ~GS_SOX_FL_WARN_SLOWCONNECT;
}

/*
 * First and completing call to 'connect()' (non-blocking).
 * Return -2 on error (fatal, must exit)
 * Return -1 if in progress
 * Return 0 on success (connection actually established)
 */
static int
gs_net_connect_by_sox(GS *gsocket, struct gs_sox *sox)
{
	struct sockaddr_in addr;
	int ret;
	
	memset(&addr, 0, sizeof addr);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = gsocket->net.addr;
	addr.sin_port = gsocket->net.port;
	errno = 0;
	ret = connect(sox->fd, (struct sockaddr *)&addr, sizeof addr);
	// DEBUGF("connect(%s:%d, fd = %d): %d (errno = %d, %s)\n", int_ntoa(gsocket->net.addr), ntohs(addr.sin_port), sox->fd, ret, errno, strerror(errno));
	if (ret != 0)
	{
		if ((errno == EINPROGRESS) || (errno == EAGAIN) || (errno == EINTR))
		{
			XFD_SET(sox->fd, gsocket->ctx->wfd);
			sox->state = GS_STATE_SYS_CONNECT;

			return GS_ERR_WAITING;
		}
		if (errno != EISCONN)
		{
			/* HERE: NOT connected */
			if (gsocket->ctx->socks_ip == 0)
			{
				// GS_LOG_ERR("connect(%s:%d): %s.\n", int_ntoa(gsocket->net.addr), ntohs(gsocket->net.port), strerror(errno));
				gs_set_error(gsocket->ctx, "connect(%s:%d)", int_ntoa(gsocket->net.addr), ntohs(gsocket->net.port));
			} else {
				// GS_LOG_ERR("connect(%s:%d): %s. Tor not running?\n", int_ntoa(gsocket->net.addr), ntohs(gsocket->net.port), strerror(errno));
				gs_set_error(gsocket->ctx, "connect(%s:%d). Tor not running?", int_ntoa(gsocket->net.addr), ntohs(gsocket->net.port));
			}
			return GS_ERR_FATAL;
		}
	}
	/* HERRE: ret == 0 or errno == EISCONN (Socket is already connected) */
	DEBUGF("connect(fd = %d) SUCCESS (errno = %d)\n", sox->fd, errno);
	FD_CLR(sox->fd, gsocket->ctx->wfd);
	XFD_SET(sox->fd, gsocket->ctx->rfd);

	/* SUCCESSFULLY connected */
	sox->state = GS_STATE_SYS_NONE;		// Not stuck in a system call (connect())
	gsocket->net.conn_count += 1;

	if (gsocket->ctx->socks_ip != 0)
	{
		GS_LOG_VV("Connection to TOR established [%s:%d].\n", int_ntoa(gsocket->ctx->socks_ip), ntohs(gsocket->ctx->socks_port));
		gs_pkt_connect_socks(gsocket, sox);
	} else {
		gs_net_connect_complete(gsocket, sox);
	}

	return GS_SUCCESS;
}

/*
 * Return > 0 on success.
 * Return 0 if write would block.
 * Return -1 on error.
 */
static int
sox_write(struct gs_sox *sox, const void *data, size_t len)
{
	int ret;

	ret = write(sox->fd, data, len);
	if (ret == len)
	{
		return len;
	}
	if (ret > 0)
		ERREXIT("Fatal, partial write() should not happen.\n");

	if (errno != EAGAIN)
		return -1;

	/* EAGAIN */
	memcpy(sox->wbuf, data, len);
	sox->wlen = len;

	return 0;
}

static int
gs_pkt_connect_socks(GS *gs, struct gs_sox *sox)
{
	// Auth: 0x05 0x01 0x00
	// Conn: 0x05 0x01 0x00 0x03 [1-octet length] [domain name] [2-octet Port]
	char buf[512];
	char *ptr = &buf[0];

	memcpy(buf, "\x05\x01\x00" "\x05\x01\x00\x03", 7);
	ptr += 7;

	size_t hlen = strlen(gs->net.hostname);
	XASSERT(hlen <= 255, "hostname to long\n");

	ptr[0] = hlen;
	ptr++;

	memcpy(ptr, gs->net.hostname, hlen);
	ptr += hlen;

	memcpy(ptr, &gs->ctx->gs_port, 2);
	ptr += 2;

	int ret;
	ret = sox_write(sox, &buf, ptr - buf);
	if (ret == 0)
		sox->state = GS_STATE_SOCKS;	// Call write() again

	sox->flags |= GS_SOX_FL_AWAITING_SOCKS;

	return 0;
}

static int
gs_pkt_ping_write(GS *gsocket, struct gs_sox *sox)
{
	int ret;

	DEBUGF("### PKT PING write(fd = %d)\n", sox->fd);
	// Might be 0 if SSL has not completed yet
	if (sox->fd < 0)
		return 0;

	/* Do not send PING if there is already data in output queue */
	if (FD_ISSET(sox->fd, gsocket->ctx->wfd))
	{
		DEBUGF("skip PING. WANT_WRITE already set.\n");
		return 0;
	}

	struct _gs_ping gping;
	memset(&gping, 0, sizeof gping);
	gping.type = GS_PKT_TYPE_PING; 

	ret = sox_write(sox, &gping, sizeof gping);
	if (ret == 0)
		sox->state = GS_STATE_PKT_PING;

	/* write() will eventually complete.
	 * As soon as rfd is ready we are expecting a PONG
	 */
	sox->flags |= GS_SOX_FL_AWAITING_PONG;

	return 0;
}

static int
gs_pkt_listen_write(GS *gsocket, struct gs_sox *sox)
{
	int ret;

	DEBUGF("### PKT LISTEN write(fd = %d)\n", sox->fd);
	if (gsocket->flags & GS_FL_IS_CLIENT)
		ERREXIT("CC trying to send a listen message. Should send connect.\n");

	struct _gs_listen glisten;
	memset(&glisten, 0, sizeof glisten);
	glisten.type = GS_PKT_TYPE_LISTEN;
	glisten.version_major = GS_PKT_PROTO_VERSION_MAJOR;
	glisten.version_minor = GS_PKT_PROTO_VERSION_MINOR;

	memcpy(glisten.token, gsocket->token, sizeof glisten.token);
	memcpy(glisten.addr, gsocket->gs_addr.addr, MIN(sizeof glisten.addr, GS_ADDR_SIZE));
	HEXDUMP(glisten.addr, sizeof glisten.addr);

	ret = sox_write(sox, &glisten, sizeof glisten);
	if (ret == 0)
		sox->state = GS_STATE_PKT_LISTEN;

	return 0;
}

static int
gs_pkt_connect_write(GS *gsocket, struct gs_sox *sox)
{
	int ret;
	DEBUGF("pkt_connect_write(fd = %d)\n", sox->fd);

	struct _gs_connect gconnect;
	memset(&gconnect, 0, sizeof gconnect);
	gconnect.type = GS_PKT_TYPE_CONNECT;
	gconnect.version_major = GS_PKT_PROTO_VERSION_MAJOR;
	gconnect.version_minor = GS_PKT_PROTO_VERSION_MINOR;
	gconnect.flags = gsocket->ctx->flags_proto;
	DEBUGF_Y("Proto Flags: %x\n", gconnect.flags);

	memcpy(gconnect.addr, gsocket->gs_addr.addr, MIN(sizeof gconnect.addr, GS_ADDR_SIZE));

	ret = sox_write(sox, &gconnect, sizeof gconnect);
	if (ret == 0)
		sox->state = GS_STATE_PKT_CONNECT;

	return 0;
}

static int
gs_pkt_accept_write(GS *gsocket, struct gs_sox *sox)
{
	int ret;

	struct _gs_accept gaccept;
	memset(&gaccept, 0, sizeof gaccept);
	gaccept.type = GS_PKT_TYPE_ACCEPT;

	ret = sox_write(sox, &gaccept, sizeof gaccept);
	if (ret == 0)
		sox->state = GS_STATE_PKT_ACCEPT; 

	return 0;
}

/*
 * Process a GS protocol message.
 */
static int
gs_pkt_dispatch(GS *gsocket, struct gs_sox *sox)
{
	if (sox->rbuf[0] == GS_PKT_TYPE_PONG)
	{
		DEBUGF("PONG received\n");
		sox->flags &= ~GS_SOX_FL_AWAITING_PONG;
		return GS_SUCCESS;
	}

	if (sox->rbuf[0] == GS_PKT_TYPE_START)
	{
		/* Called by CLIENT and SERVER. Thereafter it's up to the application
		 * layer.
		 */
		struct _gs_start *start = (struct _gs_start *)sox->rbuf;
		DEBUGF("START received. (flags = 0x%2.2x)\n", start->flags);
		if (start->flags & GS_FL_PROTO_START_SERVER)
		{
			DEBUGF_Y("This is SERVER\n");
			gsocket->flags |= GS_FL_IS_SERVER;
		}
		sox->state = GS_STATE_APP_CONNECTED;
		gettimeofday(gsocket->ctx->tv_now, NULL);
		memcpy(&gsocket->tv_connected, gsocket->ctx->tv_now, sizeof gsocket->tv_connected);
		/* Indicate to caller that a new GS connection has started */
		gsocket->net.fd_accepted = sox->fd;

		gs_pkt_accept_write(gsocket, sox);
		return GS_SUCCESS;
	}

	char msg[128];
	if (sox->rbuf[0] == GS_PKT_TYPE_STATUS)
	{
		struct _gs_status *status = (struct _gs_status *)sox->rbuf;
		DEBUGF("STATUS received. (type=%d, code=%d)\n", status->err_type, status->code);
		if (status->err_type == GS_STATUS_TYPE_FATAL)
		{
			const char *err_str = "FATAL";	// *Unknown* default
			switch (status->code)
			{
				case GS_STATUS_CODE_BAD_AUTH:
					err_str = "Address already in use";
					break;
				case GS_STATUS_CODE_CONNREFUSED:
					err_str = "Connection refused (no server listening)";
					break;
				case GS_STATUS_CODE_IDLE_TIMEOUT:
					err_str = "Idle-Timeout. Server did not receive any data";
					break;
				case GS_STATUS_CODE_SERVER_OK:
					err_str = "Server is listening.";
					break;
				default:
					err_str = "UNKNOWN";
					GS_sanitize_logmsg(msg, sizeof msg, (char *)status->msg, sizeof status->msg);
					if (msg[0] != '\0')
						err_str = msg;
					break;
			}
			gsocket->status_code = status->code;
			gs_set_errorf(gsocket, "%s (%u)", err_str, status->code);
			return GS_ERR_FATAL;
		}
		return GS_SUCCESS;
	}

	DEBUGF("Invalid Packet Type %d - Ignoring..\n", sox->rbuf[0]);

	return GS_SUCCESS;
}

/*
 * Return length of bytes read, 0 for waiting and otherwise ERROR
 * (treat EOF as GS_ERROR (and eventually reconnect if this is a listening socket)
 */
static ssize_t
sox_read(struct gs_sox *sox, size_t len)
{
	ssize_t ret;

	ret = read(sox->fd, sox->rbuf + sox->rlen, len);
	if (ret == 0)	/* EOF */
	{
		/* HERE: GS-NET can not find a listening peer for this GS-addres.
		 * Disconnect hard.
		 */
		DEBUGF_R("EOF on GS TCP connection -> treat as ECONNRESET\n");
		errno = ECONNRESET;
		return GS_ERROR;	// ERROR
	}
	if (ret < 0)
	{
		/* This can happen when we read packets. We read 1 byte and
		 * then without going into select() we try to read the rest
		 * of the packet.
		 */
		if ((errno == EAGAIN) || (errno == EINTR))
		{
#ifdef DEBUG
			gs_fds_out_fd(gs_debug_rfd, 'r', sox->fd);
			gs_fds_out_fd(gs_debug_r, 'R', sox->fd);
#endif
			DEBUGF_R("EAGAIN [would block], wanting %zd\n", len);
			return 0;	// Waiting. No data read.
		}
		return GS_ERROR;
	}

	sox->rlen += ret;

	return ret;	// Return the number of bytes read.
}

/*
 * Read at least 'min' bytes or return error if waiting.
 * Return min on SUCCESS (min bytes available in buffer)
 * Return GS_ERR_WAITING when waiting for more data.
 * Return GS_ERROR on error (recoverable. re-connect)
 * Return GS_ERR_FATAL on non-recoverable errors (never?)
 */
static ssize_t
sox_read_min(struct gs_sox *sox, size_t min)
{
	size_t len_rem;
	int ret;

	XASSERT(sox->rlen < min, "Data in buffer is %zu but only needing %zu\n", sox->rlen, min);

	len_rem = min - sox->rlen;
	ret = sox_read(sox, len_rem);
	if (ret == GS_ERROR)
		return GS_ERROR;
	if (ret == GS_ERR_FATAL)
		return GS_ERR_FATAL;	// never happens

	if (sox->rlen < min)
		return GS_ERR_WAITING;

	/* Not enough data */
	return min;
}

static int
gs_read_pkt(GS *gs, struct gs_sox *sox)
{
	int ret;
	/* Read GS message. */
	/* Read GS MSG header (first octet) */
	if (sox->rlen == 0)
	{
		ret = sox_read(sox, 1);
		if (ret != 1)
			return GS_ERROR;
	}

	size_t len_pkt = sizeof (struct _gs_pong);
	/* Client only allowed to receive START, STATUS and PONG */
	switch (sox->rbuf[0])
	{
		case GS_PKT_TYPE_PONG:
		case GS_PKT_TYPE_START:
		case GS_PKT_TYPE_STATUS:
			break;
		case GS_PKT_TYPE_LISTEN:
		case GS_PKT_TYPE_CONNECT:
			len_pkt = sizeof (struct _gs_listen);
		case GS_PKT_TYPE_PING:
		default:
			DEBUGF_R("Packet type=%d not valid (for client)\n", sox->rbuf[0]);
	}

	ret = sox_read_min(sox, len_pkt);
	if (ret == GS_ERR_WAITING)
		return GS_SUCCESS;	// Not enough data yet
	if (ret != len_pkt)
		return GS_ERROR;	// ERROR

	ret = gs_pkt_dispatch(gs, sox);
	sox->rlen = 0;

	return ret;
}

/* Accept Auth: 0x05 0x00
 * Success    : 0x05 0x00 0x00 0x01 [IP 4bytes] [PORT 2bytes]
 */
struct _socks5_pkt
{
	uint8_t ver;
	uint8_t res;
	uint8_t ver2;
	uint8_t code;
	uint8_t res2;
	uint8_t ip_type;
	uint8_t ip[4];
	uint8_t port[2];
};

/*
 * Read reply from Socks5 and 'dispatch' (change state when done or -1 on error).
 */
static int
gs_read_socks(GS *gs, struct gs_sox *sox)
{
	int ret;
	struct _socks5_pkt spkt;

	size_t len_pkt = sizeof (struct _socks5_pkt);

	ret = sox_read_min(sox, len_pkt);
	if (ret == GS_ERR_WAITING)
		return GS_SUCCESS;
	if (ret != len_pkt)
		return GS_ERROR;

	// HEXDUMPF(sox->rbuf, len_pkt, "Socks5 (%zu): ", len_pkt);
	memcpy(&spkt, sox->rbuf, sizeof spkt);
	if (spkt.code != 0)
		return GS_ERROR;

	DEBUGF_M("Socks5 CONNECTED\n");
	/* Socks5 completed. Start GS listen/connect */
	sox->flags &= ~GS_SOX_FL_AWAITING_SOCKS;
	gs_net_connect_complete(gs, sox);

	sox->rlen = 0;

	return GS_SUCCESS;
}

/*
 * Socket has something to read() or write()
 * Return 0 on success.
 */
static int
gs_process_by_sox(GS *gsocket, struct gs_sox *sox)
{
	int ret;
	GS_CTX *gs_ctx = gsocket->ctx;

	errno = 0;
	if (FD_ISSET(sox->fd, gs_ctx->w))
	{
		DEBUGF("fd == %d\n", sox->fd);
		if (sox->state == GS_STATE_SYS_CONNECT)
		{
			ret = gs_net_connect_by_sox(gsocket, sox);
			if (ret != GS_SUCCESS)
			{
				DEBUGF_R("will ret = %d, errno %s\n", ret, strerror(errno));
				gsocket->status_code = GS_STATUS_CODE_NETERROR;
				return GS_ERROR;	/* ECONNREFUSED or other */
			}

			DEBUGF("GS-NET Connection (TCP) ESTABLISHED (fd = %d)\n", sox->fd);
			/* rfd is set in gs_net_connect_by_sox */
			gs_fds_out_fd(gsocket->ctx->rfd, 'r', sox->fd);
			gs_fds_out_fd(gsocket->ctx->wfd, 'w', sox->fd);
			return GS_SUCCESS;
		}

		/* Complete a failed write() */
		if ((sox->state == GS_STATE_PKT_PING) || (sox->state == GS_STATE_PKT_LISTEN) || (sox->state == GS_STATE_SOCKS))
		{
			ret = write(sox->fd, sox->wbuf, sox->wlen);
			if (ret != sox->wlen)
			{
				DEBUGF("ret = %d, len = %zu, errno = %s\n", ret, sox->wlen, strerror(errno));
				return GS_ERROR;
			}
			FD_CLR(sox->fd, gs_ctx->wfd);
			XFD_SET(sox->fd, gs_ctx->rfd);
			sox->state = GS_STATE_SYS_NONE;

			return GS_SUCCESS;
		}

		/* write() data still in output buffer */
		DEBUGF("Oops. WFD ready but not in SYS_CONNECT or PKT_PING? (fd = %d, state = %d)\n", sox->fd, sox->state);
		return GS_ERR_FATAL;
	} /* gs_ctx->w was set */

	/* HERE: rfd is set - ready to read */
	DEBUGF_M("rfd is set (state == %d)\n", sox->state);
	if (sox->flags & GS_SOX_FL_AWAITING_SOCKS)
	{
		ret = gs_read_socks(gsocket, sox);
	} else {
		ret = gs_read_pkt(gsocket, sox);
	}

	return ret;
}

/*
 * Call every second to take care of house-keeping and keep
 * alive messages.
 */
void
GS_heartbeat(GS *gsocket)
{
	int i;

	if (gsocket == NULL)
		return;
	if (gsocket->fd >= 0)
		return;

	/* Check if it is time to send a PING to keep the connection alive */
	for (i = 0; i < gsocket->net.n_sox; i++)
	{
		struct gs_sox *sox = &gsocket->net.sox[i];

		XASSERT(sox->state != GS_STATE_APP_CONNECTED, "fd = %d but APP already CONNECTED state\n", gsocket->fd);

		// Skip if busy with connect() systemcall.
		if (sox->state == GS_STATE_SYS_CONNECT)
		{
			if (GS_TV_TO_USEC(gsocket->ctx->tv_now) < gsocket->net.tv_connect + GS_SEC_TO_USEC(GS_WARN_SLOWCONNECT))
				continue;

			if (sox->flags & GS_SOX_FL_WARN_SLOWCONNECT)
				continue;

			// Warning if connection takes longer than expected...
			sox->flags |= GS_SOX_FL_WARN_SLOWCONNECT;
			GS_LOG("Connecting to GSRN [%s:%d] takes longer than expected. Still trying...\n", int_ntoa(gsocket->net.addr), ntohs(gsocket->net.port));

			continue;
		}

		// Skip if 'want-write' is already set. We are already trying to write data.
		// fd is -1 if connect() failed
		if ((sox->fd >= 0) && (FD_ISSET(sox->fd, gsocket->ctx->wfd)))
			continue;

		/* Skip if outstanding PONG..*/
		if (sox->flags & GS_SOX_FL_AWAITING_PONG)
			continue;

		XASSERT(sox->state != GS_STATE_PKT_ACCEPT, "APP_CONNECTED == false _and_ state == ACCEPT\n");

		if (sox->state == GS_STATE_SYS_RECONNECT)
		{
			gs_net_try_reconnect_by_sox(gsocket, sox);
			continue;
		}

		if (sox->state == GS_STATE_SYS_NONE)
		{
			uint64_t tv_diff = GS_TV_DIFF(&sox->tv_last_data, gsocket->ctx->tv_now);
			// DEBUGF("diff = %llu\n", tv_diff);
			if (tv_diff > GS_SEC_TO_USEC(GSRN_DEFAULT_PING_INTERVAL))
			{
				gs_pkt_ping_write(gsocket, sox);
				memcpy(&sox->tv_last_data, gsocket->ctx->tv_now, sizeof sox->tv_last_data);
			}
			continue;
		}
		ERREXIT("NOT REACHED\n");
	}
}

static void
gs_net_reconnect_by_sox(GS *gs, struct gs_sox *sox)
{
	gs_net_connect_new_socket(gs, sox);
	/* FIXME: if a connect() call succeeds and this gsocket has more
	 * than 1 'listen' TCP connections trying to connect() then we could
	 * trigger a re-connect on all sox which are in state GS_STATE_SYS_RECONNECT
	 * immediately without having to wait for RECONNECT_DELAY.
	 */
}


/*
 * Try to connect() again or if this is to soon since the failed attempt then
 * wait and let GS_heartbeat() wake us up when it is time.
 */
static void
gs_net_try_reconnect_by_sox(GS *gs, struct gs_sox *sox)
{
	sox->state = GS_STATE_SYS_RECONNECT;

	if (GS_TV_TO_USEC(gs->ctx->tv_now) <= gs->net.tv_connect + GS_SEC_TO_USEC(GS_RECONNECT_DELAY))
	{
		DEBUGF_M("To many connect() attempts. Heartbeat will wake us later...\n");
		return;
	}
	/* Ignore return value. If this fails then ignorning return value means
	 * we will re-use old IP (which is what we want).
	 */
	/* Only update IP from hostname like every 12h or so (this should never change) */
	if (GS_TV_TO_USEC(gs->ctx->tv_now) > gs->net.tv_gs_hton + GS_SEC_TO_USEC(GS_GS_HTON_DELAY))
	{
		if (gs->net.hostname != NULL)
		{
			DEBUGF_Y("Newly resolving %s\n", gs->net.hostname);
			gs_set_ip_by_hostname(gs, gs->net.hostname);
		}
	}

	gs_net_reconnect_by_sox(gs, sox);
}

/*
 * Only called while APP is not yet connected and managing GS-packets.
 * Check "fd_accepted" for any fd that can be passed to app-layer.
 *
 * Return 0 on success.
 */
static int
gs_process(GS *gsocket)
{
	int ret;
	int i;

	if (gsocket->fd >= 0)
	{
		DEBUGF("*** WARNING ***: No more GS-Net messages after accept please..\n");
		ERREXIT("Should not happen\n");
		return GS_ERR_FATAL;	// NOT REACHED
	}

	for (i = 0; i < gsocket->net.n_sox; i++)
	{
		struct gs_sox *sox = &gsocket->net.sox[i];
		/* No PING/PONG (KeepAlive) and no further processing of any
		 * GS Protocol messages once the GS-SOCKET is connected.
		 * Instead forward all read() data to application via GS_read().
		 */
		if (sox->state == GS_STATE_APP_CONNECTED)
		{
			ERREXIT("Should not happen\n");	/* GS is disengaged from GS-Net..*/
			continue;
		}

		if (FD_ISSET(sox->fd, gsocket->ctx->r) || FD_ISSET(sox->fd, gsocket->ctx->w))
		{
			ret = gs_process_by_sox(gsocket, sox);
			DEBUGF("gs_process_by_sox() = %d\n", ret);
			if (ret == GS_ERROR)
			{
				/* GS_connect() shall not auto reconnect */
				if (!(gsocket->flags & GS_FL_AUTO_RECONNECT))
					return GS_ERR_FATAL;

				/* HERE: Auto-Reconnect. Failed in connect() or write(). */
				DEBUGF_M("GS-NET error. Re-connecting...\n");
				GS_LOG_ERR("%s GSRN %s. Re-connecting to %s:%d...\n", GS_logtime(), strerror(errno), int_ntoa(gsocket->net.addr), ntohs(gsocket->net.port));
				close(sox->fd);
				gs_net_init_by_sox(gsocket->ctx, sox);
				gs_net_try_reconnect_by_sox(gsocket, sox);
				continue;
			}
			if (ret != GS_SUCCESS)
			{
				DEBUGF_R("FATAL errno(%d) = %s\n", errno, strerror(errno));
				return GS_ERR_FATAL;
			}

			// HERE: connect() succeeded 
			memcpy(&sox->tv_last_data, gsocket->ctx->tv_now, sizeof sox->tv_last_data);
			/* Immediatly let app know that a new gs-connection has been accepted */
			if (gsocket->net.fd_accepted >= 0)
				break;
			/* We must CLEAR currently processed fd. Otherwise it can happen
			 * that another fd of this listening socket is also ready for r/w
			 * and we would process _this_ fd again (it's a sequential for-loop
			 * over all fd's of a listening gsocket.
			 */
			FD_CLR(sox->fd, gsocket->ctx->r);
			FD_CLR(sox->fd, gsocket->ctx->w);
			/* 'break' here. The calling function's 'select' loop will call us again.
			 * Otherwise the 'n = select()' counter will be off (if we process multiple
			 * fd's at once without n-- the counter.
			 */
			// break;
		}

	}

	DEBUGF("Returning 0 (fd_accepted == %d)\n", gsocket->net.fd_accepted);
	return 0;
}

int
GS_get_fd(GS *gsocket)
{
	/* If socket is connected already (APP layer) */
	if (gsocket->fd >= 0)
		return gsocket->fd;

	/* Connecting socket.
	 * Note: We may accidentially return a Accepting-socket here
	 * which is bad (GS_get_fd() is only valid on connecting
	 * or established socket but not on accpepting sockets (because
	 * accepting sockets operate on an array of accepting sockets rather
	 * than a single socket.
  	 */
	if (gsocket->net.n_sox > 1)
		return -1;

	return gsocket->net.sox[0].fd;
}


/*
 * Return 0 on success.
 * Called from gs_net_connect
 */
static int
gs_net_new_socket(GS *gsocket, struct gs_sox *sox)
{
	int s;
	int ret;

	gsocket->flags |= GS_FL_CALLED_NET_NEW_SOCKET;

	s = socket(PF_INET, SOCK_STREAM, 0);
	DEBUGF_W("socket() == %d (LIB)\n", s);
	if (s < 0)
		return -1;

	ret = fcntl(s, F_SETFL, O_NONBLOCK | fcntl(s, F_GETFL, 0));
	if (ret != 0)
		return -1;

	gsocket->ctx->max_sox = MAX(s, gsocket->ctx->max_sox);
	sox->fd = s;

	return 0;
}

/*
 * Create a new socket and connect to GS-NET.
 */
static int
gs_net_connect_new_socket(GS *gs, struct gs_sox *sox)
{
	int ret;

	/*
	 * If we use the GS_select() subsystem:
	 * After GS_accept() a new TCP connection is established to
	 * the GS-NET. We must track the new fd of that new TCP connection
	 * with GS_select(). Here: Find out the call-back for original listening
	 * socket and assign it to new TCP connection (GS-NET).
	 */
	/* GS_select-HACK-1-START */
	gselect_cb_t func;
	int cb_val;
	func = gs->ctx->func_listen;
	cb_val = gs->ctx->cb_val_listen;
	GS_SELECT_CTX *gselect_ctx = gs->ctx->gselect_ctx;
	/* GS_select_HACK-1-END */

	DEBUGF("gs_net_connect called (GS_select() cb_func = %p\n", func);

	if (sox->fd < 0)
	{
		// HERE: socket() does not exist yet. Create it.
		ret = gs_net_new_socket(gs, sox);
		if (ret != GS_SUCCESS)
			return GS_ERROR;
	}

	gs->net.tv_connect = GS_TV_TO_USEC(gs->ctx->tv_now);

	// The calling process expects a socket to be created here regardless
	// if IP is known. Thus we create a socket but only call 'connect()' once
	// IP is known (e.g. domain name resolves).
	if (gs->net.addr == 0)
	{
		// IP address failed to resolve.
		// Go into reconnect state. Heartbeat complete the connect()...
		if (sox->state == GS_STATE_SYS_RECONNECT)
			return GS_SUCCESS; // return immediately if this is already a reconnect
		sox->state = GS_STATE_SYS_RECONNECT;
	} else {
		GS_LOG_VV("Connecting to %s:%d...\n", int_ntoa(gs->net.addr), ntohs(gs->net.port));

		/* Connect TCP */
		ret = gs_net_connect_by_sox(gs, sox);
		DEBUGF("gs_net_connect_by_sox(fd = %d): %d, %s\n", sox->fd, ret, strerror(errno));
		if (ret == GS_ERR_FATAL)
			ERREXIT("%s\n", GS_CTX_strerror(gs->ctx));
	}

	/* GS_select-HACK-1-START */
	if (gs->ctx->gselect_ctx != NULL)
	{
		DEBUGF_B("Using GS_select() with new fd = %d, func = %p\n", sox->fd, func);
		/* HERE: We are using GS_select(). Track new fd. */
		gs_listen_add_gs_select_by_sox(gselect_ctx, func, sox->fd, gs, cb_val);
	}
	/* GS_select-HACK-1-END */

	return GS_SUCCESS;
}

/*
 * Connect to the GS-NET (non-blocking). 
 * Return 0 on success.
 * Return -1 on fatal error (must exist).
 */
static int
gs_net_connect(GS *gsocket)
{
	int ret;
	int i;
	GS_CTX *gs_ctx;

	if (gsocket == NULL)
		return -1;

	gs_ctx = gsocket->ctx;

	if (gs_ctx == NULL)
		return -1;

	if (gsocket->flags & GS_FL_TCP_CONNECTED)
		return 0;	/* Already connected */

	for (i = 0; i < gsocket->net.n_sox; i++)
	{
		struct gs_sox *sox = &gsocket->net.sox[i];

		ret = gs_net_connect_new_socket(gsocket, sox);

		if (ret != GS_SUCCESS)
			return ret;
	}	/* FOR loop over all sockets */

	return 0;
}

static void
gs_net_init_by_sox(GS_CTX *ctx, struct gs_sox *sox)
{
	XFD_CLR(sox->fd, ctx->wfd);
	XFD_CLR(sox->fd, ctx->rfd);
	memset(sox, 0, sizeof *sox);
	sox->fd = -1;
}

static void
gs_net_init(GS *gsocket, int backlog)
{
	int i;

	backlog = MIN(backlog, GS_MAX_SOX_BACKLOG);
	gsocket->net.n_sox = backlog;
	for (i = 0; i < gsocket->net.n_sox; i++)
	{
		gs_net_init_by_sox(gsocket->ctx, &gsocket->net.sox[i]);
	}
}

/*
 * Free fd from GS-NET structure and pass to application layer.
 * Return 0 on success.
 *
 * This function is called by GS_accept() and GS_connect()
 * GS_connect() is gsocket == new_gs because the same GS is used
 * whereas for GS_accept() the gsocket is the listening socket (that will
 * continue to listen) and new_gs is a newly created GS.
 */
static int
gs_net_disengage_tcp_fd(GS *gsocket, GS *new_gs)
{
	int i;
	int new_fd = -1;

	for (i = 0; i < gsocket->net.n_sox; i++)
	{
		struct gs_sox * sox = &gsocket->net.sox[i];

		if (sox->fd != gsocket->net.fd_accepted)
			continue;
		
		/*
		 * Return GS-connected socket fd to app (and stop processing any PKT on that fd...).
		 */
		new_fd = gsocket->net.fd_accepted;

		gsocket->net.fd_accepted = -1;
		gsocket->flags &= ~GS_FL_TCP_CONNECTED;
		gsocket->net.conn_count -= 1;
		if (gsocket->net.conn_count < 0)
			ERREXIT("FATAL: conn_count dropped to %d\n", gsocket->net.conn_count);
		sox->state = GS_STATE_SYS_NONE;
		sox->fd = -1;

		gs_instantiate(gsocket, new_gs, new_fd);

		return 0;
	}

	DEBUGF("*** WARNING ***: Can This happen???\n");
	return -2;
}

/*
 * non-blocking.
 * Return -1 for waiting.
 * Return -2 on error
 * Return 0 on success.
 */
static int
gs_connect(GS *gsocket)
{
	int ret;
	DEBUGF("gs_connect(fd = %d)\n", gsocket->fd);
	/* Connect to GS-NET if not already connected */
	if (!(gsocket->flags & GS_FL_CALLED_NET_CONNECT))
	{
		gsocket->flags |= GS_FL_CALLED_NET_CONNECT;
		gsocket->flags |= GS_FL_IS_CLIENT;
		gs_net_init(gsocket, 1);
		DEBUGF("Connecting to GS-Net...\n");
		ret = gs_net_connect(gsocket);
		DEBUGF("gs_net_connect() = %d\n", ret);
		if (ret != 0)
			return GS_ERR_FATAL;

		return GS_ERR_WAITING;
	}

	ret = gs_process(gsocket);
	DEBUGF("gs_process() = %d, error(%d) = %s\n", ret, errno, errno?strerror(errno):"");
	if (ret != 0)
		return GS_ERR_FATAL;

	if (gsocket->net.fd_accepted >= 0)
	{
		DEBUGF_B("New GS connection SUCCESS (fd = %d)\n", gsocket->net.fd_accepted);
		/* On connect() we do not create a new socket but assign existing
		 * tcp-socket to this connection.
		 */
		ret = gs_net_disengage_tcp_fd(gsocket, gsocket);

		if (ret != 0)
			return GS_ERR_FATAL;

		return 0;
	}

	return GS_ERR_WAITING;
}

/*
 * Return 0 on success.
 */
static int
gs_connect_blocking(GS *gsocket)
{
	int ret;
	int n;

	ret = gs_connect(gsocket);
	GS_CTX *ctx = gsocket->ctx;
	while (1)
	{

		struct timeval tv = {1, 0};
		// FIXME: there could be many other fd's set here from other CTX. We really
		// should only set our fd's from this gsocket (either ->fd or ->gs_net).
		memcpy(ctx->r, ctx->rfd, sizeof *ctx->r);
		memcpy(ctx->w, ctx->wfd, sizeof *ctx->w);
		n = select(gsocket->ctx->max_sox + 1, ctx->r, ctx->w, NULL, &tv);
		if ((n < 0) && (errno == EINTR))
			continue;
		gettimeofday(gsocket->ctx->tv_now, NULL);
		GS_heartbeat(gsocket);
		if (n == 0)
			continue;

		ret = gs_connect(gsocket);
		DEBUGF("gs_connect() = %d, gsocket->fd = %d\n", ret, gsocket->fd);
		if (ret == GS_ERR_WAITING)
			continue;
		if (ret == GS_ERR_FATAL)
			return GS_ERR_FATAL;
		
		DEBUGF("Setting FD BLOCKING\n");
		int tcp_fd = gsocket->fd;
		/* Make tcp fd 'blocking' for caller. */
		fcntl(tcp_fd, F_SETFL, ~O_NONBLOCK & fcntl(tcp_fd, F_GETFL, 0));

		return ret;
	}

	ERREXIT("Oops. This should not happen\n");
	return GS_ERR_FATAL;
}

/*
 * Return 0 on success.
 * Return -1 if still waiting for connection to be established.
 * Return -2 on error.
 */
int
GS_connect(GS *gsocket)
{
	int ret;

	DEBUG_SETID(gsocket);

	if (gsocket->net.fd_accepted >= 0)
	{
		/* This GS-socket is already connected.... */
		errno = EBUSY;
		return GS_ERR_FATAL;
	}

	/* For auto-reconnecting client side (is it needed?) consider:
	 * - How to handle when no listening server is available
	 * - Warn user if GSRN is unavailable.
	 */
	// gsocket->flags |= GS_FL_AUTO_RECONNECT;
	if (gsocket->flags & GSC_FL_NONBLOCKING)
		ret = gs_connect(gsocket);
	else
		ret = gs_connect_blocking(gsocket);

	if (ret < 0)
	{
		DEBUGF("GS_connect() will ret = %d (%s)\n", ret, ret==GS_ERR_WAITING?"WAITING":"FATAL");
		return ret;
	}

#ifdef WITH_GSOCKET_SSL
	if (gsocket->flags & GSC_FL_USE_SRP)
	{
		ret = gs_srp_init(gsocket);
		if (ret >= 0)
			ret = 0;	/* SUCCESS */
	}
#endif

	return ret;
}

/*
 * Return 0 on success. This can not fail.
 */
int
GS_listen(GS *gsocket, int backlog)
{
	DEBUG_SETID(gsocket);

	gsocket->flags |= GS_FL_AUTO_RECONNECT;
	gs_net_init(gsocket, backlog);
	gs_net_connect(gsocket);

	return 0;
}

static void
gs_listen_add_gs_select_by_sox(GS_SELECT_CTX *ctx, gselect_cb_t func, int fd, void *arg, int val)
{
	/* There might be some PING/PONG keepalive going on. Set both RW-fds
	 * and let GS_accept() figure it out.
	 * WARNING: If you change this also look for GS_select-HACK-1
	 */
	GS_SELECT_add_cb_r(ctx, func, fd, arg, val);
	GS_SELECT_add_cb_w(ctx, func, fd, arg, val);
}

/*
 * Helper function to set all fd's that the listening gsocket
 * is using for calling accept() on. Listening gsocket's
 * listen on more than just 1 fd to allow for gs-peers to connect
 * rapidly. There usually is only 1 listening gsocket per process.
 */
void
GS_listen_add_gs_select(GS *gs, GS_SELECT_CTX *ctx, gselect_cb_t func, void *arg, int val)
{
	gs->ctx->func_listen = func;
	gs->ctx->cb_val_listen = val;

	int i;
	for (i = 0; i < gs->net.n_sox; i++)
	{
		int fd = gs->net.sox[i].fd;
		gs_listen_add_gs_select_by_sox(ctx, func, fd, arg, val);
	}
}

/*
 * Return a GS on accept or NULL if still waiting.
 */
/*
 * Return -1 on waiting
 * Return -2 on fatal
 * Return 0 on success.
 */
static int
gs_accept(GS *gsocket, GS *new_gs)
{
	int ret;

	DEBUGF("Called gs_accept(%p, %p)\n", gsocket, new_gs);
	ret = gs_process(gsocket);
	if (ret != 0)
	{
		DEBUGF("ERROR: in gs_process(), ret = %d\n", ret);
		return GS_ERR_FATAL;
	}

	/* Check if there is a new gs-connection waiting */
	if (gsocket->net.fd_accepted >= 0)
	{
		DEBUGF("New GS Connection accepted (fd = %d, n_sox = %d)\n", gsocket->net.fd_accepted, gsocket->net.n_sox);

		ret = gs_net_disengage_tcp_fd(gsocket, new_gs);
		XASSERT(ret == 0, "ret = %d\n", ret);

		if (!(gsocket->flags & GS_FL_SINGLE_SHOT))
		{
			/* Start new TCP to GS-Net to listen for more incoming connections */
			gs_net_connect(gsocket);
		}

		return GS_SUCCESS;
	}

	return GS_ERR_WAITING; /* Waiting for socket */
}

/*
 * Return -1 on waiting
 * Return -2 on fatal
 * Return 0 on success.
 */
int
gs_accept_blocking(GS *gsocket, GS *new_gs)
{
	int ret;
	int n;

	while (1)
	{
		struct timeval tv = {1, 0};
		memcpy(gsocket->ctx->r, gsocket->ctx->rfd, sizeof *gsocket->ctx->r);
		memcpy(gsocket->ctx->w, gsocket->ctx->wfd, sizeof *gsocket->ctx->w);
		n = select(gsocket->ctx->max_sox + 1, gsocket->ctx->r, gsocket->ctx->w, NULL, &tv);
		if ((n < 0) && (errno == EINTR))
			continue;
		if (n < 0)
			DEBUGF_R("select(): %s\n", strerror(errno));
		gettimeofday(gsocket->ctx->tv_now, NULL);
		GS_heartbeat(gsocket);
		if (n == 0)
			continue;

		ret = gs_accept(gsocket, new_gs);
		if (ret == -2)
			return -2;
		if (ret == GS_ERR_WAITING)
			continue;

		/* Make tcp fd 'blocking' for caller. */
		fcntl(new_gs->fd, F_SETFL, ~O_NONBLOCK & fcntl(new_gs->fd, F_GETFL, 0));
		return 0;
	}

	ERREXIT("Oops. This should not happen\n");
	return -2;	/* NOT REACHED */
}

/*
 * Return NULL on Waiting
 * Return GS otherwise.
 *
 * This function can not return 'fatal' as any error such
 * as SRP failure is recoverable by this sub-system (by for example
 * opening a new connection and trying again).
 */
GS *
GS_accept(GS *gsocket, int *err)
{
	GS gs_tmp;
	int ret;

	DEBUG_SETID(gsocket);

	if (err != NULL)
		*err = 0;

	memset(&gs_tmp, 0, sizeof gs_tmp);
	if (gsocket->flags & GSC_FL_NONBLOCKING)
		ret = gs_accept(gsocket, &gs_tmp);
	else
		ret = gs_accept_blocking(gsocket, &gs_tmp);

	if (ret < 0)
	{
		if (err != NULL)
			*err = ret;
		return NULL;	/* WAITING or FATAL */
	}

	/* HERE: gs_accept() SUCCESS */
	/* Instantiate gs */
	GS *new_gs = calloc(1, sizeof *new_gs);
	XASSERT(new_gs != NULL, "calloc()\n");
	memcpy(new_gs, &gs_tmp, sizeof *new_gs);
	memcpy(&new_gs->tv_connected, gsocket->ctx->tv_now, sizeof new_gs->tv_connected);

	new_gs->flags |= GS_FL_IS_SERVER;
#ifdef WITH_GSOCKET_SSL
	if (new_gs->flags & GSC_FL_USE_SRP)
	{
		ret = gs_srp_init(new_gs);
		if (ret < 0)
		{
			DEBUGF("gs_srp_init() = %d (FAILED), Closing gs...\n", ret);
			gs_close(new_gs);	/* Free SSL and close socket */
			if (err != NULL)
				*err = -2;
			return NULL;
		}
	}
#endif

	/* All further will be handled by calls to GS_write() or GS_read() */

	return new_gs;
}

/*
 * as GS_close() but without call to free().
 */
static void
gs_close(GS *gsocket)
{
	XASSERT(gsocket != NULL, "gsocket == NULL\n");

	if (gsocket->fd >= 0)
	{
		DEBUGF_B("Closing I/O socket (fd = %d)\n", gsocket->fd);
		FD_CLR(gsocket->fd, gsocket->ctx->rfd);
		FD_CLR(gsocket->fd, gsocket->ctx->wfd);
		FD_CLR(gsocket->fd, gsocket->ctx->r);
		FD_CLR(gsocket->fd, gsocket->ctx->w);
		/* HERE: This was not listening socket */
		// shutdown(gsocket->fd, SHUT_WR);
		// sleep(1);
		// gsocket->fd = -1;
		XCLOSE(gsocket->fd);
		return;
	}

	/* HERE: There are GS-Net connections that need to be cleaned.*/
	int i;
	/* Close all TCP connections to GS-Network */
	DEBUGF_B("Closing %d GSN connections\n", gsocket->net.n_sox);
	for (i = 0; i < gsocket->net.n_sox; i++)
	{
		struct gs_sox * sox = &gsocket->net.sox[i];
		if (sox->fd < 0)
			continue;
		DEBUGF_B("Closing I/O socket (sox->fd = %d)\n", sox->fd);
		FD_CLR(sox->fd, gsocket->ctx->rfd);
		FD_CLR(sox->fd, gsocket->ctx->wfd);
		FD_CLR(sox->fd, gsocket->ctx->r);
		FD_CLR(sox->fd, gsocket->ctx->w);
		XCLOSE(sox->fd);
	}
	gsocket->net.n_sox = 0;

	return;
}

/*
 * Return 0 on success.
 * Return -2 on fatal error.
 */
int
GS_close(GS *gsocket)
{
	DEBUG_SETID(gsocket);

	DEBUGF_B("read: %"PRId64", written: %"PRId64"\n", gsocket->bytes_read, gsocket->bytes_written);
	if (gsocket == NULL)
		return -2;

#ifdef WITH_GSOCKET_SSL
	if (gsocket->flags & GSC_FL_USE_SRP)
	{
		if (gsocket->ssl != NULL)
		{
			DEBUGF_G("Calling SSL_free()\n");
			SSL_free(gsocket->ssl);
			gsocket->ssl = NULL;
		} else {
			DEBUGF_R("gs->ssl == NULL, This must be the listening socket.\n");
		}
	}
#endif
	gs_close(gsocket);
	memset(gsocket, 0, sizeof *gsocket);

	free(gsocket);

	return 0;
}

/*
 * Return ERR_WAITING if I/O needs attention (blocking) [Will Trigger CALL-AGAIN]
 * Return GS_SUCCESS if gsocket is still alive (for reading, but not writing)
 * Return ERR_FATAL if gsocket is DONE (destroy connection).
 * Return ERR_FATAL on fatal error (destroy connection).
 */
int
GS_shutdown(GS *gsocket)
{
	int ret;
	DEBUG_SETID(gsocket);

	if (gsocket->flags & GSC_FL_USE_SRP)
	{
		if (gsocket->ssl_state != GS_SSL_STATE_RW)
		{
			/* Return if the SSL is not yet connected. We can not shut down
			 * unless it's connected. Shutdown triggered after SRP completion.
			 */
			gsocket->is_want_shutdown = 1;
			return GS_SUCCESS;
		}
		ret = gs_ssl_shutdown(gsocket);
		return ret;
	} else {
		gsocket->is_sent_shutdown = 1;
		if (gsocket->eof_count >= 1)
			ret = shutdown(gsocket->fd, SHUT_RDWR);
		else
			ret = shutdown(gsocket->fd, SHUT_WR);
		DEBUGF_B("tcp shutdown() = %d, eof_count=%d\n", ret, gsocket->eof_count);
		if (gsocket->eof_count == 0)
			return GS_SUCCESS;
		return GS_ERR_FATAL;
	}

	return GS_ERR_FATAL;	/* NOT REACHED */
}

/*
 * Return error string (0-terminated).
 * Format: [<errno-str> - ]<Internal Error Buffer>[[SSL-Error string]]
 */
const char *
GS_CTX_strerror(GS_CTX *gs_ctx)
{
	char *dst = gs_ctx->err_buf2;
	int dlen = sizeof gs_ctx->err_buf2;

	*dst = 0;

	// First record 'errno' (if set) 
	if (errno != 0)
		snprintf(dst, dlen, "%s", strerror(errno));

	// Then add everything from our internal error buffer
	if (strlen(gs_ctx->err_buf) > 0)
	{
		if (errno != 0)
			snprintf(dst + strlen(dst), dlen - strlen(dst), " - "); // strlcat(dst, " - ", dlen);
		snprintf(dst + strlen(dst), dlen - strlen(dst), "%s", gs_ctx->err_buf);
	}

	/* Get the last SSL error only. Clear the error-queue */
	int err = 0;
	int err2;
	while (1)
	{
		err2 = ERR_get_error();
		DEBUGF_Y("err2 = %d\n", err2);
		if (err2 == 0)
			break;
		err = err2;
	}
	if (err != 0)
	{
		snprintf(dst + strlen(dst), dlen - strlen(dst), " [%s]", ERR_error_string(err, NULL));
	}

	return gs_ctx->err_buf2;
}

const char *
GS_strerror(GS *gsocket)
{
	return GS_CTX_strerror(gsocket->ctx);
}

/*
 * Called after CTX has been created. Set template flags for GS.
 * Flags are copied to GS on GS_new().
 */
int
GS_CTX_setsockopt(GS_CTX *ctx, int level, const void *opt_value, size_t opt_len)
{

	// PROTO-FLAGS
	if (level == GS_OPT_SOCKWAIT)
	{
		ctx->flags_proto |= GS_FL_PROTO_WAIT;
		ctx->flags_proto &= ~GS_FL_PROTO_FAST_CONNECT; // Disable fast-connect
	} else if (level == GS_OPT_CLIENT_OR_SERVER) {
		ctx->flags_proto |= GS_FL_PROTO_CLIENT_OR_SERVER;
		ctx->flags_proto &= ~GS_FL_PROTO_FAST_CONNECT; // Disable fast-connect
	} else if (level == GS_OPT_LOW_LATENCY) {
		ctx->flags_proto |= GS_FL_PROTO_LOW_LATENCY;
	} else if (level == GS_OPT_SERVER_CHECK) {
		ctx->flags_proto |= GS_FL_PROTO_SERVER_CHECK;
	} 

	// GS-FLAGS 
	else if (level == GS_OPT_BLOCK)
		ctx->gs_flags &= ~GSC_FL_NONBLOCKING;
	else if (level == GS_OPT_NO_ENCRYPTION)
		ctx->gs_flags &= ~GSC_FL_USE_SRP;
	else if (level == GS_OPT_SINGLESHOT)
		ctx->gs_flags |= GS_FL_SINGLE_SHOT;

	// OPTIONS
	else if (level == GS_OPT_USE_SOCKS)
	{
		/* Set if not already set from GS_CTX_init() */
		if (ctx->socks_ip == 0)
			ctx->socks_ip = inet_addr(GS_SOCKS_DFL_IP);
	} else
		return -1; // UNKNOWN option

	return 0;	// Success
}


void
GS_FD_CLR_R(GS *gs)
{
	GS_SELECT_CTX *sctx = gs->ctx->gselect_ctx;
	int fd = gs->fd;

	if (sctx->is_rw_state_saved[fd])
	{
		// DEBUGF_R("Clearing fd=%d in SAVES state\n", fd);
		/* Add to saved state */
		sctx->saved_rw_state[fd] &= ~0x01;	/* clear READ */
	} else {
		// DEBUGF_R("Clearing fd=%d in rfd state\n", fd);
		FD_CLR(fd, sctx->rfd);
	}

}

/*
 * Return 0 on WOULD_BLOCK
 * Return FATAL on error
 * Return EOF
 * Return length on SUCCESS
 */
ssize_t
GS_read(GS *gsocket, void *buf, size_t count)
{
	ssize_t len;
	int err = 0;
	// DEBUGF("GS_read(fd = %d)...\n", gsocket->fd);
	GS_SELECT_CTX *sctx = gsocket->ctx->gselect_ctx;
	DEBUG_SETID(gsocket);

	if (gsocket->flags & GSC_FL_USE_SRP)
	{
#ifndef WITH_GSOCKET_SSL
		return GS_ERR_FATAL;
#else
		len = gs_ssl_continue(gsocket, GS_CAN_READ);
		// DEBUGF("gs_ssl_continue()==%zd, ssl-state=%d\n", len, gsocket->ssl_state);
		if (len <= 0)
			return len;

		len = SSL_read(gsocket->ssl, buf, count);

		if (len <= 0)
		{
			err = SSL_get_error(gsocket->ssl, len);
			DEBUGF_Y("fd=%d, SSL Error: ret = %zd, err = %d (%s) %s\n", gsocket->fd, len, err, GS_SSL_strerror(err), strerror(errno));
			gs_set_errorf(gsocket, "SSL: %s", ERR_error_string(err, NULL));
		}
#endif
	} else {
		len = read(gsocket->fd, buf, count);
		// DEBUGF_M("read(fd=%d) = %zd, errno = %d\n", gsocket->fd, len, errno);

		if (len == 0)
		{
			/* See BUG-TCP-SHUTDOWN: We must stop calling read() if we received
			 * a shutdown() or close() [can not differentiate]. Stop receiving
			 * but still allow sending until write() fails or stdin closes (for gs-pipe)
			 */
			/* Must clear both so to never ever read() again (cleartext) */
			GS_FD_CLR_R(gsocket);
			FD_CLR(GS_get_fd(gsocket), gsocket->ctx->rfd);
			err = SSL_ERROR_ZERO_RETURN;
		}

		if (len < 0)
		{
			if ((errno != EAGAIN) && (errno != EINTR))
				return GS_ERR_FATAL;
			err = SSL_ERROR_WANT_READ;
		} 
	}

	/* SSL_ERROR_ZERO_RETURNS successfully read from socket (an error message, but
	 * nevertheless...we can get out of our saved state gain)
	 */
	if ((len > 0) || (err == SSL_ERROR_ZERO_RETURN))
	{
		errno = 0;
		gsocket->ts_net_io = GS_TV_TO_USEC(gsocket->ctx->tv_now);
		gsocket->bytes_read += len;
		// DEBUGF("write_pending=%d\n", gsocket->write_pending);
		if (gsocket->write_pending == 0)
			gs_ssl_want_io_finished(gsocket);
		gsocket->read_pending = 0;
		gsocket->ctx->gselect_ctx->blocking_func[gsocket->fd] &= ~GS_CALLREAD;
		// gsocket->ctx->gselect_ctx->current_func[gsocket->fd] = 0;
		/* Mark if there is still data in the input buffer so another cb is done */
#ifdef WITH_GSOCKET_SSL
		if ((gsocket->ssl) && (SSL_pending(gsocket->ssl) > 0))
		{
			DEBUGF("rdata-pending\n");
			gs_select_set_rdata_pending(gsocket->ctx->gselect_ctx, gsocket->fd, SSL_pending(gsocket->ssl));
		}
#endif
	}

	if (len > 0)
		return len;	// HERE: len > 0

	/* ERROR */
	if (err == SSL_ERROR_ZERO_RETURN)
	{
		gsocket->eof_count++;
		DEBUGF_R("%d. EOF received by gs (fd = %d).\n", gsocket->eof_count, gsocket->fd);
		/* Second EOF means that the underlying transport was shut (TCP). It's a hard fail. */
		if (gsocket->eof_count >= 2)
			return GS_ERR_FATAL;
		/* We sent shutdown already and now we receive a shutdown => Destroy connection. */
		if (gsocket->is_sent_shutdown)
		{
			DEBUGF_B("I sent a shutdown already. Destroy connection now.\n");
			return GS_ERR_FATAL;
		}
		return GS_ERR_EOF;
	}

	gsocket->read_pending = 1;

	int ret;
	ret = 0;
	if (err == SSL_ERROR_WANT_WRITE)
	{
		sctx->blocking_func[gsocket->fd] |= GS_CALLREAD;
		ret = gs_ssl_want_io_rw(sctx, gsocket->fd, err);
	}

	if (err != SSL_ERROR_WANT_READ)
		return GS_ERR_FATAL;	// Any other error 

	return ret;
}

void
GS_SELECT_FD_SET_W(GS *gs)
{
	GS_SELECT_CTX *sctx = gs->ctx->gselect_ctx;
	int fd = gs->fd;

	if (sctx->is_rw_state_saved[fd])
	{
		/* Add to saved state */
		sctx->saved_rw_state[fd] |= 0x02;	/* add WRITE */
	} else {
		XFD_SET(fd, sctx->wfd);
	}
}

/*
 * Return 0 on WOULD_BLOCK
 * Return -1 on error
 * Return -2 nothing to be done.
 * Return lengh on SUCCESS
 */
ssize_t
GS_write(GS *gsocket, const void *buf, size_t count)
{
	ssize_t len;
	int err;

	DEBUG_SETID(gsocket);
	// If already in a stored state then modify the stored state and return to caller
	// that to be called again (caller must not modify rfd/wfd as this is used by SSL...)
	GS_SELECT_CTX *sctx = gsocket->ctx->gselect_ctx;
	// DEBUGF("fd=%d, count=%zu is_state_saved=%d(==%d), pending=%d\n", gsocket->fd, count, sctx->is_rw_state_saved[gsocket->fd], sctx->saved_rw_state[gsocket->fd], gsocket->write_pending);
	if (sctx->is_rw_state_saved[gsocket->fd])
	{
		/* HERE: *write() blocked previously or SSL_read() WANTS-WRITE */
		if (gsocket->write_pending == 0)
		{
			/* HERE: GS_write() was called but SSL still busy with SSL_read/SSL_accpet/SSL_connect.
			 * Set wfd in saved state so that when state is restored this function
			 * is triggered.
			 */
			DEBUGF_R("*** WARNING **** Wanting to write app data (%zu) while SSL is busy..\n", count);
			GS_SELECT_FD_SET_W(gsocket);
			/* This should never be called again because we disable cmd's FD-IN */

			return 0;	/* WOULD BLOCK */
		}
		/* HERE: w-fd became writeable while in saved state */
	}

	// DEBUGF("GS_write(%zu) to fd = %d, ssl = %p\n", count, gsocket->fd, gsocket->ssl);

	if (gsocket->flags & GSC_FL_USE_SRP)
	{
#ifndef WITH_GSOCKET_SSL
		return -1;
#else
		len = gs_ssl_continue(gsocket, GS_CAN_WRITE);
		if (len <= 0)
		{
			// HERE: ssl-state continued. Return.
			DEBUGF("gs_ssl_continue()==%zd\n", len);
			return len;
		}

		// No state to continue
		if (count == 0)
		{
			// This can happen if we receive an app-ping. This sets
			// wfd (for writing) to wake up to send the pong-reply.
			// The write-callback is called and does not know if the SSL-state
			// has to continue (wanted write?) or if it is an outstanding pong-reply.
			// Thus the callback calls GS_write() and _here_ we determine that no
			// SSL-state needed attention. The caller then sends the pong.
			DEBUGF_C("GS_write() with no data. NO stuck state either.\n");
			return -2;
		}

		len = SSL_write(gsocket->ssl, buf, count);
		// DEBUGF_M("SSL_write(%zu) == %zd\n", count, len);
		if (len <= 0)
		{
			err = SSL_get_error(gsocket->ssl, len);
			DEBUGF_Y("fd=%d (count=%zu), SSL Error: ret = %zd, err = %d (%s)\n", gsocket->fd, count, len, err, GS_SSL_strerror(err));
		}
#endif
	} else {
		if (count == 0)
			return -2; // Nothing to be done.
		len = write(gsocket->fd, buf, count);
		// DEBUGF("write(%zu) = %zd (%s)\n", count, len, errno==0?"ok":strerror(errno));

		if (len <= 0)
		{
			if ((errno != EAGAIN) && (errno != EINTR))
				return -1;
			err = SSL_ERROR_WANT_WRITE;
		}
	}

	if (len > 0)
	{
			errno = 0;
			gsocket->ts_net_io = GS_TV_TO_USEC(gsocket->ctx->tv_now);
			gsocket->bytes_written += len;
			if (gsocket->read_pending == 0)
				gs_ssl_want_io_finished(gsocket);
			gsocket->write_pending = 0;
			sctx->blocking_func[gsocket->fd] &= ~GS_CALLWRITE;
			FD_CLR(gsocket->fd, sctx->wfd);

			return len;
	}

	/* ERROR */
	int ret;
	ret = 0;
#if 1
	sctx->blocking_func[gsocket->fd] |= GS_CALLWRITE;
	ret = gs_ssl_want_io_rw(sctx, gsocket->fd, err);
#endif
	gsocket->write_pending = 1;

	// DEBUGF("write = %zd %s\n", len, strerror(errno));
	return ret;
}

/******************************************************************************
 * GS UTILS                                                                   *
 ******************************************************************************/




/*
 * Convert usec into human readable string of duration.
 * '123hrs 59min 59.283sec'
 */
char *
GS_usecstr(char *buf, size_t len, uint64_t usec)
{
	static char buf2[64];
	char *ptr = buf;

	if (buf == NULL)
	{
		len = sizeof buf2;
		ptr = buf2;
	}

	int sec;
	int min;
	int msec;
	int hr;

	// usec = (uint64_t)((2*60*60+61)*1000 + 123) * 1000;
	msec = (usec / 1000) % 1000;
	sec = usec / 1000000;

	hr = sec / 3600;
	sec -= hr * 3600;
	min = sec / 60;
	sec -= min * 60;

	*ptr = 0;

	if (hr != 0)
		snprintf(ptr, len, "%dhrs %2dmin %2d.%03dsec", hr, min, sec, msec);
	else
		snprintf(ptr, len, "%2d min %2d.%03d sec", min, sec, msec);
	return ptr;

}

/*
 * Convert bytes into human readable string (TB, MB, KB or B).
 */
char *
GS_bytesstr(char *dst, size_t len, int64_t bytes)
{
	static char buf2[64];
	char *ptr = dst;

	if (dst == NULL)
	{
		len = sizeof buf2;
		ptr = buf2;
	}

	int i;

	bytes *= 100;
	for (i = 0; bytes >= 100*1000 && unit[i] != 'T'; i++)
		bytes = (bytes + 512) / 1024;

	snprintf(ptr, len, "%3lld.%1lld%c%s",
		(long long) (bytes + 5) / 100,
		(long long) (bytes + 5) / 10 % 10,
		unit[i],
		i ? "B" : " ");

	return ptr;
}

/*
 * Convert bytes into full length string with thousands seperation ','
 */
char *
GS_bytesstr_long(char *dst, size_t len, int64_t bytes)
{
	if (dst == NULL)
		return NULL;

	int m = bytes / 1000 / 1000;
	bytes -= m * 1000 * 1000;
	int k = bytes / 1000;
	bytes -= k * 1000;

	if (m > 0)
		snprintf(dst, len, "%d,%03d,%03d", m, k, (int)bytes);
	else if (k > 0)
		snprintf(dst, len, "%d,%03d", k, (int)bytes);
	else
		snprintf(dst, len, "%d", (int)bytes);

	return dst;
}

/*
 * Create 'local' timestamp logfile style.
 */
const char *
GS_logtime(void)
{
	static char tbuf[32];

	time_t t = time(NULL);
	strftime(tbuf, sizeof tbuf, "%c", localtime(&t));

	return tbuf;
}

/*
 * Set the 'listen' token. This will stop a client (who knows the secret) to
 * impersonate a server (while the server is connected).
 *
 * A User might decide to use the same 'token' as a kind of master password
 * for all its servers. We like not to be able to track the User. Thus the
 * token is a hash over TOKEN-STRING + GS-ADDRESS. This makes every token unique
 * per GS-ADDRESS.
 *
 * FIXME: extend this later to use as an auth-token:
 * - store token on GS-net server side
 * - Any 'server' connecting must present same token to be allowed
 *   to send pkt-listen message. 
 * - User can control this with e.g. '-a <Any Server Listen Password>'
 */
void
GS_set_token(GS *gs, const void *data, size_t len)
{
	unsigned char md[SHA256_DIGEST_LENGTH];
	uint8_t *input;

	if (data == NULL)
		RAND_bytes(gs->token, sizeof gs->token);
	else {
		input = malloc(len + sizeof gs->gs_addr.addr);
		memcpy(input, data, len);
		memcpy(input + len, gs->gs_addr.addr, sizeof gs->gs_addr.addr);
		SHA256(input, len + sizeof gs->gs_addr.addr, md);
		memcpy(gs->token, md, sizeof gs->token);
		free(input);
	}
	HEXDUMPF(gs->token, sizeof gs->token, "Token:\n");
}

int
GS_is_server(GS *gs)
{
	return gs->flags & GS_FL_IS_SERVER;
}

