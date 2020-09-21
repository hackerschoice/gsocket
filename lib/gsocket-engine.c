
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
#include <netdb.h>		// gethostbyname
#include <gsocket/gsocket.h>
#include "gsocket-engine.h"
#include "gsocket-sha256.h"	// Use internal SHA256 if no OpenSSL available

#ifdef DEBUG
# define WITH_DEBUG
FILE *gs_dout;		/* DEBUG OUTPUT */
int gs_debug_level;
#endif
// #define WITH_DEBUG

#define GS_NET_DEFAULT_HOST			"gs.thc.org"
#define GS_NET_DEFAULT_PORT			7350
#ifdef WITH_DEBUG
# define GS_DEFAULT_PING_INTERVAL	(30)
#else
# define GS_DEFAULT_PING_INTERVAL	(2*60)	/* Every n minutes */
#endif

// #define STRESSTEST	1
#ifdef STRESSTEST
# define GS_DEFAULT_PING_INTERVAL	(1)
#endif

static const char unit[] = "BKMGT";    /* Up to Exa-bytes. */

static int gs_pkt_listen_write(GS *gsocket, struct gs_sox *sox);
static int gs_pkt_connect_write(GS *gsocket, struct gs_sox *sox);
static void gs_close(GS *gsocket);
static void gs_listen_add_gs_select_by_sox(GS_SELECT_CTX *ctx, gselect_cb_t func, int fd, void *arg, int val);

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
#ifdef WITH_DEBUG
	if (FD_ISSET(fd, fdset))
		DEBUGF("fd=%d %c (set)\n", fd, id);
	else
		DEBUGF("fd=%d %c (not set)\n", fd, id);
#endif
}

static int gs_lib_init_called;

void
gs_fds_out(fd_set *fdset, char id)
{
#ifdef WITH_DEBUG
	int i;

	for (i = 0; i < FD_SETSIZE; i++)
	{
		if (FD_ISSET(i, fdset))
			DEBUGF("%c FD %d is set\n", id, i);
	}
#endif
}

void
GS_library_init(void)
{
	if (gs_lib_init_called != 0)
		return;
	gs_lib_init_called = 1;

	/* Initialize SSL */
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	XASSERT(RAND_status() == 1, "RAND_status()");

#ifdef DEBUG
	gs_dout = stderr;
#endif
}

int
GS_CTX_init(GS_CTX *ctx, fd_set *rfd, fd_set *wfd, fd_set *r, fd_set *w, struct timeval *tv_now)
{
	GS_library_init();

	memset(ctx, 0, sizeof *ctx);

	ctx->rfd = rfd;
	ctx->wfd = wfd;
	ctx->r = r;
	ctx->w = w;
	ctx->tv_now = tv_now;
	ctx->out = stderr;	/* library output to STDERR */
	ctx->log_fp = stderr;

	if (ctx->rfd == NULL)
	{
		ERREXIT("Is this still being used? how about r and w == NULL?\n");
		ctx->rfd = calloc(1, sizeof *ctx->rfd);
		ctx->wfd = calloc(1, sizeof *ctx->wfd);
		ctx->flags |= GS_CTX_FL_RFD_INTERNAL;
	} 

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

static uint32_t
hostname_to_ip(char *hostname)
{
	struct hostent *he;
	struct in_addr **addr_list;

	he = gethostbyname(hostname);
	if (he == NULL)
		return 0xFFFFFFFF;

	addr_list = (struct in_addr **)he->h_addr_list;
	if (addr_list == NULL)
		return 0xFFFFFFFF;
	if (addr_list[0] == NULL)
		return 0xFFFFFFFF;

	return addr_list[0][0].s_addr;
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

GS *
GS_new(GS_CTX *ctx, GS_ADDR *addr)
{
	GS *gsocket = NULL;
	char *ptr;
	char *hostname;

	gsocket = calloc(1, sizeof *gsocket);
	if (gsocket == NULL)
		return NULL;

	gsocket->fd = -1;

	ptr = getenv("GSOCKET_PORT");
	if (ptr != NULL)
		gsocket->net.port = htons(atoi(ptr));
	else
		gsocket->net.port = htons(GS_NET_DEFAULT_PORT);

	ptr = getenv("GSOCKET_IP");
	if (ptr != NULL)
	{
		gsocket->net.addr = inet_addr(ptr);
	} else {
		char buf[256];
		hostname = getenv("GSOCKET_HOST");
		if (hostname == NULL)
		{
			/* Connect to [a-z].gsocket.org depending on GS-address */
			int num = 0;
			int i;
			for (i = 0; i < sizeof addr->addr; i++)
				num += addr->addr[i];
			num = num % 26;
			snprintf(buf, sizeof buf, "%c.%s", 'a' + num, GS_NET_DEFAULT_HOST);
			hostname = buf;
		}

		uint32_t ip;
		ip = hostname_to_ip(hostname);
		if (ip == 0xFFFFFFFF)
		{
			free(gsocket);
			gs_set_error(ctx, "Failed to resolve '%s'", hostname);
			return NULL;
		}
		gsocket->net.addr = ip;
	}
	gsocket->net.fd_accepted = -1;

	gsocket->ctx = ctx;

	gsocket->net.n_sox = 5;

	gsocket->flags |= GS_FL_NONBLOCKING;	/* non-blocking by default */
	gsocket->flags |= GS_FL_USE_SRP;		/* encryption by default */

	memcpy(&gsocket->gs_addr, addr, sizeof gsocket->gs_addr);

	GS_srp_setpassword(gsocket, gsocket->gs_addr.b58str);

	GS_set_token(gsocket, NULL, 0);

	return gsocket;
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
	ret = connect(sox->fd, (struct sockaddr *)&addr, sizeof addr);
	DEBUGF("connect(%s, fd = %d): %d (errno = %d)\n", int_ntoa(gsocket->net.addr), sox->fd, ret, errno);
	if (ret != 0)
	{
		if ((errno == EINPROGRESS) || (errno == EAGAIN) || (errno == EINTR))
		{
			FD_SET(sox->fd, gsocket->ctx->wfd);
			sox->state = GS_STATE_SYS_CONNECT;

			return -1;
		}
		if (errno != EISCONN)
		{
			gs_set_error(gsocket->ctx, "connect(%s:%d)", int_ntoa(gsocket->net.addr), ntohs(gsocket->net.port));
			return -2;
		}
	}
	/* HERRE: ret == 0 or errno == EISCONN (Socket is already connected) */
	DEBUGF("connect(fd = %d) SUCCESS (errno = %d)\n", sox->fd, errno);
	FD_CLR(sox->fd, gsocket->ctx->wfd);
	FD_SET(sox->fd, gsocket->ctx->rfd);

	/* SUCCESSFULLY connected */
	sox->state = GS_STATE_SYS_NONE;
	gsocket->net.conn_count += 1;

	if (gsocket->flags & GS_FL_IS_CLIENT)
		gs_pkt_connect_write(gsocket, sox);
	else
		gs_pkt_listen_write(gsocket, sox);

	if (gsocket->net.conn_count >= gsocket->net.n_sox)
		gsocket->flags |= GS_FL_TCP_CONNECTED;

	return 0;
}

/*
 * Return > 0 on success.
 * Return 0 if write would block.
 * Return -1 on error.
 */
static int
gs_write(GS_CTX *ctx, struct gs_sox *sox, const void *data, size_t len)
{
	int ret;

	ret = write(sox->fd, data, len);
	if (ret == len)
	{
		// FD_CLR(sox->fd, ctx->wfd);
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
gs_pkt_ping_write(GS *gsocket, struct gs_sox *sox)
{
	int ret;

	DEBUGF("### PKT PING write(fd = %d)\n", sox->fd);

	/* Do not send PING if there is already data in output queue */
	if (FD_ISSET(sox->fd, gsocket->ctx->wfd))
	{
		DEBUGF("skip PING. WANT_WRITE already set.\n");
		return 0;
	}

	struct _gs_ping gping;
	memset(&gping, 0, sizeof gping);
	gping.type = GS_PKT_TYPE_PING; 

	ret = gs_write(gsocket->ctx, sox, &gping, sizeof gping);
	if (ret == 0)
		sox->state = GS_STATE_PKT_PING;

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

	ret = gs_write(gsocket->ctx, sox, &glisten, sizeof glisten);
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
	gconnect.flags = gsocket->flags_proto;
	DEBUGF_Y("Proto Flags: %x\n", gconnect.flags);

	memcpy(gconnect.addr, gsocket->gs_addr.addr, MIN(sizeof gconnect.addr, GS_ADDR_SIZE));

	ret = gs_write(gsocket->ctx, sox, &gconnect, sizeof gconnect);
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

	ret = gs_write(gsocket->ctx, sox, &gaccept, sizeof gaccept);
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
		return 0;
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
		return 0;
	}

	DEBUGF("Invalid Packet Type %d - Ignoring..\n", sox->rbuf[0]);

	return 0;
}

/*
 * Return length of bytes read or -1 on error (treat EOF as ECONNRESET & return -1)
 */
static ssize_t
gs_read(struct gs_sox *sox, size_t len)
{
	ssize_t ret;

	ret = read(sox->fd, sox->rbuf + sox->rlen, len);
	if (ret == 0)	/* EOF */
		errno = ECONNRESET;
	if (ret <= 0)
		return -1;

	sox->rlen += ret;

	return ret;
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
			if (ret != 0)
			{
				DEBUGF_R("will ret = %d, errno %s\n", ret, strerror(errno));
				return -1;	/* ECONNREFUSED or other */
			}

			DEBUGF("GS-NET Connection (TCP) ESTABLISHED (fd = %d)\n", sox->fd);
			/* rfd is set in gs_net_connect_by_sox */
			gs_fds_out_fd(gsocket->ctx->rfd, 'r', sox->fd);
			gs_fds_out_fd(gsocket->ctx->wfd, 'w', sox->fd);
			return 0;
		}

		if ((sox->state == GS_STATE_PKT_PING) || (sox->state == GS_STATE_PKT_LISTEN))
		{
			ret = write(sox->fd, sox->wbuf, sox->wlen);
			/* Fatal is a single write fails even if wfd was set */
			if (ret != sox->wlen)
			{
				DEBUGF("ret = %d, len = %zu, errno = %s\n", ret, sox->wlen, strerror(errno));
				return -1;
			}
			FD_CLR(sox->fd, gs_ctx->wfd);
			FD_SET(sox->fd, gs_ctx->rfd);
			sox->state = GS_STATE_SYS_NONE;

			return 0;
		}

		/* write() data still in output buffer */
		DEBUGF("Oops. WFD ready but not in SYS_CONNECT or PKT_PING? (fd = %d, state = %d)\n", sox->fd, sox->state);
		return -1;
	}

	/* Read GS message. */
	/* Read GS MSG header (first octet) */
	if (sox->rlen == 0)
	{
		ret = gs_read(sox, 1);
		if (ret != 1)
			return -1;
	}

	size_t len_pkt;
	if (sox->rbuf[0] == GS_PKT_TYPE_LISTEN)
		len_pkt = sizeof (struct _gs_listen);
	else
		len_pkt = sizeof (struct _gs_ping);

	if (sox->rlen >= len_pkt)
		ERREXIT("BOOM! rlen %zu pkg_len %zu\n", sox->rlen, len_pkt);
	
	size_t len_rem = len_pkt - sox->rlen;
	ret = gs_read(sox, len_rem);
	if (ret < 0)
		return -1;

	if (sox->rlen > len_pkt)
		ERREXIT("BOOM!!\n");

	if (sox->rlen < len_pkt)
		return 0;	/* Not enough data yet */

	gs_pkt_dispatch(gsocket, sox);
	sox->rlen = 0;

	return 0;
}

/*
 * Call every second to take care of house-keeping and keep
 * alive messages.
 */
void
GS_heartbeat(GS *gsocket)
{
	int i;

	if (gsocket->fd >= 0)
		return;

	// DEBUGF_M("GS_heartbeat()\n");
	/* Check if it is time to send a PING to keep the connection alive */
	for (i = 0; i < gsocket->net.n_sox; i++)
	{
		struct gs_sox *sox = &gsocket->net.sox[i];

		XASSERT(sox->state != GS_STATE_APP_CONNECTED, "fd = %d but APP already CONNECTED state\n", gsocket->fd);
		/* Skip if 'want-write' is already set. We are already trying to write data. */
		if (FD_ISSET(sox->fd, gsocket->ctx->wfd))
			continue;

		/* Skip if oustanding PONG..*/
		if (sox->flags & GS_SOX_FL_AWAITING_PONG)
			continue;

		XASSERT(sox->state != GS_STATE_PKT_ACCEPT, "APP_CONNECTED == false _and_ state == ACCEPT\n");

		/* Skip if we are busy with any other system-call (e.g. needing to call 'connect()' again */
		if (sox->state == GS_STATE_SYS_CONNECT)
			continue;

		uint64_t tv_diff = GS_TV_DIFF(&sox->tv_last_data, gsocket->ctx->tv_now);
		// DEBUGF("diff = %llu\n", tv_diff);
		if (tv_diff > GS_SEC_TO_USEC(GS_DEFAULT_PING_INTERVAL))
		{
			gs_pkt_ping_write(gsocket, sox);
			memcpy(&sox->tv_last_data, gsocket->ctx->tv_now, sizeof sox->tv_last_data);
		}	
	}
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
		return 0;
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
			if (ret != 0)
				return -1;

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
	if (s < 0)
		return -1;

	ret = fcntl(s, F_SETFL, O_NONBLOCK | fcntl(s, F_GETFL, 0));
	if (ret != 0)
		return -1;

	gsocket->ctx->max_sox = MAX(s, gsocket->ctx->max_sox);
	sox->fd = s;

	DEBUGF("socket(): %d\n", s);

	return 0;
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
	func = gsocket->ctx->func_listen;
	cb_val = gsocket->ctx->cb_val_listen;

	DEBUGF("gs_net_connect called (GS_select() func = %p\n", func);
	GS_SELECT_CTX *gselect_ctx = gsocket->ctx->gselect_ctx;

	for (i = 0; i < gsocket->net.n_sox; i++)
	{
		struct gs_sox *sox = &gsocket->net.sox[i];

		if (sox->fd >= 0)
			continue;	// Skip existing (valid) TCP sockets

		/* HERE: socket() does not exist yet. Create it. */
		ret = gs_net_new_socket(gsocket, sox);
		if (ret != 0)
			return -1;

		/* Connect TCP */
		ret = gs_net_connect_by_sox(gsocket, sox);
		DEBUGF("gs_net_connect_by_sox(fd = %d): %d, %s\n", sox->fd, ret, strerror(errno));
		if (ret == -2)
			return -1;
	
		/* GS_select-HACK-1-START */
		if (gsocket->ctx->gselect_ctx != NULL)
		{
			DEBUGF_B("Using GS_select() with new fd = %d, func = %p\n", sox->fd, func);
			/* HERE: We are using GS_select(). Track new fd. */
			gs_listen_add_gs_select_by_sox(gselect_ctx, func, sox->fd, gsocket, cb_val);
		}
		/* GS_select-HACK-1-END */

	}	/* FOR loop over all sockets */

	return 0;
}

static void
gs_net_init(GS *gsocket, int backlog)
{
	int i;

	backlog = MIN(backlog, GS_MAX_SOX_BACKLOG);
	gsocket->net.n_sox = backlog;
	for (i = 0; i < gsocket->net.n_sox; i++)
	{
		struct gs_sox *sox = &gsocket->net.sox[i];
		sox->fd = -1;
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
		
		DEBUGF("Setting FD BLOCKING on ret = %d\n", ret);
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

	if (gsocket->net.fd_accepted >= 0)
	{
		/* This GS-socket is already connected.... */
		errno = EBUSY;
		return GS_ERR_FATAL;
	}

	if (gsocket->flags & GS_FL_NONBLOCKING)
		ret = gs_connect(gsocket);
	else
		ret = gs_connect_blocking(gsocket);

	if (ret < 0)
	{
		DEBUGF("GS_connect() will ret = %d (%s)\n", ret, ret==GS_ERR_WAITING?"WAITING":"FATAL");
		return ret;
	}

#ifdef WITH_GSOCKET_SSL
	if (gsocket->flags & GS_FL_USE_SRP)
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
#if 0
	/* SINGLE_CONN socket wants 1 TCP connection only */
	if (gsocket->flags & GS_FL_SINGLE_CONN)
		backlog = 1;

	/* Force SINGLE_CONN if backlog is 0 */
	if (backlog <= 0)
	{
		gsocket->flags |= GS_FL_SINGLE_CONN;
		backlog = 1;
	}
#endif

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
 * FIXME: How do we determine error after gs_process() to exit fully or when GS_accept()
 * was blocking???
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

	//DEBUGF("Called GS_accept()\n");
	ret = gs_process(gsocket);
	if (ret != 0)
	{
		DEBUGF("ERROR: in gs_process(), ret = %d\n", ret);
		return GS_ERR_FATAL;
	}

	/* Check if there is a new gs-connection waiting */
	if (gsocket->net.fd_accepted >= 0)
	{
		DEBUGF("New GS Connection accepted (fd = %d)\n", gsocket->net.fd_accepted);

		ret = gs_net_disengage_tcp_fd(gsocket, new_gs);
		XASSERT(ret == 0, "ret = %d\n", ret);

		/* Start new TCP to GS-Net to listen for more incoming connections */
		gs_net_connect(gsocket);

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
		gettimeofday(gsocket->ctx->tv_now, NULL);
		GS_heartbeat(gsocket);
		if (n == 0)
			continue;

		ret = gs_accept(gsocket, new_gs);
		if (ret == -2)
			return -2;
		if (ret == -1)
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

	if (err != NULL)
		*err = 0;

	memset(&gs_tmp, 0, sizeof gs_tmp);
	if (gsocket->flags & GS_FL_NONBLOCKING)
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
	if (new_gs->flags & GS_FL_USE_SRP)
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
		close(gsocket->fd);
		gsocket->fd = -1;
		return;
	}

	/* HERE: There are GS-Net connections that need to be cleaned.*/
	int i;
	/* Close all TCP connections to GS-Network */
	for (i = 0; i < gsocket->net.n_sox; i++)
	{
		struct gs_sox * sox = &gsocket->net.sox[i];
		if (sox->fd < 0)
			continue;
		DEBUGF_B("Closing I/O socket (fd = %d)\n", sox->fd);
		FD_CLR(sox->fd, gsocket->ctx->rfd);
		FD_CLR(sox->fd, gsocket->ctx->wfd);
		FD_CLR(sox->fd, gsocket->ctx->r);
		FD_CLR(sox->fd, gsocket->ctx->w);
		close(sox->fd);
		sox->fd = -1;
	}

	return;
}

/*
 * Return 0 on success.
 * Return -1 on waiting for
 * Return -2 on fatal error.
 */
int
GS_close(GS *gsocket)
{
	DEBUGF_B("read: %zd, written: %zd\n", gsocket->bytes_read, gsocket->bytes_written);
	if (gsocket == NULL)
		return -1;

#ifdef WITH_GSOCKET_SSL
	if (gsocket->flags & GS_FL_USE_SRP)
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

	if (gsocket->flags & GS_FL_USE_SRP)
	{
		if (gsocket->ssl_state != GS_SSL_STATE_RW)
		{
			/* Return if the SSL is not yet connected. We can not shut down
			 * unless it's connected. Shutdown triggered after SRP completion.
			 */
			gsocket->is_want_shutdown = 1;
			return GS_SUCCESS;
		}
		gsocket->is_sent_shutdown = 1;
		ret = gs_ssl_shutdown(gsocket);
		return ret;
	} else {
		gsocket->is_sent_shutdown = 1;
		if (gsocket->eof_count >= 1)
			ret = shutdown(gsocket->fd, SHUT_RDWR);
		else
			ret = shutdown(gsocket->fd, SHUT_WR);
		DEBUGF_B("tcp shutdown() = %d\n", ret);
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

	int err;
	err = ERR_peek_last_error();
	if (err != 0)
	{
		/* VERBOSE */
		snprintf(dst + strlen(dst), dlen - strlen(dst), " [%s]", ERR_error_string(err, NULL));
	}

	return gs_ctx->err_buf2;
}

const char *
GS_strerror(GS *gsocket)
{
	return GS_CTX_strerror(gsocket->ctx);
}

int
GS_setsockopt(GS *gsocket, int level, const void *opt_value, size_t opt_len)
{
	if (gsocket->flags & GS_FL_CALLED_NET_NEW_SOCKET)
	{
		DEBUGF("ERROR: Cant set socket option after socket was created\n");
		errno = EPERM;		/* Cant set socket options after socket was created */
		return -1;
	}

	if (level == GS_OPT_SOCKWAIT)
		gsocket->flags_proto |= GS_FL_PROTO_WAIT;
	else if (level == GS_OPT_BLOCK)
		gsocket->flags &= ~GS_FL_NONBLOCKING;
	else if (level == GS_OPT_CLIENT_OR_SERVER)
		gsocket->flags_proto |= GS_FL_PROTO_CLIENT_OR_SERVER;
	else if (level == GS_OPT_NO_ENCRYPTION)
		gsocket->flags &= ~GS_FL_USE_SRP;
	else
		return -1;
#if 0
	else if (level == GS_OPT_USE_SRP)
	{
#ifndef WITH_GSOCKET_SSL
		return -1;
#else
		const char *pwd = (const char *)opt_value;
		gsocket->flags |= GS_FL_USE_SRP;
		if (pwd == NULL)
			pwd = gsocket->gs_addr.b58str;
		XASSERT(strlen(pwd) > 16, "strlen(pwd) <= 16");
		GS_srp_setpassword(gsocket, pwd);
#endif
#endif

	return 0;
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

	// gsocket->ctx->gselect_ctx->current_func[gsocket->fd] = GS_CALLREAD;

	if (gsocket->flags & GS_FL_USE_SRP)
	{
#ifndef WITH_GSOCKET_SSL
		return GS_ERR_FATAL;
#else
		len = gs_ssl_continue(gsocket);
		if (len <= 0)
			return len;

		len = SSL_read(gsocket->ssl, buf, count);

		if (len <= 0)
		{
			err = SSL_get_error(gsocket->ssl, len);
			DEBUGF_Y("fd=%d, SSL Error: ret = %zd, err = %d (%s)\n", gsocket->fd, len, err, GS_SSL_strerror(err));
			ERR_print_errors_fp(stderr);
		}
#endif
	} else {
		len = read(gsocket->fd, buf, count);
		DEBUGF_M("read(fd=%d) = %zd, errno = %d\n", gsocket->fd, len, errno);

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
		gsocket->bytes_read += len;
		if (gsocket->write_pending == 0)
			gs_ssl_want_io_finished(gsocket);
		gsocket->read_pending = 0;
		gsocket->ctx->gselect_ctx->blocking_func[gsocket->fd] &= ~GS_CALLREAD;
		// gsocket->ctx->gselect_ctx->current_func[gsocket->fd] = 0;
		/* Mark if there is still data in the input buffer so another cb is done */
#ifdef WITH_GSOCKET_SSL
		if ((gsocket->ssl) && (SSL_pending(gsocket->ssl) > 0))
			gs_select_set_rdata_pending(gsocket->ctx->gselect_ctx, gsocket->fd);
#endif
	}

	if (len > 0)
		return len;	// HERE: len > 0

	/* ERROR */
	if (err == SSL_ERROR_ZERO_RETURN)
	{
		gsocket->eof_count++;
		DEBUGF_R("%d. EOF received from peer.\n", gsocket->eof_count);
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
GS_FD_SET_W(GS *gs)
{
	GS_SELECT_CTX *sctx = gs->ctx->gselect_ctx;
	int fd = gs->fd;

	if (sctx->is_rw_state_saved[fd])
	{
		/* Add to saved state */
		sctx->saved_rw_state[fd] |= 0x02;	/* add WRITE */
	} else {
		FD_SET(fd, sctx->wfd);
	}

}

static int repeats;

/*
 * Return 0 on WOULD_BLOCK
 * Return -1 on error
 * Return lengh on SUCCESS
 */
ssize_t
GS_write(GS *gsocket, const void *buf, size_t count)
{
	ssize_t len;
	int err;

	// If we already in a stored state then modify the stored state and return to caller
	// that we like to be called again (caller must not modify rfd/wfd as this is used by SSL...)
	GS_SELECT_CTX *sctx = gsocket->ctx->gselect_ctx;
#if 0
	/* HERE: Socket is writeable. */
	if (gsocket->write_pending == 1)
	{
		/* HERE: Data is already pending */
		if (!(sctx->blocking_func[gsocket->fd] & GS_CALLWRITE))
		{
			DEBUGF_R("*** WARNING **** Oops. Apps trying to send data while SSL_write() was busy?..\n");

			return 0;
		}
	}
#endif
#if 1
	if (sctx->is_rw_state_saved[gsocket->fd])
	{
		/* HERE: *write() blocked previously or SSL_read() wants write */
		if (gsocket->write_pending == 0) //sctx->current_func[gsocket->fd] != GS_CALLWRITE)
		{
			/* HERE: GS_write() was called but SSL still busy with SSL_read().
			 * Set wfd in saved state so that when state is restored this function
			 * is triggered.
			 */
			DEBUGF_R("*** WARNING **** Wanting to write app data while SSL is busy..\n");
			GS_FD_SET_W(gsocket);
			repeats++;
			if (repeats > 3)
				ERREXIT("Oops. looping..\n");

			return 0;	/* WOULD BLOCK */
		}
	}
#endif 

	// DEBUGF("GS_write(%zu) to fd = %d, ssl = %p\n", count, gsocket->fd, gsocket->ssl);
	// gsocket->ctx->gselect_ctx->current_func[gsocket->fd] = GS_CALLWRITE;

	if (gsocket->flags & GS_FL_USE_SRP)
	{
#ifndef WITH_GSOCKET_SSL
		return -1;
#else
		len = gs_ssl_continue(gsocket);
		if (len <= 0)
			return len;

		len = SSL_write(gsocket->ssl, buf, count);
		// DEBUGF_M("SSL_write() == %zd\n", len);
		if (len <= 0)
		{
			err = SSL_get_error(gsocket->ssl, len);
			DEBUGF_Y("fd=%d, SSL Error: ret = %zd, err = %d (%s)\n", gsocket->fd, len, err, GS_SSL_strerror(err));
		}
#endif
	} else {
		len = write(gsocket->fd, buf, count);
		// DEBUGF("write(%zu) = %zd (%s)\n", count, len, errno==0?"ok":strerror(errno));

		if (len <= 0)
		{
			if ((errno != EAGAIN) & (errno != EINTR))
				return -1;
			err = SSL_ERROR_WANT_WRITE;
		}
	}

	if (len > 0)
	{
			errno = 0;
			gsocket->bytes_written += len;
			if (gsocket->read_pending == 0)
				gs_ssl_want_io_finished(gsocket);
			gsocket->write_pending = 0;
			sctx->blocking_func[gsocket->fd] &= ~GS_CALLWRITE;
			FD_CLR(gsocket->fd, sctx->wfd);
			repeats = 0;

			return len;
	}

	/* ERROR */
	int ret;
	ret = 0;
#if 0
	/* FIXME 2020-09-16: Why do we have to keep the state if SSL_write() returns
	 * WANT-WRITE? Why not just return here?
	 */
	if (err == SSL_ERROR_WANT_READ)
	{
		sctx->blocking_func[gsocket->fd] |= GS_CALLWRITE;
		ret = gs_ssl_want_io_rw(sctx, gsocket->fd, err);
	}

#endif
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

static const char       b58digits_ordered[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const int8_t b58digits_map[] = {
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
	-1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
	22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
	-1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
	47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
};


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
#if 0
	if (hr != 0)
		snprintf(ptr, len, "%d:%02d:%02d.%03d", hr, min, sec, msec);
	else
		snprintf(ptr, len, "%02d:%02d.%03d", min, sec, msec);
#endif

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
 * Log a with local timestamp.
 */
// void
// GS_log(GS *gs, const char *str)
// {
// 	char tbuf[64];
// 	FILE *fp;

// 	if (gs == NULL)
// 		return;
// 	if (gs->ctx == NULL)
// 		return;
// 	fp = gs->ctx->log_fp;
// 	if (fp == NULL)
// 		return;

// 	time_t t = time(NULL);
// 	strftime(tbuf, sizeof tbuf, "%c", localtime(&time(NULL)/*t*/));
// 	fprintf(fp, "%s ", tbuf);
// 	fprintf(fp, "%s", str);
// 	fflush(fp);
// }

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

bool
b58tobin(void *bin, size_t *binszp, const char *b58, size_t b58sz)
{

	size_t binsz = *binszp;
	const unsigned char *b58u = (void*)b58;
	unsigned char *binu = bin;
	size_t outisz = (binsz + 3) / 4;
	uint32_t outi[outisz];
	uint64_t t;
	uint32_t c;
	size_t i, j;
	uint8_t bytesleft = binsz % 4;
	uint32_t zeromask = bytesleft ? (0xffffffff << (bytesleft * 8)) : 0;
	unsigned zerocount = 0;
	
	if (!b58sz)
		b58sz = strlen(b58);
	
	memset(outi, 0, outisz * sizeof(*outi));
	
	// Leading zeros, just count
	for (i = 0; i < b58sz && b58u[i] == '1'; ++i)
		++zerocount;
	
	for ( ; i < b58sz; ++i)
	{
		if (b58u[i] & 0x80)
			// High-bit set on invalid digit
			return false;
		if (b58digits_map[b58u[i]] == -1)
			// Invalid base58 digit
			return false;
		c = (unsigned)b58digits_map[b58u[i]];
		for (j = outisz; j--; )
		{
			t = ((uint64_t)outi[j]) * 58 + c;
			c = (t & 0x3f00000000) >> 32;
			outi[j] = t & 0xffffffff;
		}
		if (c)
			// Output number too big (carry to the next int32)
			return false;
		if (outi[0] & zeromask)
			// Output number too big (last int32 filled too far)
			return false;
	}
	
	j = 0;
	switch (bytesleft) {
		case 3:
			*(binu++) = (outi[0] &   0xff0000) >> 16;
		case 2:
			*(binu++) = (outi[0] &     0xff00) >>  8;
		case 1:
			*(binu++) = (outi[0] &       0xff);
			++j;
		default:
			break;
	}
	
	for (; j < outisz; ++j)
	{
		*(binu++) = (outi[j] >> 0x18) & 0xff;
		*(binu++) = (outi[j] >> 0x10) & 0xff;
		*(binu++) = (outi[j] >>    8) & 0xff;
		*(binu++) = (outi[j] >>    0) & 0xff;
	}
	
	// Count canonical base58 byte count
	binu = bin;
	for (i = 0; i < binsz; ++i)
	{
		if (binu[i])
			break;
		--*binszp;
	}
	*binszp += zerocount;
	
	return true;	
}

#if 0
/* Convert Base58 address to binary. Check CRC.
 */
static int
b58dec(void *dst, char *str)
{
	return 0;
}
#endif

/* Convert 128 bit binary into base58 + CRC
 */
static int
b58enc(char *b58, size_t *b58sz, uint8_t *src, size_t binsz)
{
    const uint8_t *bin = src;
    int carry;
    size_t i, j, high, zcount = 0;
    size_t size;

    /* Find out the length. Count leading 0's. */
    while (zcount < binsz && !bin[zcount])
            ++zcount;

    size = (binsz - zcount) * 138 / 100 + 1;
    uint8_t buf[size];
    memset(buf, 0, size);

    for (i = zcount, high = size - 1; i < binsz; ++i, high = j)
    {
            for (carry = bin[i], j = size - 1; (j > high) || carry; --j)
            {
                    carry += 256 * buf[j];
                    buf[j] = carry % 58;
                    carry /= 58;
                    if (!j)
                    {
                            break;
                    }
            }
    }

    for (j = 0; j < size && !buf[j]; ++j);

    if (*b58sz <= zcount + size - j)
    {
            ERREXIT("Wrong size...%zu\n", zcount + size - j + 1);
            *b58sz = zcount + size - j + 1;
            return -1;
    }
    if (zcount)
    	memset(b58, '1', zcount);

    for (i = zcount; j < size; ++i, ++j)
    {
            b58[i] = b58digits_ordered[buf[j]];
    }
    b58[i] = '\0';
    *b58sz = i + 1;

	return 0;
}


/*
 * Convert a binary to a GS address.
 */
GS_ADDR *
GS_ADDR_bin2addr(GS_ADDR *addr, const void *data, size_t len)
{
	unsigned char md[SHA256_DIGEST_LENGTH];
	char b58[GS_ADDR_B58_LEN + 1];
	size_t b58sz = sizeof b58;

	memset(addr, 0, sizeof *addr);
	GS_SHA256(data, len, md);
	memcpy(addr->addr, md, sizeof addr->addr);
	HEXDUMP(addr->addr, sizeof addr->addr);

	b58enc(b58, &b58sz, md, GS_ADDR_SIZE);
	DEBUGF("b58 (%lu): %s\n", b58sz, b58);
	addr->b58sz = b58sz;
	snprintf(addr->b58str, sizeof addr->b58str, "%s", b58);

	return addr;
}

/*
 * Convert a human readable string (password) to GS address. 
 */
GS_ADDR *
GS_ADDR_str2addr(GS_ADDR *addr, const char *str)
{
	addr = GS_ADDR_bin2addr(addr, str, strlen(str));

	return addr;
}

/*
 * Derive a GS-Address from IPv4 + Port tuple.
 * Use at your own risk. GS-Address can easily be guessed.
 */
GS_ADDR *
GS_ADDR_ipport2addr(GS_ADDR *addr, uint32_t ip, uint16_t port)
{
	struct in_addr in;
	char buf[128];

	in.s_addr = ip;

	snprintf(buf, sizeof buf, "%s:%d", inet_ntoa(in), ntohs(port));
	//DEBUGF("%s\n", buf);
	GS_ADDR_str2addr(addr, buf);
	
	return addr;
}

/*
 * Set the 'listen' token. This will stop a client (who knows the secret) to
 * impersonate a server (while the server is connected).
 *
 * A User might decide to use the same 'token' as a kind of master password
 * for all its servers. We like not to be able to track the User. Thus the
 * token is a has over TOKEN-STRING + GS-ADDRESS. This makes every token unique
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
		GS_SHA256(input, len + sizeof gs->gs_addr.addr, md);
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

