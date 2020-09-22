/*
 * EXAMPLE: 'Netcat' tool to forward TCP traffic via Global Sockets
 *
 *
 * Exampel 1: Simple TCP forwarding
 **********************************
 * Server (behind NAT):
 * $ ./gs-netcat -l 192.168.6.7 22
 *
 * Client (behind NAT):
 * $ ./gs-netcat -p 2222
 *
 * Any TCP connection to port 2222 on the Client is forwarded to
 * 192.168.6.7 on port 22 (via Global Socket). This allows
 * a User (Server) to tunnel somebody into the internal network
 * when both parties are behind NAT and without a server on the
 * internet.
 *
 * Example 1: Simple Bash Shell
 * ****************************
 * Server:
 * $ ./gs-netcat -l -e /bin/sh
 * Client:
 * $ ./gs-netcat
 *
 * Effectivly this is a 'reverse shell': The client can connect
 * to a shell on the server from any location and when both systems
 * (Server and Client) are behind NAT.
 *
 *
 * FEATURES:
 * MULTI-CONNECT
 *      An example program to show the use of GS_SELECT with multiple
 *		sockets and connections.
 */
 
#include "common.h"
#include "utils.h"

struct _peer
{
	/* A peer is connected to a gsocket and the a cmd_fd */
	GS *gs;
	int fd_in;
	int fd_out;	/* Same as fd_in unless client reads from stdin/stdout */
	uint8_t rbuf[2048];	/* from GS */
	ssize_t rlen;
	uint8_t wbuf[2048];	/* to GS */
	ssize_t wlen;
	int is_network_forward;
	int is_stdin_forward;
	int is_app_forward;
	/* For Statistics */
	int id;			/* Stats: assign an ID to each pere */
};

/* All connected gs-peers indexed by gs->fd */
static struct _peer *peers[FD_SETSIZE];

/* static functions declaration */
static int write_gs(GS_SELECT_CTX *ctx, struct _peer *p);

/*
 * Make statistics and return them in 'dst'
 */
static void
peer_mk_stats(char *dst, size_t len, struct _peer *p)
{
	GS *gs = p->gs;

	struct timeval *tv_now = gs->ctx->tv_now;
	gettimeofday(tv_now, NULL);
	uint64_t diff = GS_TV_DIFF(&gs->tv_connected, tv_now);
	int64_t msec = diff / 1000;
	msec = MAX(msec, 1);	/* dont device by zero */

	char dbuf[64];
	GS_usecstr(dbuf, sizeof dbuf, diff);
	char rbuf[64];
	char wbuf[64];
	GS_bytesstr_long(rbuf, sizeof rbuf, gs->bytes_read);
	GS_bytesstr_long(wbuf, sizeof wbuf, gs->bytes_written);
	// GS_bytesstr(rbuf, sizeof rbuf, gs->bytes_read);
	// GS_bytesstr(wbuf, sizeof wbuf, gs->bytes_written);
	char rbufps[64];
	char wbufps[64];
	int bps = ((gs->bytes_read * 1000) / msec);
	GS_bytesstr(rbufps, sizeof rbufps, bps==0?0:bps);
	bps = ((gs->bytes_written * 1000) / msec);
	GS_bytesstr(wbufps, sizeof wbufps, bps==0?0:bps);

	snprintf(dst, len, "[ID=%d] Disconnected after %s\n    Up: %s Bytes [%s/s], Down: %s Bytes [%s/s]\n", p->id, dbuf, wbuf, wbufps, rbuf, rbufps);
}


/*
 * Close gs-peer and free memory. Close peer->fd unless it's 
 * stdin/stdout (in which case we keep it open for the next
 * connecting gs-peer).
 */
static void
peer_free(GS_SELECT_CTX *ctx, struct _peer *p)
{
	GS *gs = p->gs;
	int is_stdin_forward = p->is_stdin_forward;

	XASSERT(peers[gs->fd] == p, "Oops, %p != %p on fd = %d, cmd_fd = %d\n", peers[gs->fd], p, gs->fd, p->fd_in);

	/* Exit() if we were reading from stdin/stdout. No other clients
	 * in this case.
	 */
	GS_SELECT_del_cb(ctx, p->fd_in);
	if (is_stdin_forward)
	{
		// We could hard exit here but we like to see all the
		// stats that GS_close() gives us...
		//exit(0);	// this will close all fd's :>
	} else {
		/* is_stdin_forward == 0 */
		/*. Not stdin/stdout. */
		close(p->fd_in);
	}

	stty_reset();
	char buf[512];
	peer_mk_stats(buf, sizeof buf, p);
	VLOG("%s %s", GS_logtime(), buf);

	GS_SELECT_del_cb(ctx, gs->fd);

	DEBUGF_Y("free'ing peer on fd = %d\n", gs->fd);
	memset(p, 0, sizeof *p);
	XFREE(peers[gs->fd]);
	GS_close(gs);	// sets gs->fd to 0
	gopt.peer_count = MAX(gopt.peer_count - 1, 0);
	DEBUGF_M("Freed gs-peer. Still connected: %d\n", gopt.peer_count);
#ifdef DEBUG
	int c = 0;
	int i;
	for (i = 0; i < FD_SETSIZE; i++)
	{
		if (peers[i] != NULL)
			c++;
	}
	XASSERT(c == gopt.peer_count, "Oops, found %d peers but should be peer_count = %d\n", c, gopt.peer_count);
#endif

	/* STDIN/STDOUT reading supports one gs connection only */
	if (is_stdin_forward)
		exit(0);
}

/* *********************** FD READ / WRITE ******************************/


static int
cb_read_fd(GS_SELECT_CTX *ctx, int fd, void *arg, int val)
{
	struct _peer *p = (struct _peer *)arg;
	GS *gs = p->gs;
	int ret;

	XASSERT(p->wlen <= 0, "Already data in gs-write buffer (%zd)\n", p->wlen);

	errno = 0;
	p->wlen = read(fd, p->wbuf, sizeof p->wbuf);
	DEBUGF_M("Read %zd from fd_cmd = %d (errno %d)\n", p->wlen, fd, errno);
	// write(2, p->wbuf, p->wlen);
	if (p->wlen <= 0)
	{
		if (p->is_stdin_forward)
		{
			/* Gracefully half-duplex. We can not read from fd but
			 * peer might still have data to send (which we can write).
			 */
			FD_CLR(fd, ctx->rfd);	// Stop reading from fd
			ret = GS_shutdown(gs);
			/* Destroy peer if shutdown failed or we already received a EOF from peer */
			if (ret != GS_ERR_FATAL)
				return GS_SUCCESS;
		} 
		peer_free(ctx, p);
		return GS_SUCCESS;	/* SUCCESS. fd had no errors [ssl may have had] */

	}
	if ((gopt.is_interactive) && !(gopt.flags & GSC_FL_IS_SERVER))
		stty_check_esc(gs, p->wbuf[0]);

	write_gs(ctx, p);

	return GS_SUCCESS;
}

static int
write_fd(GS_SELECT_CTX *ctx, struct _peer *p)
{
	ssize_t len;


	len = write(p->fd_out, p->rbuf, p->rlen);
	// DEBUGF_G("write(fd = %d,, len = %zd) == %zd\n", p->fd_out, p->rlen, len);
	
	if ((len < 0) && (errno == EAGAIN))
	{
		/* Stop reading from GS */
		FD_CLR(p->gs->fd, ctx->rfd);
		/* Mark that cmd_fd need call to write() */
		FD_SET(p->fd_out, ctx->wfd);
		return GS_SUCCESS;	/* Successfully handled */
	}

	if (len < 0)
	{
		peer_free(ctx, p);
		return GS_SUCCESS;	/* Succesfully remove peer */
	}

	p->rlen = 0;
	return GS_SUCCESS;
}

static int
cb_write_fd(GS_SELECT_CTX *ctx, int fd, void *arg, int val)
{
	return write_fd(ctx, (struct _peer *)arg);
}

/* *********************** NETWORK READ / WRITE *************************/
static int
cb_read_gs(GS_SELECT_CTX *ctx, int fd, void *arg, int val)
{
	struct _peer *p = (struct _peer *)arg;
	GS *gs = p->gs;

	XASSERT(p->rlen <= 0, "Already data in input buffer (%zd)\n", p->rlen);
	p->rlen = GS_read(gs, p->rbuf, sizeof p->rbuf);
	DEBUGF_G("GS_read(fd = %d) == %zd\n", gs->fd, p->rlen);
	if (p->rlen == 0)
		return GS_ECALLAGAIN;

	if (p->rlen == GS_ERR_EOF)
	{
		/* The same for STDOUT, tcp-fordward or cmd-forward [/bin/sh] */
		DEBUGF_M("CMD shutdown(fd=%d)\n", p->fd_out);
		shutdown(p->fd_out, SHUT_WR);
		if (gopt.is_receive_only)
			peer_free(ctx, p);
		return GS_SUCCESS;
	}
	if (p->rlen < 0) /* any ERROR (but EOF) */
	{
		DEBUGF_R("Fatal error=%zd in GS_read() (stdin-forward == %d)\n", p->rlen, p->is_stdin_forward);
		GS_shutdown(gs);
		// DEBUGF_R("GS_shutdown() = %d\n", ret);
		/* Finish peer on FATAL (2nd EOF) or if half-duplex (never send data) */
		peer_free(ctx, p);	// Will exit() if reading from stdin.
		return GS_SUCCESS;	/* Successfully removed peer */
	}

	write_fd(ctx, p);

	p->rlen = 0;
	return GS_SUCCESS;
}

static int
write_gs(GS_SELECT_CTX *ctx, struct _peer *p)
{
	GS *gs = p->gs;
	int len;

	len = GS_write(gs, p->wbuf, p->wlen);
	DEBUGF_R("GS_write() = %d\n", len);
	if (len == 0)
	{
		/* GS_write() would block. */
		FD_CLR(p->fd_in, ctx->rfd);	// Stop reading from input
		return GS_ECALLAGAIN;
	}

	if (len == p->wlen)
	{
		/* GS_write() was a success */
		p->wlen = 0;
		FD_SET(p->fd_in, ctx->rfd);	// Start reading from input again
		return GS_SUCCESS;
	}

	/* HERE: ERROR on GS_write() */
	peer_free(ctx, p);
	return GS_SUCCESS;	// Successfully removed peer

}

static int
cb_write_gs(GS_SELECT_CTX *ctx, int fd, void *arg, int val)
{
	return write_gs(ctx, (struct _peer *)arg);
}

/* ******************************* GS LISTEN ****************************/
static void
completed_connect(GS_SELECT_CTX *ctx, struct _peer *p, int fd_in, int fd_out)
{
	GS *gs = p->gs;
	/* Get ready to read from FD (either (forwarding) TCP, app or stdin/stdout */
	FD_CLR(fd_out, ctx->wfd);
	FD_SET(fd_in, ctx->rfd);
	GS_SELECT_add_cb(ctx, cb_read_fd, cb_write_fd, fd_in, p, 0);

	/* And also get ready to read from GS-peer */
	FD_SET(gs->fd, ctx->rfd);
}

/*
 * Complete TCP connection to network forward on server side.
 */
static int
cb_complete_connect(GS_SELECT_CTX *ctx, int fd, void *arg, int val)
{
	int ret;
	struct _peer *p = (struct _peer *)arg;

	ret = fd_net_connect(ctx, fd, gopt.dst_ip, gopt.port);
	DEBUGF_M("fd_net_connect(fd=%d) = %d\n", fd, ret);
	if (ret == GS_ERR_WAITING)
		return GS_ECALLAGAIN;
	if (ret == GS_ERR_FATAL)
	{
		peer_free(ctx, p);
		return GS_SUCCESS;
	}

	completed_connect(ctx, p, p->fd_in, p->fd_out);

	return GS_SUCCESS;
}

/*
 * Server & Client
 */
static struct _peer *
peer_new_init(GS *gs)
{
	struct _peer *p;
	int fd = GS_get_fd(gs);

	XASSERT(peers[fd] == NULL, "peers[%d] already used by %p (fd = %d)\n", fd, peers[fd], peers[fd]->gs->fd);
	p = calloc(1, sizeof *p);
	p->gs = gs;
	peers[fd] = p;
	gopt.peer_count++;
	gopt.peer_id_counter++;
	p->id = gopt.peer_id_counter;
	DEBUGF_M("Connected gs-peers: %d\n", gopt.peer_count);

	return p;
}

/*
 * SERVER
 */
static struct _peer *
peer_new(GS_SELECT_CTX *ctx, GS *gs)
{
	struct _peer *p;
	int ret;

	p = peer_new_init(gs);

	/* Create a new fd to relay gs-traffic to/from */
	if ((gopt.cmd != NULL) || (gopt.is_interactive))
	{
		p->fd_in = fd_cmd(gopt.cmd);// Forward to forked process stdin/stdout
		p->fd_out = p->fd_in;
		p->is_app_forward = 1;
	} else if (gopt.port != 0) {
		p->fd_in = fd_new_socket();	// Forward to ip:port
		p->fd_out = p->fd_in;
		p->is_network_forward = 1;
	} else {
		p->fd_in = STDIN_FILENO;	// Forward to STDIN/STDOUT
		p->fd_out = STDOUT_FILENO;
		p->is_stdin_forward = 1;
#if 0
		/* 2020-09-09: Do not allow multiple gs-peers to connect
		 * to the same stdin/stdout. In stdin/stdout mode enforce
		 * 1x gs-peer to stdin (stop accepting new connections)
		 */
		/* Disconnect any connected gs but this one */
		for (int i = 0; i < FD_SETSIZE; i++)
		{
			if ((peers[i] == NULL) || (peers[i]->gs == NULL))
				continue;
			if (peers[i]->gs->fd == gs->fd)
				continue;	// found myself
			DEBUGF_R("Disconnecting stale peer: gs-fd = %d\n", peers[i]->gs->fd);
			/* Free/Disconnect gs-peer but keep stdin/stdout open */
			peer_free(ctx, peers[i]);
			break;	/* There can only be 1 stale/old gs-peer */
		}
#endif
	}

	if (p->fd_in < 0)
		ERREXIT("Cant create forward...\n");

	if (p->is_network_forward == 0)
	{
		/* STDIN/STDOUT or app-fd always complete immediately */
		completed_connect(ctx, p, p->fd_in, p->fd_out);
	} else {
		ret = fd_net_connect(ctx, p->fd_in, gopt.dst_ip, gopt.port);
		if (ret <= -2)
		{
			peer_free(ctx, p);
			return NULL;
		}
		GS_SELECT_add_cb(ctx, cb_complete_connect, cb_complete_connect, p->fd_in, p, 0);
		FD_SET(p->fd_in, ctx->wfd);	/* Wait for connect() to complete */
		FD_CLR(p->fd_in, ctx->rfd);

		FD_CLR(gs->fd, ctx->rfd);		// Stop reading from GS-peer 
	}

	return p;
}

/*
 * SERVER
 */
static int
cb_listen(GS_SELECT_CTX *ctx, int fd, void *arg, int val)
{
	GS *gs = (GS *)arg;
	GS *gs_new;
	int err;

	DEBUGF("cb_listen %p, fd = %d, arg = %p, type = %d\n", ctx, fd, arg, val);
	gs_new = GS_accept(gs, &err);
	if (gs_new == NULL)
	{
		if (err <= -2)
			ERREXIT("Fatal error. Another Server already listening?\n");
		/* HERE: GS_accept() is not ready yet to accept() a new
		 * gsocket. (May have processed GS-pkt data) or may have 
		 * closed the socket and established a new one (to wait for
		 * the next connection).
		 */
		return GS_SUCCESS;	/* continue */
	}

	/* Stop accepting more connections if stdin/stdout is used */
	if ((gopt.cmd == NULL) && (gopt.dst_ip == 0) && (!gopt.is_interactive))
	{
		GS_close(gopt.gsocket);
	}
	/* HERE: Success. A new GS connection. */
	DEBUGF_B("Current max_fd %d (gs fd = %d)\n", ctx->max_fd, gs_new->fd);

	struct _peer *p;
	p = peer_new(ctx, gs_new);
	if (p == NULL)
		return GS_SUCCESS;	/* free'ing peer was a success */

	VLOG("%s [ID=%d] New Connection\n", GS_logtime(), p->id);

	/* Start reading from Network (SRP is handled by GS_read()/GS_write()) */
	GS_SELECT_add_cb(ctx, cb_read_gs, cb_write_gs, gs_new->fd, p, 0);

	return 0; /* continue */
}

static void
do_server(void)
{
	GS_SELECT_CTX ctx;
	int n;

	GS_SELECT_CTX_init(&ctx, &gopt.rfd, &gopt.wfd, &gopt.r, &gopt.w, &gopt.tv_now, GS_SEC_TO_USEC(1));
	/* Tell GS_CTX subsystem to use GS-SELECT */
	GS_CTX_use_gselect(&gopt.gs_ctx, &ctx);

	GS_listen(gopt.gsocket, 2);
	/* Add all listening fd's to select()-subsystem */
	GS_listen_add_gs_select(gopt.gsocket, &ctx, cb_listen, gopt.gsocket, 0);

	while (1)
	{
		n = GS_select(&ctx);
		GS_heartbeat(gopt.gsocket);
		if (n < 0)
			break;
	}
	ERREXIT("NOT REACHED\n");
}

/********************** CLIENT *************************************/

/*
 * A hack to set the remote window size without inband
 * communication. Only used with -i.
 */
static void
stty_set_remote_size(GS_SELECT_CTX *ctx, struct _peer *p)
{
	snprintf((char *)p->wbuf, sizeof p->wbuf, GS_STTY_INIT_HACK, gopt.winsize.ws_row, gopt.winsize.ws_col);
	p->wlen = (ssize_t)strlen((char *)p->wbuf);
	write_gs(ctx, p);
}

/*
 * CLIENT
 */
static int
cb_connect_client(GS_SELECT_CTX *ctx, int fd, void *arg, int val)
{
	struct _peer *p = (struct _peer *)arg;
	GS *gs = p->gs;
	int ret;

	ret = GS_connect(gs);
	DEBUGF_M("GS_connect(fd=%d) == %d\n", gs->fd, ret);
	if (ret == GS_ERR_FATAL)
		ERREXIT("Fatal GS_connect() error\n");
	if (ret == GS_ERR_WAITING)
		return GS_ECALLAGAIN;

	DEBUGF_M("*** GS_connect() SUCCESS *****\n");
	/* HERE: Connection successfully established */
	/* Start reading from Network (SRP is handled by GS_read()/GS_write()) */
	GS_SELECT_add_cb(ctx, cb_read_gs, cb_write_gs, fd, p, 0);

	/* Start reading from STDIN or inbound TCP */
	GS_SELECT_add_cb(ctx, cb_read_fd, cb_write_fd, p->fd_in, p, 0);
	FD_SET(p->fd_in, ctx->rfd);	/* Start reading */

	/* -i specified and we are a client: Set TTY to raw for a real shell
	 * experience. Ignore this for this example.
	 */
	if ((p->is_stdin_forward) && (gopt.is_interactive))
	{
		/* HERE: Client */
		DEBUGF_M("Setting tty\n");
		XASSERT(p->fd_in == STDIN_FILENO, "p->fd_in = %d, not STDIN\n", p->fd_in);
		stty_set_raw();
		stty_set_remote_size(ctx, p);
	}

	return GS_SUCCESS;
}

/*
 * Client
 */
static struct _peer *
gs_and_peer_connect(GS_SELECT_CTX *ctx, GS *gs, int fd_in, int fd_out)
{
	int ret;
	struct _peer *p;

	ret = GS_connect(gs);	// First call always returns -1 (waiting)
	XASSERT(ret == GS_ERR_WAITING, "ERROR GS_connect() == %d\n", ret);
	DEBUGF_B("GS_connect() = %d\n", ret);
	DEBUGF_B("GS->fd = %d\n", GS_get_fd(gs));
	p = peer_new_init(gs);
	p->fd_in = fd_in;
	p->fd_out = fd_out;

	GS_SELECT_add_cb(ctx, cb_connect_client, cb_connect_client, GS_get_fd(gs), p, 0);

	return p;
}

/*
 * Client accepting incoming TCP connection to be forwarded to GS
 */
static int
cb_accept(GS_SELECT_CTX *ctx, int listen_fd, void *arg, int val)
{
	int fd;
	GS *gs;
	struct _peer *p;

	fd = fd_net_accept(ctx, listen_fd);
	if (fd < 0)
		return GS_SUCCESS;

	DEBUGF_G("New TCP connection RECEIVED (fd = %d)\n", fd);

	/* Create a new GS and call GS_connect() */
	gs = gs_create(); /* Create a new GS */
	p = gs_and_peer_connect(ctx, gs, fd, fd);	/* in/out fd's are identical for TCP */
	p->is_network_forward = 1;

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof addr);
	socklen_t len = sizeof addr;
	getpeername(fd, (struct sockaddr *)&addr, &len);
	VLOG("%s [ID=%d] New Connection from %s:%d\n", GS_logtime(), p->id, inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

	return GS_SUCCESS;
}

static void
do_client(void)
{
	GS_SELECT_CTX ctx;
	// GS *gs = gopt.gsocket;
	int fd;
	int ret;
	struct _peer *p;

	GS_SELECT_CTX_init(&ctx, &gopt.rfd, &gopt.wfd, &gopt.r, &gopt.w, &gopt.tv_now, GS_SEC_TO_USEC(1));
	/* Tell GS_CTX subsystem to use GS-SELECT */
	GS_CTX_use_gselect(&gopt.gs_ctx, &ctx);

	if (gopt.port == 0)
	{
		/* Read/Write from STDIN/STDOUT. No TCP. */
		/* STDIN can be blocking */
		p = gs_and_peer_connect(&ctx, gopt.gsocket, STDIN_FILENO, STDOUT_FILENO);
		p->is_stdin_forward = 1;
	} else {
		fd = fd_new_socket();
		ret = fd_net_listen(&ctx, fd, gopt.port);
		if (ret != 0)
			ERREXIT("listen(): %s\n", strerror(errno));

		GS_SELECT_add_cb(&ctx, cb_accept, cb_accept, fd, NULL, 0);
		FD_SET(fd, ctx.rfd);	/* listening socket */
	}

	int n;
	while (1)
	{
		n = GS_select(&ctx);
		if (n < 0)
			break;
	}
	ERREXIT("NOT REACHED\n");
}

static void
my_usage(void)
{
	fprintf(stderr, ""
"gs-netcat [-lwiC] [-e cmd] [-p port] [-d ip]\n"
"");

	usage("skrlgqwCTie");
	fprintf(stderr, ""
"\n"
"Example to forward traffic from port 2222 to 192.168.6.7:22:\n"
"    $ gs-netcat -l -d 192.168.6.7 -p 22     # Server\n"
"    $ gs-netcat -p 2222                     # Client\n"
"Example file transfer:\n"
"    $ gs-netcat -s blah -rl >warez.tar.gz   # Server\n"
"    $ gs-netcat -s blah <warez.tar.gz       # Client\n"
"Example for a reverse shell:\n"
"    $ gs-netcat -l -i                       # Server\n"
"    $ gs-netcat -i                          # Client\n"
"");
	exit(255);
}

static void
my_getopt(int argc, char *argv[])
{
	int c;

	do_getopt(argc, argv);	/* from utils.c */
	optind = 1;	/* Start from beginning */
	while ((c = getopt(argc, argv, UTILS_GETOPT_STR)) != -1)
	{
		switch (c)
		{
			case 'p':
				gopt.port = htons(atoi(optarg));
				break;
			case 'e':
				gopt.cmd = optarg;
				break;
			case 'd':
				gopt.dst_ip = inet_addr(optarg);
				break;
			default:
				break;
			case 'A':	// Disable -A for gs-netcat. Use gs-full-pipe instead
			case '?':
				my_usage();
		}
	}

	init_vars();			/* from utils.c */

	/* Disable encryption (-C) */
	if (gopt.is_encryption == 0)
		GS_setsockopt(gopt.gsocket, GS_OPT_NO_ENCRYPTION, NULL, 0);

	VLOG("=Encryption: %s (Prime: %d bits)\n", GS_get_cipher(gopt.gsocket), GS_get_cipher_strength(gopt.gsocket));
}

int
main(int argc, char *argv[])
{
	init_defaults();
	my_getopt(argc, argv);

	if (gopt.flags & GSC_FL_IS_SERVER)
		do_server();
	else
		do_client();

	exit(255);
	return -1;	/* NOT REACHED */
}


