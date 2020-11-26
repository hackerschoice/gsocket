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
#include "socks.h"
#include "console.h"
#include "man_gs-netcat.h"

/* All connected gs-peers indexed by gs->fd */
static struct _peer *peers[FD_SETSIZE];

/* static functions declaration */
static int write_gs(GS_SELECT_CTX *ctx, struct _peer *p);
static int peer_forward_connect(struct _peer *p, uint32_t ip, uint16_t port);
static void vlog_hostname(struct _peer *p, const char *desc, uint16_t port);
static int stty_send_wsize(GS_SELECT_CTX *ctx, struct _peer *p, int row);
static int send_pong(GS_SELECT_CTX *ctx, struct _peer *p);
static int send_ping(GS_SELECT_CTX *ctx, struct _peer *p);

// static void stty_set_remote_size(GS_SELECT_CTX *ctx, struct _peer *p);

#define GS_APP_KEEPALIVE	GS_SEC_TO_USEC(60 * 2) // If no activty send app-layer ping (-i needed)
#define GS_APP_PINGFREQ		GS_SEC_TO_USEC(5)      // Send a ping every 5 sec (-i, in console)
#define GS_APP_BPSFREQ		GS_SEC_TO_USEC(2)      // Calculate BPS every second

#define PKT_MSG_WSIZE		(1)
#define PKT_MSG_PING		(16)
#define PKT_MSG_PONG		(16)

struct _app_pong
{
	uint16_t load;
	uint16_t idle;
	uint8_t user[12];
} __attribute__((__packed__));

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
	char rbufps[64];
	char wbufps[64];
	int bps = ((gs->bytes_read * 1000) / msec);
	GS_bytesstr(rbufps, sizeof rbufps, bps==0?0:bps);
	bps = ((gs->bytes_written * 1000) / msec);
	GS_bytesstr(wbufps, sizeof wbufps, bps==0?0:bps);

	snprintf(dst, len, 
	"[ID=%d] Disconnected after %s\n"
	"    Up: "D_MAG("%12s")" [%s/s], Down: "D_MAG("%12s")" [%s/s]\n", p->id, dbuf, wbuf, wbufps, rbuf, rbufps);
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
	int fd;

	/* Reset console/stty before outputting stats */
	if (is_stdin_forward)
	{
		CONSOLE_reset();
		stty_reset();
	}
	/* A connecting fd (gs->net.sox[0].fd or a connected fd (gs->fd) */
	fd = GS_get_fd(gs);
	DEBUGF_R("GS_get_fd() == %d\n", GS_get_fd(gs));
	XASSERT(peers[fd] == p, "Oops, %p != %p on fd = %d, cmd_fd = %d\n", peers[fd], p, fd, p->fd_in);

	GS_EVENT_del(&gopt.event_ping);
	GS_EVENT_del(&gopt.event_bps);
	GS_PKT_close(&p->pkt);
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
		XCLOSE(p->fd_in);
	}

	/* Output stats gs was connected */
	if (gs->tv_connected.tv_sec != 0)
	{
		char buf[512];
		peer_mk_stats(buf, sizeof buf, p);
		VLOG("%s %s", GS_logtime(), buf);
		if ((p->is_network_forward) && (p->socks.dst_port != 0))
	    	vlog_hostname(p, "", p->socks.dst_port);
	}

	GS_SELECT_del_cb(ctx, fd);

	DEBUGF_Y("free'ing peer on fd = %d\n", fd);
	memset(p, 0, sizeof *p);
	XFREE(peers[fd]);
	GS_close(gs);	// sets gs->fd to -1
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

static void
cb_atexit(void)
{
	CONSOLE_reset();
	stty_reset();
}

/* *********************** FD READ / WRITE ******************************/

/*
 * read() but with detecting CTRL+E (console command)
 */
static ssize_t
read_esc(int fd, uint8_t *buf, size_t len, uint8_t *key)
{
	size_t n = 0;
	ssize_t sz;
	uint8_t c;
	int ret;

	/* FIXME-PERFORMANCE: Implement buffered read for performance
	 * when in interactive mode [but then how fast can you type?]
	 */
	/* FIXME-PERFORMANCE: Cant leave stdin as non-blocking. 'top' wont
	 * work any more. xterm sends data to stdin (?) and expects
	 * blocking stdout (my stdin)?
	 * FIXME-PERFORMANCE: Block-read while console is not being
	 * displayed (?)
	 */
    fcntl(fd, F_SETFL, O_NONBLOCK | fcntl(fd, F_GETFL, 0));

	while (n < len)
	{
		sz = read(fd, &c, 1);
		if (sz <= 0)
		{
			/* EOF or ERROR */
			if (errno == EWOULDBLOCK)
				break;
			if (n == 0)
				n = -1;  // treat EOF as ERROR
			break;
		}
		/* Check if this is an ESCAPE and stop reading */
		ret = CONSOLE_check_esc(c, &c);
		// DEBUGF_G("con = %d\n", ret);
		if (ret != -1)
		{
			if (ret > 0)
			{
				*key = ret;
				break;
			}
			continue;
		} 

		buf[n] = c;
		n++;
	}

    fcntl(fd, F_SETFL, ~O_NONBLOCK & fcntl(fd, F_GETFL, 0));

	return n;
}

// static ssize_t
// read_noesc(int fd, uint8_t *buf, size_t len)
// {
// 	ssize_t sz = read(fd, buf, len);
// 	if (sz == 0)
// 		sz = -1;
// 	return sz;
// }

static int
cb_read_fd(GS_SELECT_CTX *ctx, int fd, void *arg, int val)
{
	struct _peer *p = (struct _peer *)arg;
	GS *gs = p->gs;
	int ret;
	uint8_t key = 0;

	XASSERT(p->wlen <= 0, "Already data in gs-write buffer (%zd)\n", p->wlen);

	errno = 0;
	if ((gopt.is_interactive) && (!(gopt.flags & GSC_FL_IS_SERVER)))
	{
		p->wlen = read_esc(fd, p->wbuf, p->w_max, &key);
		if ((key == 0) && (p->wlen == 0))
			return GS_SUCCESS;	// EWOULDBLOCK
	} else {
		p->wlen = read(fd, p->wbuf, p->w_max);
		if (p->wlen == 0)
			p->wlen = -1; // treat EOF as -1 (error)
	}
	// HEXDUMPF(p->wbuf, p->wlen, "read(%zd): ", p->wlen);

	// DEBUGF_M("Read %zd from fd_cmd = %d (errno %d)\n", p->wlen, fd, errno);
	if (p->wlen < 0)
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

	// First offer data to console
	int was_data_for_console = 0;
	if ((gopt.is_interactive) && (!(gopt.flags & GSC_FL_IS_SERVER)))
	{
		was_data_for_console = CONSOLE_readline(p, p->wbuf, p->wlen);
		if (was_data_for_console)
			p->wlen = 0;
	}

	if (!(was_data_for_console))
	{
	 	if (gopt.is_interactive)
	 	{
			size_t dsz;
			GS_PKT_encode(&p->pkt, p->wbuf, p->wlen, p->pbuf, &dsz);
			if (p->wlen != dsz)
			{
				/* HERE: ESC found. Encoded. */
				memcpy(p->wbuf, p->pbuf, dsz);
				p->wlen = dsz;
			}
		}
		write_gs(ctx, p);
	}

	/*
	 * Take action if a console key has been received
	 */
	if (key > 0)
		CONSOLE_action(p, key);

	return GS_SUCCESS;
}

static int
write_fd(GS_SELECT_CTX *ctx, struct _peer *p)
{
	ssize_t len;

	if ((gopt.is_interactive) && (!(gopt.flags & GSC_FL_IS_SERVER)))
		len = CONSOLE_write(p->fd_out, p->rbuf, p->rlen);
	else
		len = write(p->fd_out, p->rbuf, p->rlen);
	// DEBUGF_G("write(fd = %d, len = %zd) == %zd, errno = %d (%s)\n", p->fd_out, p->rlen, len, errno, errno==0?"":strerror(errno));
	
	if (len < 0)
	{
		if (errno == EAGAIN)
		{
			/* Marked saved state and current state to STOP READING.
			 * Even when in WANT_WRITE we must not start reading after
			 * the WANT_WRITE has been satisfied (until this write() has
			 * completed.
			 */
			GS_SELECT_FD_CLR_R(ctx, p->gs->fd);
			XFD_SET(p->fd_out, ctx->wfd);	// Mark cmd_fd for writing	
			return GS_ECALLAGAIN; //GS_SUCCESS;	/* Successfully handled */
		}

		peer_free(ctx, p);
		return GS_SUCCESS;	/* Succesfully removed peer */
	}

	FD_CLR(p->fd_out, ctx->wfd);	// write success.
	/* Start reading from GS if we are not in a saved state.
	 * Otherwise mark for reading in saved state (and let WANT_WRITE finish)
	 */
	GS_SELECT_FD_SET_R(ctx, p->gs->fd);
	p->rlen = 0;
	return GS_SUCCESS;
}

static int
cb_write_fd(GS_SELECT_CTX *ctx, int fd, void *arg, int val)
{
	return write_fd(ctx, (struct _peer *)arg);
}

/* *********************** NETWORK READ / WRITE *************************/
/*
 * Check & Handle GS_read() errors
 */
static void
cb_read_gs_error(GS_SELECT_CTX *ctx, struct _peer *p, ssize_t len)
{
	if (len == GS_ERR_EOF)
	{
		/* The same for STDOUT, tcp-fordward or cmd-forward [/bin/sh] */
		DEBUGF_M("CMD shutdown(fd=%d)\n", p->fd_out);
		shutdown(p->fd_out, SHUT_WR);	// BUG-2-MAX-FD
		if (gopt.is_receive_only)
		{
			DEBUGF_M("is_receive_only is TRUE. Calling peer_free()\n");
			peer_free(ctx, p);
		}
	} else if (len < 0) { /* any ERROR (but EOF) */
		DEBUGF_R("Fatal error=%zd in GS_read() (stdin-forward == %d)\n", len, p->is_stdin_forward);
		GS_shutdown(p->gs);
		// DEBUGF_R("GS_shutdown() = %d\n", ret);
		/* Finish peer on FATAL (2nd EOF) or if half-duplex (never send data) */
		peer_free(ctx, p);	// Will exit() if reading from stdin.
	}
}

static int
cb_read_gs(GS_SELECT_CTX *ctx, int fd, void *arg, int val)
{
	struct _peer *p = (struct _peer *)arg;
	GS *gs = p->gs;
	ssize_t len;
	int ret;

	// XASSERT(p->rlen <= 0, "Already data in input buffer (%zd)\n", p->rlen);
	XASSERT(p->rlen < p->r_max, "rlen=%zd larger than buffer\n", p->rlen);
	len = GS_read(gs, p->rbuf + p->rlen, p->r_max - p->rlen);
	// DEBUGF_G("GS_read(fd = %d) == %zd\n", gs->fd, len);
	if (len == 0)
		return GS_ECALLAGAIN;

	if (len < 0)
	{
		cb_read_gs_error(ctx, p, len);
		return GS_SUCCESS;	// Successfully removed peer
	}

	p->rlen += len;

	if ((gopt.is_socks_server && (p->socks.state != GSNC_STATE_CONNECTED)))
	{
		/* HERE: SOCKS has not finished yet. Keep stuffing data in */
		ret = SOCKS_add(p);
		if (ret != GS_SUCCESS)
		{
			DEBUGF_R("**** SOCKS_add() ERROR ****\n");
			cb_read_gs_error(ctx, p, GS_ERR_FATAL);

			return GS_SUCCESS;
		}
		if (p->socks.state == GSNC_STATE_CONNECTING)
		{
			DEBUGF_C("SOCKS_add() has finished\n");
			ret = peer_forward_connect(p, p->socks.dst_ip, p->socks.dst_port);
			if (ret != 0)
				return GS_SUCCESS;	// Successfully removed
			p->socks.state = GSNC_STATE_CONNECTED;	// as if this is a normal port forward...
		}
		/* HERE: Socks just got CONNECTED. Flush any pending data. */
		if (p->wlen > 0)
			write_gs(ctx, p);
	} else {
		if (gopt.is_interactive)
		{
			if (p->is_stdin_forward)
			{
				/* HERE: Client */
				if (p->is_stty_set_raw == 0)
				{
					/* Set TTY=raw first time we receive data [connection alive] */
					XASSERT(p->fd_in == STDIN_FILENO, "p->fd_in = %d, not STDIN\n", p->fd_in);
					stty_set_raw();
					p->is_stty_set_raw = 1;
				}
			}
			/* HERE: Client Or Server. Interactive */
			size_t dsz;
			ret = GS_PKT_decode(&p->pkt, p->rbuf, p->rlen, p->rbuf, &dsz);
			p->rlen = dsz;
			if (ret != 0)
			{
				/* Protocol Error [FATAL] */
				cb_read_gs_error(ctx, p, GS_ERR_FATAL);
				return GS_SUCCESS; // Successfully removed peer
			}
		}

		write_fd(ctx, p);
	}

	return GS_SUCCESS;
}

static int
write_gs(GS_SELECT_CTX *ctx, struct _peer *p)
{
	GS *gs = p->gs;
	int len = 0;

	if (p->wlen > 0)
	{
		len = GS_write(gs, p->wbuf, p->wlen);
		// DEBUGF_R("GS_write(fd==%d) = %d\n", gs->fd, len);
		if (len == 0)
		{
			/* GS_write() would block. */
			FD_CLR(p->fd_in, ctx->rfd);		// Stop reading from input
			return GS_ECALLAGAIN;
		}
	}

	if (len == p->wlen)
	{
		/* GS_write() was a success or p->wlen == 0 */
		p->wlen = 0;
		if (p->is_fd_connected)
		{
			/* SOCKS subsystem calls write_gs() before p->fd_in is connected
			 * Make sure XFD_SET() is only called on a connected() socket.
			 */
			FD_CLR(p->gs->fd, ctx->wfd);
			XFD_SET(p->fd_in, ctx->rfd);	// Start reading from input again
		}
		/* Check if there is any other data we like to write... */
		if (gopt.is_win_resized)
		{
			get_winsize();
			int row = gopt.winsize.ws_row;
			if (gopt.is_console)
				row -= GS_CONSOLE_ROWS; 
			gopt.is_win_resized = 0;
			/* Calls write_gs() */
			return stty_send_wsize(ctx, p, row);
		}
		if (gopt.is_pong_pending)
		{
			gopt.is_pong_pending = 0;
			return send_pong(ctx, p);
		}
		if (gopt.is_want_ping)
		{
			gopt.is_want_ping = 0;
			return send_ping(ctx, p);
		}

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
	XFD_SET(fd_in, ctx->rfd);
	GS_SELECT_add_cb_r(ctx, cb_read_fd, fd_in, p, 0);
	GS_SELECT_add_cb_w(ctx, cb_write_fd, fd_out, p, 0);

	/* And also get ready to read from GS-peer */
	XFD_SET(gs->fd, ctx->rfd);

	p->is_fd_connected = 1;

	/* Write any data that is left in rbuf to fd */
	if (p->rlen > 0)
		write_fd(ctx, p);
}

/*
 * Complete TCP connection to network forward on server side.
 */
static int
cb_complete_connect(GS_SELECT_CTX *ctx, int fd, void *arg, int val)
{
	int ret;
	struct _peer *p = (struct _peer *)arg;

	ret = fd_net_connect(ctx, fd, p->socks.dst_ip, p->socks.dst_port);
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
 * Interactive client only has 1 peer. We need to find
 * it from signal handlers. Set it here.
 */
static struct _peer *my_peer;
static void
cb_sigwinch(int sig)
{
	// DEBUGF("Window Size changed\n");
	XASSERT(my_peer != NULL, "my_peer is NULL. Not client. Not interactive.?\n");
	gopt.is_win_resized = 1;
	GS_SELECT_FD_SET_W(my_peer->gs);
}


/*
 * When console is visible then send a ping more often. Otherwise
 * only if there is no other network i/o for GS_APP_KEEPLIVE usec.
 */
static int
cbe_ping(void *ptr)
{
	GS_EVENT *event = (GS_EVENT *)ptr;
	struct _peer *p = (struct _peer *)event->data;

	if (gopt.is_console == 0)
	{
		// Return if data was transmitted recently
		if (p->gs->ts_net_io + GS_APP_KEEPALIVE >= GS_TV_TO_USEC(&gopt.tv_now))
			return 0;
	}

	cmd_ping(event->data);

	return 0;
}

// Called every second
static int
cbe_bps(void *ptr)
{
	GS_EVENT *event = (GS_EVENT *)ptr;

	// Calculate BPS
	CONSOLE_update_bps((struct _peer *)event->data);

	return 0;
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
	GS_PKT_init(&p->pkt);
	p->w_max = sizeof p->wbuf;
	p->r_max = sizeof p->rbuf;
	if ((gopt.is_interactive))// && !(gopt.flags & GSC_FL_IS_SERVER))
	{
		/* -i: Use of packet protocol needs decoding space */
		p->w_max = sizeof p->wbuf / 2;	/* from fd, to GS */
		p->r_max = sizeof p->rbuf / 2;	/* from fd, to GS */
		if (!(gopt.flags & GSC_FL_IS_SERVER))
		{
			/* CLIENT, interactive */
			my_peer = p;
			signal(SIGWINCH, cb_sigwinch);
			get_winsize();
			GS_EVENT_add_by_ts(&gs->ctx->gselect_ctx->emgr, &gopt.event_ping, 0, GS_APP_PINGFREQ, cbe_ping, p, 0);
			GS_EVENT_add_by_ts(&gs->ctx->gselect_ctx->emgr, &gopt.event_bps, 0, GS_APP_BPSFREQ, cbe_bps, p, 0);
		}
	}
	DEBUGF_M("[ID=%d] (fd=%d) Number of connected gs-peers: %d\n", p->id, fd, gopt.peer_count);

	return p;
}

static void
vlog_hostname(struct _peer *p, const char *desc, uint16_t port)
{
	uint16_t hp = ntohs(port);
	if (hp == 443)
		VLOG("    [ID=%d] %s"D_BLU("%s")":"D_GRE("%d")"\n", p->id, desc, p->socks.dst_hostname, hp);
	else if (hp == 80)
		VLOG("    [ID=%d] %s"D_BLU("%s")":"D_YEL("%d")"\n", p->id, desc, p->socks.dst_hostname, hp);
	else
		VLOG("    [ID=%d] %s"D_BLU("%s")":"D_BRED("%d")"\n", p->id, desc, p->socks.dst_hostname, hp);
}

static int
peer_forward_connect(struct _peer *p, uint32_t ip, uint16_t port)
{
	int ret;
	GS *gs = p->gs;
	GS_SELECT_CTX *ctx = gs->ctx->gselect_ctx;

	vlog_hostname(p, "Forwarding to ", port);
	ret = fd_net_connect(ctx, p->fd_in, ip, port);
	if (ret <= -2)
	{
		peer_free(ctx, p);
		return -1;
	}
	GS_SELECT_add_cb(ctx, cb_complete_connect, cb_complete_connect, p->fd_in, p, 0);
	XFD_SET(p->fd_in, ctx->wfd);	/* Wait for connect() to complete */
	FD_CLR(p->fd_in, ctx->rfd);

	FD_CLR(gs->fd, ctx->rfd);		// Stop reading from GS-peer 

	return 0;
}

/* SERVER - client changed window size. Adjust pty. */
static void
pkt_cb_wsize(uint8_t msg, const uint8_t *data, size_t len, void *ptr)
{
	struct _peer *p = (struct _peer *)ptr;

	uint16_t col, row;

	memcpy(&col, data, 2);
	memcpy(&row, data + 2, 2);

	col = ntohs(col);
	row = ntohs(row);
	DEBUGF_W("cols = %u, rows = %u\n", col, row);

	int ret;
	struct winsize ws;
	ret = ioctl(p->fd_in, TIOCGWINSZ, &ws);
	if (ret != 0)
		DEBUGF_R("ioctrl() %s\n", strerror(errno));
	ws.ws_col = col;
	ws.ws_row = row;
	ret = ioctl(p->fd_in, TIOCSWINSZ, &ws);
	if (ret != 0)
		DEBUGF_R("ioctl()-2 %s\n", strerror(errno));
}

/* SERVER - answer to PING request on channel */
static void
pkt_cb_ping(uint8_t msg, const uint8_t *data, size_t len, void *ptr)
{
	struct _peer *p = (struct _peer *)ptr;

	DEBUGF_C("PING received\n");
	gopt.is_pong_pending = 1;
	GS_SELECT_FD_SET_W(p->gs);
}

/* CLIENT - Answer to PING received */
static void
pkt_cb_pong(uint8_t msg, const uint8_t *data, size_t len, void *ptr)
{
	struct _peer *p = (struct _peer *)ptr;
	struct _app_pong pong;
	// Check if we were waiting at all!
	if (gopt.ts_ping_sent == 0)
		return;

	memcpy(&pong, data, sizeof pong);

	float ms = (float)(GS_TV_TO_USEC(&gopt.tv_now) - gopt.ts_ping_sent) / 1000;

	uint8_t buf[sizeof (pong.user) + 1];
	memcpy(buf, pong.user, sizeof pong.user);
	sanitize_fname_to_str(buf, sizeof buf - 1);

	CONSOLE_update_pinginfo(p, ms, ntohs(pong.load), (char *)buf, ntohs(pong.idle));

	DEBUGF_C("PONG received (% 6.03fms) (load % 4.02f, idle %u)\n", ms, (float)ntohs(pong.load) / 100, ntohs(pong.idle));
	gopt.ts_ping_sent = 0;
}

#if 0
// FIXME: display alarm in xterm title if root logs in?
static void
pkt_cb_title(uint8_t msg, const uint8_t *data, size_t len, void *ptr)
{
	struct _peer *p = (struct _peer *)ptr;

}
#endif

/*
 * SERVER
 */
static struct _peer *
peer_new(GS_SELECT_CTX *ctx, GS *gs)
{
	struct _peer *p;
	int ret;

	p = peer_new_init(gs);

	if (gopt.is_interactive)
	{
		/* SERVER */
		GS_PKT_assign_msg(&p->pkt, PKT_MSG_WSIZE, pkt_cb_wsize, p);
		GS_PKT_assign_msg(&p->pkt, PKT_MSG_PING, pkt_cb_ping, p);
	}

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
	} else if (gopt.is_socks_server != 0) {
		p->fd_in = fd_new_socket();	// SOCKS
		DEBUGF_W("[ID=%d] gs->fd = %d\n", p->id, gs->fd);
		p->fd_out = p->fd_in;
		p->is_network_forward = 1;		
	} else {
		p->fd_in = STDIN_FILENO;	// Forward to STDIN/STDOUT
		p->fd_out = STDOUT_FILENO;
		p->is_stdin_forward = 1;
	}

	if (p->fd_in < 0)
	{
		ERREXIT("Cant create forward...%s\n", GS_strerror(gs));
	}

	if (p->is_network_forward == 0)
	{
		/* STDIN/STDOUT or app-fd always complete immediately */
		completed_connect(ctx, p, p->fd_in, p->fd_out);
	} else {
		if (gopt.is_socks_server)
		{
			ret = SOCKS_init(p);
			if (ret != GS_SUCCESS)
			{
				peer_free(ctx, p);
				return NULL;
			}
		} else {
			/* A straight network forward is as if the SOCKS completed already */
			p->socks.dst_ip = gopt.dst_ip;
			p->socks.dst_port = gopt.port;
			snprintf(p->socks.dst_hostname, sizeof p->socks.dst_hostname, "%s", int_ntoa(p->socks.dst_ip));
			p->socks.state = GSNC_STATE_CONNECTED;

			ret = peer_forward_connect(p, p->socks.dst_ip, p->socks.dst_port);
			if (ret != 0)
				return NULL;

		}
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
			ERREXIT("ERROR: %s.\n", GS_CTX_strerror(gs->ctx)); //Another Server is already listening or Network error.\n");
		/* HERE: GS_accept() is not ready yet to accept() a new
		 * gsocket. (May have processed GS-pkt data) or may have 
		 * closed the socket and established a new one (to wait for
		 * the next connection).
		 */
		return GS_SUCCESS;	/* continue */
	}

	/* Stop accepting more connections if stdin/stdout is used */
	if (gopt.is_multi_peer == 0) //(gopt.cmd == NULL) && (gopt.dst_ip == 0) && (!gopt.is_interactive))
	{
		GS_close(gopt.gsocket);
		gopt.gsocket = NULL;
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

	GS_listen(gopt.gsocket, 1);

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
#if 0
static void
stty_set_remote_size(GS_SELECT_CTX *ctx, struct _peer *p)
{
	snprintf((char *)p->wbuf, sizeof p->wbuf, GS_STTY_INIT_HACK, gopt.winsize.ws_row, gopt.winsize.ws_col);
	p->wlen = (ssize_t)strlen((char *)p->wbuf);
	write_gs(ctx, p);
}
#endif

static int
stty_send_wsize(GS_SELECT_CTX *ctx, struct _peer *p, int row)
{
	p->wbuf[0] = GS_PKT_ESC;
	p->wbuf[1] = PKT_MSG_WSIZE;
	uint16_t c, r;
	c = htons(gopt.winsize.ws_col);
	r = htons(row);
	memcpy(p->wbuf + 2, &c, 2);
	memcpy(p->wbuf + 4, &r, 2);
	p->wlen = 2 + GS_PKT_MSG_size_by_type(PKT_MSG_WSIZE);
	return write_gs(ctx, p);
}

static int
send_pong(GS_SELECT_CTX *ctx, struct _peer *p)
{
	double load;
	uint16_t l = 0;
	struct _app_pong pong;

	p->wbuf[0] = GS_PKT_ESC;
	p->wbuf[1] = PKT_MSG_PONG;

	// Get system load.
	if (getloadavg(&load, 1) == 1)
		l = (uint16_t)(load * 100);

	pong.load = htons(l);
	pong.idle = htons(13);
	for (int i = 0; i < sizeof pong.user; i++)
		pong.user[i] = '0'+i%10;

	// snprintf(ong.user, sizeof pong.user, "roottoor3");

	memcpy(p->wbuf + 2, &pong, sizeof pong);

	p->wlen = 2 + GS_PKT_MSG_size_by_type(PKT_MSG_PONG);
	return write_gs(ctx, p);
}

static int
send_ping(GS_SELECT_CTX *ctx, struct _peer *p)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	gopt.ts_ping_sent = GS_TV_TO_USEC(&tv);
	p->wbuf[0] = GS_PKT_ESC;
	p->wbuf[1] = PKT_MSG_PING;
	p->wlen = 2 + GS_PKT_MSG_size_by_type(PKT_MSG_PING);
	return write_gs(ctx, p);
}


/*
 * CLIENT
 */
static int
cb_connect_client(GS_SELECT_CTX *ctx, int fd_notused, void *arg, int val)
{
	struct _peer *p = (struct _peer *)arg;
	GS *gs = p->gs;
	int ret;

	ret = GS_connect(gs);
	DEBUGF_M("GS_connect(fd=%d) == %d\n", gs->fd, ret);
	if (ret == GS_ERR_FATAL)
	{
		VLOG("%s [ID=%d] %s\n", GS_logtime(), p->id, GS_strerror(gs));
		if (gopt.is_multi_peer == 0)
			exit(255);	// No server listening
		/* This can happen if server accepts 1 connection only but client
		 * wants to open multiple. All but the 1st connection will fail. We shall
		 * not exit but keep the 1 connection alive.
		 * ./gs-netcat -l
		 * ./gs-netcat -p 1080
		 * -> Connection 2x to 127.1:1080 should keep 1st connection alive and 2nd
		 * should (gracefully) fail.
		 */
		peer_free(ctx, p);
		return GS_SUCCESS;
	}
	if (ret == GS_ERR_WAITING)
		return GS_ECALLAGAIN;

	DEBUGF_M("*** GS_connect() SUCCESS *****\n");
	/* HERE: Connection successfully established */
	/* Start reading from Network (SRP is handled by GS_read()/GS_write()) */
	GS_SELECT_add_cb(ctx, cb_read_gs, cb_write_gs, gs->fd, p, 0);

	/* Start reading from STDIN or inbound TCP */
	GS_SELECT_add_cb_r(ctx, cb_read_fd, p->fd_in, p, 0);
	GS_SELECT_add_cb_w(ctx, cb_write_fd, p->fd_out, p, 0);
	XFD_SET(p->fd_in, ctx->rfd);	/* Start reading */
	p->is_fd_connected = 1;

	/* -i specified and we are a client: Set TTY to raw for a real shell
	 * experience. Ignore this for this example.
	 */
	// if ((p->is_stdin_forward) && (gopt.is_interactive))
	// {
	// 	/* HERE: Client */
	// 	DEBUGF_M("Setting tty\n");
	// 	XASSERT(p->fd_in == STDIN_FILENO, "p->fd_in = %d, not STDIN\n", p->fd_in);
	// 	stty_set_raw();
	// 	// stty_set_remote_size(ctx, p);
	// }
	if (gopt.is_interactive)
	{
		stty_send_wsize(ctx, p, gopt.winsize.ws_row);
		GS_PKT_assign_msg(&p->pkt, PKT_MSG_PONG, pkt_cb_pong, p);
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
	DEBUGF_B("GS_connect(GS->fd = %d)\n", GS_get_fd(gs));
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

	fd = fd_net_accept(listen_fd);
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
	struct _peer *p;

	GS_SELECT_CTX_init(&ctx, &gopt.rfd, &gopt.wfd, &gopt.r, &gopt.w, &gopt.tv_now, GS_SEC_TO_USEC(1));
	/* Tell GS_CTX subsystem to use GS-SELECT */
	GS_CTX_use_gselect(&gopt.gs_ctx, &ctx);

	if (gopt.is_multi_peer == 0)
	{
		/* Read/Write from STDIN/STDOUT. No TCP. */
		/* STDIN can be blocking */
		p = gs_and_peer_connect(&ctx, gopt.gsocket, STDIN_FILENO, STDOUT_FILENO);
		p->is_stdin_forward = 1;
	} else {
		GS_SELECT_add_cb(&ctx, cb_accept, cb_accept, gopt.listen_fd, NULL, 0);
		XFD_SET(gopt.listen_fd, ctx.rfd);	/* listening socket */
	}

	int n;
	while (1)
	{
		n = GS_select(&ctx);
		GS_heartbeat(gopt.gsocket);
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

	usage("skrlSgqwCTL");
	fprintf(stderr, ""
"  -S           Act as a Socks server [needs -l]\n"
"  -D           Daemon & Watchdog mode [background]\n"
"  -d <IP>      IPv4 address for port forwarding\n"
"  -p <port>    TCP Port to listen on or forward to\n"
"  -i           Interactive login shell (TTY) [~. to terminate]\n"
"  -e <cmd>     Execute command [e.g. \"bash -il\" or \"id\"]\n"
"  -m           Display man page\n"
"   "
"\n"
"Example to forward traffic from port 2222 to 192.168.6.7:22:\n"
"    $ gs-netcat -l -d 192.168.6.7 -p 22     # Server\n"
"    $ gs-netcat -p 2222                     # Client\n"
"Example to act as a Socks proxy\n"
"    $ gs-netcat -l -S                       # Server\n"
"    $ gs-netcat -p 1080                     # Client\n"
"Example file transfer:\n"
"    $ gs-netcat -l -r >warez.tar.gz         # Server\n"
"    $ gs-netcat <warez.tar.gz               # Client\n"
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
	while ((c = getopt(argc, argv, UTILS_GETOPT_STR "m")) != -1)
	{
		switch (c)
		{
			case 'm':
				printf("%s", man_str);
				exit(0);
				break;	// NOT REACHED
			case 'D':
				gopt.is_daemon = 1;
				break;
			case 'p':
				gopt.port = htons(atoi(optarg));
				gopt.is_multi_peer = 1;
				break;
			case 'e':
				gopt.cmd = optarg;
				gopt.is_multi_peer = 1;
				break;
			case 'd':
				gopt.dst_ip = inet_addr(optarg);
				gopt.is_multi_peer = 1;
				break;
			case 'S':
				gopt.is_socks_server = 1;
				gopt.is_multi_peer = 1;
				gopt.flags |= GSC_FL_IS_SERVER;	// implicit
				break;
			default:
				break;
			case 'A':	// Disable -A for gs-netcat. Use gs-full-pipe instead
			case '?':
				my_usage();
		}
	}

	if (gopt.is_daemon)
	{
		if (gopt.is_logfile == 0)
			gopt.is_quite = 1;
	}

	if (gopt.is_quite != 0)
	{
		gopt.log_fp = NULL;
		gopt.err_fp = NULL;
	}

	if (gopt.flags & GSC_FL_IS_SERVER)
	{
		/* Server side (-i -l) shall be allowed to spawn multiple shells */
		if (gopt.is_interactive)
			gopt.is_multi_peer = 1;
	}
	/* Try to bind port (if listening) now and exit with error on failure
	 * so that we only turn daemon/watchdog if port is available
	 */
	if (!(gopt.flags & GSC_FL_IS_SERVER))
	{
		/* HERE: Client */
		if (gopt.is_multi_peer == 1)
		{
			XASSERT(gopt.port != 0, "Client listening port is 0 but want multple peers.\n");
			gopt.listen_fd = fd_new_socket();
			int ret;
			ret = fd_net_listen(gopt.listen_fd, gopt.port);
			if (ret != 0)
				ERREXIT("Listening on port %d failed: %s\n", ntohs(gopt.port), strerror(errno));
		}
	}

	/* Become a daemon & watchdog (auto-restart)
	 * Do this before init_vars() so that any error in resolving
	 * is re-tried by watchdog.
	 */
	if (gopt.is_daemon)
	{
		gopt.err_fp = gopt.log_fp;	// Errors to logfile or NULL
		GS_daemonize(gopt.log_fp);
	}

	init_vars();			/* from utils.c */
	VLOG("=Encryption     : %s (Prime: %d bits)\n", GS_get_cipher(gopt.gsocket), GS_get_cipher_strength(gopt.gsocket));

	atexit(cb_atexit);
}

static void
my_test(void)
{
	gopt.is_console = 1;

	utmp_monitor();
	// double load;
	// int ret = getloadavg(&load, 1);
	// uint32_t l = (uint32_t)(load * 100);
	// DEBUGF("%d: %f %.02f\n", ret, load, (float)l / 100);
	// uint8_t buf[14];
	// for (int i = 0; i < sizeof buf; i++)
	// 	buf[i] = '0'+i%10;

	// sanitize_fname_to_str(buf, sizeof (buf) - 1);
	// DEBUGF("user = '%s'\n", buf);

#if 0
	char buf[8];
	int64_t i;
	i=3; format_bps(buf, sizeof buf, i); DEBUGF_Y("%12lld rate = '%s/s'\n", i, buf);
	i=36; format_bps(buf, sizeof buf, i); DEBUGF_Y("%12lld rate = '%s/s'\n", i, buf);
	i=999; format_bps(buf, sizeof buf, i); DEBUGF_Y("%12lld rate = '%s/s'\n", i, buf);
	i=1000; format_bps(buf, sizeof buf, i); DEBUGF_Y("%12lld rate = '%s/s'\n", i, buf);
	i=5000; format_bps(buf, sizeof buf, i); DEBUGF_Y("%12lld rate = '%s/s'\n", i, buf);
	i=50000; format_bps(buf, sizeof buf, i); DEBUGF_Y("%12lld rate = '%s/s'\n", i, buf);
	i=500000; format_bps(buf, sizeof buf, i); DEBUGF_Y("%12lld rate = '%s/s'\n", i, buf);
	i=10*1024*1024; format_bps(buf, sizeof buf, i); DEBUGF_Y("%12lld rate = '%s/s'\n", i, buf);
	i=10*(int64_t)1024*1024*1024; format_bps(buf, sizeof buf, i); DEBUGF_Y("%12lld rate = '%s/s'\n", i, buf);
#endif
#if 0
	float ms = 23;
	DEBUGF("[%3dms]\n", (int)ms);
	ms = 987;
	DEBUGF("[%3dms]\n", (int)ms);
	ms = 4253;
	DEBUGF("[%1.01fs ]\n---\n", ms / 1000);

	int load = 45;
	DEBUGF("[% -04.02f]\n", (float)5 / 100); // THIS
	DEBUGF("[% 04.02f]\n", (float)5 / 100); // THIS
	DEBUGF("[% -04.02f]\n", (float)45 / 100); // THIS
	DEBUGF("[% 04.02f]\n", (float)45 / 100); // THIS
	DEBUGF("[% -04.02f]\n", (float)145 / 100); // THIS
	DEBUGF("[% 04.02f]\n", (float)145 / 100); // THIS
	load = 3245;
	// DEBUGF("[% 04.02f]\n", (float)load / 100); // 
	DEBUGF("[% -02.02f]\n", (float)3245 / 100);
	DEBUGF("[%02.02f]\n", (float)3245 / 100); // OK
	DEBUGF("[%- 02.02f]\n", (float)245 / 100); 

#endif
	// DEBUGF("[%4.02f]\n", (float)load / 100); // THIS
	// DEBUGF("[% 4.02f]\n", (float)load / 100);
	// DEBUGF("[%4.02f]\n", (float)load / 100);
	// DEBUGF("[% -4.02f]\n", (float)load / 100);
	exit(0);
}

int
main(int argc, char *argv[])
{
	init_defaults(&argc, &argv);
	my_getopt(argc, argv);

	// my_test();

	if (gopt.flags & GSC_FL_IS_SERVER)
		do_server();
	else
		do_client();

	exit(255);
	return -1;	/* NOT REACHED */
}


