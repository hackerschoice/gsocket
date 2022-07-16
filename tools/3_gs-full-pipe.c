/*
 * EXAMPLE: Bi-directional encrypted GS-Connection
 *
 * Client:
 * - Read from STDIN and send to server.
 * - Read from Server and write to STDOUT
 * Server: dito
 *
 * Server:
 * $ ./gs-full-pipe -A
 *
 * Client:
 * $ ./gs-full-pipe -A
 *
 * FEATURES:
 * GS_OPT_CLIENT_OR_SERVER
 *      Client to become server if no server is available.
 * GS_SELECT
 *      Framework to deal with OpenSSL's insane non-blocking
 *      behaviour and switching encryption off (-C).
 */

#include "common.h"
#include "utils.h"

static ssize_t stdin_len;
static char stdin_buf[1024];//2*16*1024];

static int write_gs(GS_SELECT_CTX *ctx, GS *gs);
static void do_exit(GS_SELECT_CTX *ctx, GS *gs);

static int
shutdown_net(GS *gs)
{
	int ret;
	ret = GS_shutdown(gs);
	DEBUGF_G("GS_shutdown() = %d\n", ret);

	if (ret == 0)
		return GS_SUCCESS;

	if (ret == -1)	/* Waiting */
		return GS_ECALLAGAIN;

	return -2;
}

/******* STDIN I/O ********************/
static int
cb_read_stdin(GS_SELECT_CTX *ctx, int fd, void *arg, int val)
{
	GS *gs = (GS *)arg;
	int ret;

	XASSERT(stdin_len <= 0, "Already data in input buffer (%zd)\n", stdin_len);
	stdin_len = read(0, stdin_buf, sizeof stdin_buf);
	// DEBUGF_M("Read %zd\n", stdin_len);
	if (stdin_len <= 0)
	{
		DEBUGF_R("STDIN EOF (%zd)\n", stdin_len);

		FD_CLR(0, ctx->rfd);	// Stop reading from STDIN
		fd_kernel_flush(gs->fd);
		// flush_kernel_buffer(gs->fd);
		// // FIXME: Test 5.5 fails if we do not call usleep() here but before fixing kernel-flush in gsrnd...
		// if (GS_is_server(gs))
		// 	usleep(50 * 1000);
		ret = shutdown_net(gs);
		DEBUGF("shutdown_net() == %d\n", ret);
		if (ret == GS_ECALLAGAIN)
			return GS_ECALLAGAIN;

		if (ret == -2)
			do_exit(ctx, gs);

		return GS_SUCCESS;
	}
	if ((gopt.is_interactive) && !(gopt.flags & GSC_FL_IS_SERVER))
		stty_check_esc(gs, stdin_buf[0]);

	write_gs(ctx, gs);

	return GS_SUCCESS;
}

/******* NETWORK I/O ******************/

/*
 * Write data to Server
 */
static int
write_gs(GS_SELECT_CTX *ctx, GS *gs)
{
	int ret; 
	ret = GS_write(gs, stdin_buf, stdin_len);
	DEBUGF_G("GS_write(fd = %d, len = %zd) = %d\n", gs->fd, stdin_len, ret);

	if (ret == 0)
	{
		FD_CLR(0, ctx->rfd);	// Stop reading from STDIN
		return GS_ECALLAGAIN;
	}

	if (ret == stdin_len)
	{
		stdin_len = 0;
		FD_SET(0, ctx->rfd);	// Start reading from STDIN
		return GS_SUCCESS;
	}

	if (ret > 0)
	{
		memmove(stdin_buf, stdin_buf + ret, stdin_len - ret);
		stdin_len -= ret;
		DEBUGF("LEFT %zu\n", stdin_len);
		FD_CLR(0, ctx->rfd);
		FD_SET(gs->fd, ctx->wfd);
		return GS_ECALLAGAIN;
	}


	if (ret > 0)
		ERREXIT("Partial write(%zd) == %d. Should not happen (%s)\n", stdin_len, ret, strerror(errno));

	ERREXIT("Fatal write error. FIXME: reconnect?(%s)\n", strerror(errno));

	return GS_ERROR;	/* NOT REACHED */
}

static void
do_exit(GS_SELECT_CTX *ctx, GS *gs)
{
	GS_SELECT_del_cb(ctx, STDIN_FILENO);	// Stop reading from STDIN
	GS_close(gs);
	stty_reset();
	exit(0);
}

/*
 * CallBack when Network is ready for reading.
 */
static int
cb_read_gs(GS_SELECT_CTX *ctx, int fd, void *arg, int val)
{
	GS *gs = (GS *)arg;

	// DEBUGF_G("cb_read_gs(fd = %d)\n", fd);
	ssize_t len;
	ssize_t wlen;
	char buf[1024];
	len = GS_read(gs, buf, sizeof buf);
	// DEBUGF_Y("GS_read() = %zd\n", len);
	if (len == 0)
		return GS_ECALLAGAIN;

	if (len == GS_ERR_EOF)
	{
		shutdown(STDOUT_FILENO, SHUT_WR);
		if (gopt.is_receive_only)
			do_exit(ctx, gs);
		return GS_SUCCESS;
	}

	if (len < 0) /* any ERROR (but EOF) */
	{
		GS_shutdown(gs);
		/* Finish peer on FATAL (2nd EOF) or if half-duplex (never send data) */
		do_exit(ctx, gs);
		return GS_SUCCESS;	/* NOT REACHED */
	}

	wlen = write(STDOUT_FILENO, buf, len);
	XASSERT(wlen == len, "ERROR write(%zd) == %zd: %s\n", len, wlen, strerror(errno));
	return GS_SUCCESS;
}

/*
 * CallBack when Network is ready for writing.
 */
static int
cb_write_gs(GS_SELECT_CTX *ctx, int fd, void *arg, int val)
{
	return write_gs(ctx, (GS *)arg);
}

/*
 * A hack to set the remote window size without inband
 * communication. Only used with -i.
 */
static void
stty_set_remote_size(GS_SELECT_CTX *ctx, GS *gs)
{
	snprintf(stdin_buf, sizeof stdin_buf, GS_STTY_INIT_HACK, gopt.winsize.ws_row, gopt.winsize.ws_col);
	stdin_len = strlen(stdin_buf);
	write_gs(ctx, gs);
}

static int
cb_connect_client(GS_SELECT_CTX *ctx, int fd, void *arg, int val)
{
	GS *gs = (GS *)arg;
	int ret;

	DEBUGF("called\n");
	ret = GS_connect(gs);
	if (ret == GS_ERR_FATAL)
		ERREXIT("%s\n", GS_strerror(gs));
	//Fatal GS_connect() error\n");
	if (ret == GS_ERR_WAITING)
		return GS_ECALLAGAIN;

	/* HERE: Connection successfully established */
	/* Define which function to call if ECALLGAGAIN happens */
	/* Start reading from Network (SRP is handled by GS_read()/GS_write()) */
	GS_SELECT_add_cb(ctx, cb_read_gs, cb_write_gs, fd, gs, 0);

	/* Start reading from STDIN */
	GS_SELECT_add_cb_r(ctx, cb_read_stdin, STDIN_FILENO, gs, 0);
	FD_SET(0, ctx->rfd);	/* Start reading from STDIN */

	/* -i specified and we are a client: Set TTY to raw for a real shell
	 * experience. Ignore this for this example.
	 */
	if ((gopt.is_interactive) && (!GS_is_server(gs)))
	{
		stty_set_raw();
		stty_set_remote_size(ctx, gs);
	}

	return GS_SUCCESS;
}

static void
do_client_or_server(void)
{
	GS_SELECT_CTX ctx;
	GS *gs = gopt.gsocket;

	GS_SELECT_CTX_init(&ctx, &gopt.rfd, &gopt.wfd, &gopt.r, &gopt.w, &gopt.tv_now, GS_SEC_TO_USEC(1));
	/* Tell GS_ subsystem to use GS-SELECT */
	GS_CTX_use_gselect(&gopt.gs_ctx, &ctx);

	/* Will return GS_ERR_WAITING */
	GS_connect(gs);	

	DEBUGF("fd = %d\n", GS_get_fd(gs));
	/* Call when socket becomes read- or writeable [connection established] */
	GS_SELECT_add_cb_r(&ctx, cb_connect_client, GS_get_fd(gs), gs, 0);
	GS_SELECT_add_cb_w(&ctx, cb_connect_client, GS_get_fd(gs), gs, 0);

	int n;
	while (1)
	{
		n = GS_select(&ctx);
		GS_heartbeat(gopt.gsocket);
		if (n < 0)
			break;
	}
	ERREXIT("NOT REACHED\n");

	GS_close(gs);
}

static void
my_getopt(int argc, char *argv[])
{
	int c;

	do_getopt(argc, argv);	/* from utils.c */
	optind = 1;
	while ((c = getopt(argc, argv, UTILS_GETOPT_STR)) != -1)
	{
		switch (c)
		{
			default:
				break;
			case 'l':	/* -l not allowed for full pipe */
			case '?':
				usage("skrgqwACTi");
				exit(EX_UNKNWNCMD);
		}
	}

	init_vars();			/* from utils.c */
	gopt.gsocket = gs_create();

	GS_LOG("=Encryption     : %s (Prime: %d bits)\n", GS_get_cipher(gopt.gsocket), GS_get_cipher_strength(gopt.gsocket));
}

int
main(int argc, char *argv[])
{
	init_defaults(&argc, &argv);
	my_getopt(argc, argv);

	do_client_or_server();

	exit(EX_NOTREACHED);
	return -1;	/* NOT REACHED */
}