/*
 * EXAMPLE: Blocking & Encrypted GS Connection.
 *
 * Read from STDIN on client side and write to STDOUT on server
 * side (via Global Socket).
 *
 * Use encryption.
 *
 * Server:
 * $ ./gs-pipe -l
 *
 * Client:
 * $ ./gs-pipe [-w]
 *
 * Features:
 * SSL
 *		This example uses SSL. Libgsocket completes the SSL handshake
 *		to the peer (end-to-end encryption). Thereafter this example grabs
 *		the SSL object and directly uses SSL_read()/SSL_write() calls to
 *		exchange data between the two peers.
 * GS_OPT_SOCK_WAIT
 *		The normal behaviour for a client is to disconnect when the
 *		peer is not listening. This flag makes the client wait until
 * 		a peer becomes available. It then connects immediately when
 *		the server becomes available.
 *
 *		Effectively it means that the client can be started
 *		before the server: The client waits until the server becomes
 *		available.
 *
 *		The -w command line parameters turns on this feature.
 */
#include "common.h"
#include "utils.h"

static char buf[1024];
SSL *ssl;

/*
 * Read from SSL and write to STDOUT
 */
static void
do_ssl_server(SSL *ssl)
{
	int len;
	ssize_t wlen;
	while (1)
	{
		len = SSL_read(ssl, buf, sizeof buf);
		if (len <= 0)
			break;
		wlen = write(STDOUT_FILENO, buf, len);
		XASSERT(wlen == len, "ERROR write(%d) == %zd: %s\n", len, wlen, strerror(errno));
	}
}

/*
 * Read from STDIN and write to SSL
 */
static void
do_ssl_client(SSL *ssl)
{
	int len;
	while (1)
	{
		len = read(STDIN_FILENO, buf, sizeof buf);
		if (len <= 0)
			break;
		if (SSL_write(ssl, buf, len) <= 0)
			break;
	}
}

/*
 * Application started with -l command line option. This is a
 * (listening) server waiting for client connections.
 */
static void
do_server(void)
{
	GS *gs;

	GS_listen(gopt.gsocket, 1);
	gs = GS_accept(gopt.gsocket, NULL);
	if (gs == NULL)
	{
		ERREXIT("%s\n", GS_strerror(gopt.gsocket));
	}

	/* Accepted 1 GS connection.
	 * The listening GS socket is no longer needed.
	 */
	GS_close(gopt.gsocket);

	/* In this example we operate directly on the SSL socket */
	ssl = gs->ssl;
	do_ssl_server(ssl);
}

/*
 */
static void
do_client(void)
{
	int ret;

	fprintf(stderr, "Reading from standard input....");
	ret = GS_connect(gopt.gsocket);
	if (ret != 0)
		ERREXIT("%s\n", GS_strerror(gopt.gsocket));

	ssl = gopt.gsocket->ssl;

	/* -A flags can make a Client to act as a Server if no server is
	 * listening. This is used for run_all_tests.sh and for the sake
	 * of studying this exampe you can ignore the call to do_ssl_server().
	 */
	if (GS_is_server(gopt.gsocket))
		do_ssl_server(ssl);
	else
		do_ssl_client(ssl);
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
			case '?':
				usage("sklgqwACT");
				exit(EX_UNKNWNCMD);
		}
	}

	gopt.is_blocking = 1;
	init_vars();			/* from utils.c */
	gopt.gsocket = gs_create();

	GS_LOG("=Encryption: %s (Prime: %d bits)\n", GS_get_cipher(gopt.gsocket), GS_get_cipher_strength(gopt.gsocket));
}

int
main(int argc, char *argv[])
{
	init_defaults(&argc, &argv);
	my_getopt(argc, argv);

	if (gopt.flags & GSC_FL_IS_SERVER)
		do_server();
	else
		do_client();

	/* Send all data stuck in SSL output buffer */
	int ret;
	ret = SSL_shutdown(ssl);
	if (ret == 0)
		SSL_read(ssl, buf, sizeof buf);

	exit(EX_NOTREACHED);
	return -1;	/* NOT REACHED */
}