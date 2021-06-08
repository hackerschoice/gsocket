/*
 * EXAMPLE: Blocking & Cleartext ECHO SERVER (via Global Socket).
 *
 * Server:
 * $ ./gs-helloworld -l
 *
 * Client:
 * $ ./gs-helloworld
 *
 * Features:
 * CLEARTEXT TCP
 *		Libgsocket connects two peers through the GS-Network with each other.
 *		Libgsocket then makes the (connected) Unix File Descriptor
 *		(TCP socket) available to the application.
 *
 * 		This examples uses cleartext TCP and read()/write() calls to
 *		exchange data from one peer to the other peer via the GS-Network.
 */
#include "common.h"
#include "utils.h"

/*
 * Read from 'in' and write to 'out'.
 */
static void
relay(int in, int out, const char *str)
{
	char buf[1024];
	char info[64];
	ssize_t rlen, wlen;

	rlen = read(in, buf, sizeof buf);
	if (rlen < 0)
		ERREXIT("closed...(fd = %d, ret = %zd)\n", in, rlen);
	if (rlen == 0)
		exit(0);	/* EOF */

	/* Output information of what we received */
	if (str != NULL)
	{
		snprintf(info, sizeof info, "%zd bytes ", rlen);
		wlen = write(STDOUT_FILENO, info, strlen(info));
		wlen = write(STDOUT_FILENO, str, strlen(str));
		XASSERT(wlen > 0, "write(): %s\n", strerror(errno));
	}
	wlen = write(out, buf, rlen);
	if (wlen <= 0)
		ERREXIT("closed...(fd = %d)\n", out);
}

/*
 * An Echo-Server: Send back whatever is received...
 */
static void
do_server(void)
{
	GS *gs;

	GS_listen(gopt.gsocket, 1);
	gs = GS_accept(gopt.gsocket, NULL);
	if (gs == NULL)
		ERREXIT("%s\n", GS_strerror(gopt.gsocket));

	/* Accepted 1 connection.
	 * The listening socket is no longer needed and we can close it.
	 */
	GS_close(gopt.gsocket);

	int fd = GS_get_fd(gs);
	while (1)
	{
		relay(fd, fd, "From Client\n");
	}

	GS_close(gs);
}


static void
do_client(void)
{
	int ret;

	ret = GS_connect(gopt.gsocket);
	if (ret != 0)
		ERREXIT("%s\n", GS_strerror(gopt.gsocket));

	int fd = GS_get_fd(gopt.gsocket);

	while (1)
	{
		/* Read from STDIN and write to gsocket */
		relay(0, fd, NULL);
		/* Read reply from gsocket and write to STDOUT */
		relay(fd, 1, "From Server: ");
	}

	GS_close(gopt.gsocket);
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
				usage("sklgT");
				exit(EX_UNKNWNCMD);
		}
	}

	gopt.is_no_encryption = 1;	// Do not use end-2-end encryption
	gopt.is_blocking = 1;		// Use blocking sockets

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


	exit(EX_NOTREACHED);
	return -1;	/* NOT REACHED */
}
