
#include "common.h"
#include "utils.h"

struct _gopt gopt;

void
init_defaults(void)
{
	GS_library_init();

	gopt.is_encryption = 1;
	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);	// no defunct childs please
}

GS *
gs_create(void)
{
	GS *gs = GS_new(&gopt.gs_ctx, &gopt.gs_addr);

	if (gopt.token_str != NULL)
		GS_set_token(gs, gopt.token_str, strlen(gopt.token_str));

	/* If Server is not available yet then wait for Server. */
	if (gopt.is_sock_wait != 0)
		GS_setsockopt(gs, GS_OPT_SOCKWAIT, NULL, 0);

	/* We can turn client _OR_ server */
	if (gopt.is_client_or_server != 0)
		GS_setsockopt(gs, GS_OPT_CLIENT_OR_SERVER, NULL, 0);

	return gs;
}

static void
cb_sigterm(int sig)
{
	exit(255);	// will call cb_atexit()
}

static void
cb_atexit(void)
{
	stty_reset();
}

void
init_vars(void)
{
	int ret;

	ret = GS_CTX_init(&gopt.gs_ctx, &gopt.rfd, &gopt.wfd, &gopt.r, &gopt.w, &gopt.tv_now);

	gopt.sec_str = GS_user_secret(&gopt.gs_ctx, gopt.sec_file, gopt.sec_str);

	fprintf(stderr, "=Secret    : \"%s\"\n", gopt.sec_str);

	/* Convert a secret string to an address */
	GS_ADDR_str2addr(&gopt.gs_addr, gopt.sec_str);
	gopt.gsocket = gs_create();

	DEBUGF("PID = %d\n", getpid());

	signal(SIGTERM, cb_sigterm);
	atexit(cb_atexit);

	ret = ioctl(STDOUT_FILENO, TIOCGWINSZ, &gopt.winsize);
	if ((ret == 0) && (gopt.winsize.ws_col != 0))
	{
		/* SUCCESS */
		DEBUGF_M("Columns: %d, Rows: %d\n", gopt.winsize.ws_col, gopt.winsize.ws_row);
	} else {
			gopt.winsize.ws_col = 80;
			gopt.winsize.ws_row = 24;
	}

}

void
usage(const char *params)
{
	fprintf(stderr, "%s [0x%lxL]\n", OPENSSL_VERSION_TEXT, OPENSSL_VERSION_NUMBER);

	while (*params)
	{
		switch (params[0])
		{
			case 'r':
				fprintf(stderr, "  -r           Receive-only. Terminate when no more data.\n");
				break;
			case 's':
				fprintf(stderr, "  -s <secret>  Secret (e.g. password).\n");
				break;
			case 'k':
				fprintf(stderr, "  -k <file>    Read Secret from file.\n");
				break;
			case 'l':
				fprintf(stderr, "  -l           Listening server [default: client]\n");
				break;
			case 'g':
				fprintf(stderr, "  -g           Generate a Secret (random)\n");
				break;
			case 'a':
				fprintf(stderr, "  -a <token>   Set listen password\n");
				break;
			case 'w':
				fprintf(stderr, "  -w           Wait for server to become available [client only]\n");
				break;
			case 'A':
				fprintf(stderr, "  -A           Be server if no server is listening\n");
				break;
			case 'C':
				fprintf(stderr, "  -C           Disable encryption\n");
				break;
			case 'i':
				fprintf(stderr, "  -i           Interactive login shell (TTY) [~. to terminate]\n");
				break;
			case 'e':
				fprintf(stderr, "  -e <cmd>     Execute command [e.g. \"bash -il\" or \"id\"]\n");
				break;
		}

		params++;
	}
}

void
do_getopt(int argc, char *argv[])
{
	int c;

	opterr = 0;
	while ((c = getopt(argc, argv, UTILS_GETOPT_STR)) != -1)
	{
		switch (c)
		{
			case 'r':
				gopt.is_receive_only = 1;
				break;
			case 'i':
				gopt.is_interactive = 1;
				break;
			case 'C':
				gopt.is_encryption = 0;
				break;
			case 'A':
				gopt.is_client_or_server = 1;
				break;
			case 'w':
				gopt.is_sock_wait = 1;
				break;
			case 'a':
				gopt.token_str = optarg;
				break;
			case 'l':
				gopt.flags |= GSC_FL_IS_SERVER;
				break;
			case 's':
				gopt.sec_str = optarg;
				break;
			case 'k':
				gopt.sec_file = optarg;
				break;
			case 'g':		/* Generate a secret */
				printf("%s", GS_gen_secret());
				fflush(stdout);
				exit(0);
		}
	}

}

// static char stty_val[1024];
static int is_stty_set_raw;
struct termios tios_saved;

/*
 * Save TTY state and set raw mode.
 */
void
stty_set_raw(void)
{
	if (is_stty_set_raw)
		return;

    struct termios tios;
    tcgetattr(STDIN_FILENO, &tios);
    memcpy(&tios_saved, &tios, sizeof tios_saved);
    tios.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
	tios.c_oflag &= ~(OPOST);
	tios.c_cflag |= (CS8);
	tios.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &tios);

#if 0
	FILE *f;
	size_t len;
	int ret;

	f = popen("stty -g", "r");
	if (f == NULL)
	{
		fprintf(stderr, "ERROR popen(stty -g): %s\n", strerror(errno));
		return;
	}

	len = fread(stty_val, 1, sizeof stty_val - 1, f);
	if (len <= 0)
		return;
	stty_val[len] = '\0';

	DEBUGF_B("stty = %s\n", stty_val);

	signal(SIGCHLD, SIG_DFL);
	ret = system("stty raw -echo");
	signal(SIGCHLD, SIG_IGN);
	if (ret < 0)
		fprintf(stderr, "ERROR system(stty raw -echo) == %d: %s\n", ret, strerror(errno));
#endif

	is_stty_set_raw = 1;
}

/*
 * Restore TTY state
 */
void
stty_reset(void)
{
	if (is_stty_set_raw == 0)
		return;

    tcsetattr(STDIN_FILENO, TCSAFLUSH, &tios_saved);
#if 0
	char buf[1024];
	int ret;

	snprintf(buf, sizeof buf, "stty %.512s\n", stty_val);
	signal(SIGCHLD, SIG_DFL);
	ret = system(buf);
	signal(SIGCHLD, SIG_IGN);
	if (ret < 0)
		fprintf(stderr, "ERROR system(stty): %s\n", strerror(errno));
#endif
}

static const char esc_seq[] = "\r~.\r";
static int esc_pos;
/*
 * Check if interactive mode/Client mode and user typed '\n~.\n' escape
 * sequence.
 */
void
stty_check_esc(GS *gs, char c)
{
	if (is_stty_set_raw == 0)
		return;

	// DEBUGF_R("chekcing %d on esc_pos %d == %d\n", c, esc_pos, esc_seq[esc_pos]);
	if (c == esc_seq[esc_pos])
	{
		esc_pos++;
		if (esc_pos < sizeof esc_seq - 1)
			return;

		DEBUGF_M("ESC detected. EXITING...\n");
		/* Hard exit */
		stty_reset();
		exit(0);
		return;
	}
	esc_pos = 0;
	if (c == esc_seq[0])
		esc_pos = 1;
}

/*
 * Return SHELL and shell name (/bin/bash , -bash)
 */
static const char *
mk_shellname(char *shell_name, ssize_t len)
{
	const char *shell = getenv("SHELL");
	if (shell == NULL)
		shell = "/bin/sh";

	char *ptr = strrchr(shell, '/');
	if (ptr == NULL)
	{
		shell = "/bin/sh";
		ptr = "/sh";
	}
	snprintf(shell_name, len, "-%s", ptr + 1);

	return shell;
}

int
pty_cmd(const char *cmd)
{
	pid_t pid;
	int fd;
	
	pid = forkpty(&fd, NULL, NULL, NULL);
	XASSERT(pid >= 0, "Error: fork(): %s\n", strerror(errno));

	if (pid == 0)
	{
		/* HERE: Child */
		int i;
		for (i = 3; i < FD_SETSIZE; i++)
				close(i);

		char shell_name[64];
		const char *shell;
		shell = mk_shellname(shell_name, sizeof shell_name);

		execl(shell, shell_name, "-il", NULL);
		ERREXIT("execlp(%s) failed: %s\n", shell, strerror(errno));
	}
	/* HERE: Parent */

	return fd;
}

/*
 * Spawn a cmd and return fd.
 */
int
fd_cmd(const char *cmd)
{
	pid_t pid;
	int fd = -1;
	int fds[2];
	int ret;

#if 1
	if (gopt.is_interactive)
	{
		return pty_cmd(cmd);
	}
#endif

	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
	if (ret != 0)
		ERREXIT("pipe(): %s\n", strerror(errno));	/* FATAL */

	pid = fork();
	if (pid < 0)
		ERREXIT("fork(): %s\n", strerror(errno));	/* FATAL */

	if (pid == 0)
	{
		/* HERE: Child process */
		signal(SIGCHLD, SIG_DFL);
		/* Close all (but 1 end of socketpair) fd's */
		fd = fds[0];
		int i;
		for (i = 0; i < FD_SETSIZE; i++)
		{
			if (i != fd)
				close(i);
		}

		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);
		dup2(fd, STDIN_FILENO);
#if 0		
        if (gopt.is_interactive)
        {
                setpgid(0, 0);
                /* Spawn an interactive PTY default shell */
				char shell_name[64];
                const char *shell;
                shell = mk_shellname(shell_name, sizeof shell_name);

#ifdef BSD_SCRIPT
                execlp("script", shell_name, "-q", "/dev/null", shell, "-il", NULL);
#else
                char buf[64]; snprintf(buf, sizeof buf, "%s -il", shell);
                execlp("script", shell_name, "-qc", buf, "/dev/null", NULL);
#endif
        } else {
                execl("/bin/sh", cmd, "-c", cmd, NULL);
        }
#endif
		execl("/bin/sh", cmd, "-c", cmd, NULL);
		ERREXIT("exec(%s) failed: %s\n", cmd, strerror(errno));
	}

	/* HERE: Parent process */
	close(fds[0]);
	fd = fds[1];

	return fd;
}

#ifdef DEBUG
#ifndef int_ntoa
static const char *
int_ntoa(uint32_t ip)
{
	struct in_addr in;

	in.s_addr = ip;
	return inet_ntoa(in);
}
#endif
#endif

/*
 * Complete the connect() call
 * Return -1 on waiting.
 * Return -2 on fatal.
 */
int
fd_net_connect(GS_SELECT_CTX *ctx, int fd, uint32_t ip, uint16_t port)
{
	struct sockaddr_in addr;
	int ret;

	memset(&addr, 0, sizeof addr);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = ip;
	addr.sin_port = port;
	ret = connect(fd, (struct sockaddr *)&addr, sizeof addr);
	DEBUGF("connect(%s, fd = %d): %d (errno = %d)\n", int_ntoa(ip), fd, ret, errno);
	if (ret != 0)
	{
		if ((errno == EINPROGRESS) || (errno == EAGAIN) || (errno == EINTR))
		{
			FD_SET(fd, ctx->wfd);
			return -1;
		}
		if (errno != EISCONN)
		{
			DEBUGF_R("ERROR %s\n", strerror(errno));
			// gs_set_error(gsocket->ctx, "connect(%s:%d)", int_ntoa(ip), ntohs(port));
			return -2;
		}
	}
	/* HERRE: ret == 0 or errno == EISCONN (Socket is already connected) */
	DEBUGF_G("connect(fd = %d) SUCCESS (errno = %d)\n", fd, errno);

	return 0;
}

int
fd_net_accept(GS_SELECT_CTX *ctx, int listen_fd)
{
	int sox;
	int ret;

	sox = accept(listen_fd, NULL, NULL);
	if (sox < 0)
		return -2;

	ret = fcntl(sox, F_SETFL, O_NONBLOCK | fcntl(sox, F_GETFL, 0));
	if (ret != 0)
		return -2;

	return sox;
}

/*
 * Create a listening fd on port.
 */
int
fd_net_listen(GS_SELECT_CTX *ctx, int fd, uint16_t port)
{
	struct sockaddr_in addr;
	int ret;

	memset(&addr, 0, sizeof addr);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = port;

	ret = bind(fd, (struct sockaddr *)&addr, sizeof addr);
	if (ret < 0)
		return ret;

	ret = listen(fd, 1);
	if (ret != 0)
		return -1;

	return 0;
}

/*
 * Return fd on success.
 * Return < 0 on fata error.
 */
int
fd_new_socket(void)
{
	int fd;
	int ret;

	fd = socket(PF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return -2;

	ret = fcntl(fd, F_SETFL, O_NONBLOCK | fcntl(fd, F_GETFL, 0));
	if (ret != 0)
		return -2;

	return fd;
}


