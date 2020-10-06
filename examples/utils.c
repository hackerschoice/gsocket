
#include "common.h"
#include "utils.h"

struct _gopt gopt;

extern char **environ;

/*
 * Add list of argv's from GSOCKET_ARGS to argv[]
 */
static void
add_env_argv(int *argcptr, char **argvptr[])
{
	char *str = getenv("GSOCKET_ARGS");
	char *next = str;
	char **newargv;
	int newargc;

	if (str == NULL)
		return;

	newargv = malloc(*argcptr * sizeof *argvptr);
	memcpy(newargv, *argvptr, *argcptr * sizeof *argvptr);
	newargc = *argcptr;

	while (next != NULL)
	{
		while (*str == ' ')
			str++;

		next = strchr(str, ' ');
		if (next != NULL)
		{
			*next = 0;
			next++;
		}
		DEBUGF("arg = '%s'\n", str);
		/* *next == '\0'; str points to argument (0-terminated) */
		newargc++;
		newargv = realloc(newargv, newargc * sizeof newargv);
		newargv[newargc - 1] = str;

		str = next;
		if (str == NULL)
			break;
	}

	*argcptr = newargc;
	*argvptr = newargv;
	DEBUGF("Total argv[] == %d\n", newargc);
}

void
init_defaults(int *argcptr, char **argvptr[])
{
	GS_library_init();

	gopt.log_fp = stderr;
	gopt.err_fp = stderr;
	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);	// no defunct childs please

	/* MacOS process limit is 256 which makes Socks-Proxie yield...*/
	struct rlimit rlim;
	memset(&rlim, 0, sizeof rlim);
	int ret;
	ret = getrlimit(RLIMIT_NOFILE, &rlim);
	if (ret == 0)
	{
		rlim.rlim_cur = MIN(rlim.rlim_max, FD_SETSIZE);
		ret = setrlimit(RLIMIT_NOFILE, &rlim);
		getrlimit(RLIMIT_NOFILE, &rlim);
		// DEBUGF_C("Max File Des: %llu (max = %llu)\n", rlim.rlim_cur, rlim.rlim_max);
	}

	add_env_argv(argcptr, argvptr);
}

GS *
gs_create(void)
{
	GS *gs = GS_new(&gopt.gs_ctx, &gopt.gs_addr);

	if (gopt.token_str != NULL)
		GS_set_token(gs, gopt.token_str, strlen(gopt.token_str));

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

	if (gopt.is_use_tor == 1)
		GS_CTX_setsockopt(&gopt.gs_ctx, GS_OPT_USE_SOCKS, NULL, 0);
	/* If Server is not available yet then wait for Server. */
	if (gopt.is_sock_wait != 0)
		GS_CTX_setsockopt(&gopt.gs_ctx, GS_OPT_SOCKWAIT, NULL, 0);

	/* We can turn client _OR_ server */
	if (gopt.is_client_or_server != 0)
		GS_CTX_setsockopt(&gopt.gs_ctx, GS_OPT_CLIENT_OR_SERVER, NULL, 0);

	/* Disable encryption (-C) */
	if (gopt.is_no_encryption == 1)
		GS_CTX_setsockopt(&gopt.gs_ctx, GS_OPT_NO_ENCRYPTION, NULL, 0);

	/* This example uses blocking sockets. Set blocking. */
	if (gopt.is_blocking == 1)
		GS_CTX_setsockopt(&gopt.gs_ctx, GS_OPT_BLOCK, NULL, 0);


	gopt.sec_str = GS_user_secret(&gopt.gs_ctx, gopt.sec_file, gopt.sec_str);

	VLOG("=Secret    : \"%s\"\n", gopt.sec_str);

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
			case 'L':
				fprintf(stderr, "  -L <file>    Logfile\n");
				break;
			case 'q':
				fprintf(stderr, "  -q           Quite. No log output\n");
				break;
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
			case 'T':
				fprintf(stderr, "  -T           Use TOR.\n");
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
			case 'L':
				gopt.log_fp = fopen(optarg, "a");
				if (gopt.log_fp == NULL)
					ERREXIT("fopen(%s): %s\n", optarg, strerror(errno));
				break;
			case 'T':
				gopt.is_use_tor = 1;
				break;
			case 'q':
				gopt.log_fp = NULL;
				break;
			case 'r':
				gopt.is_receive_only = 1;
				break;
			case 'i':
				gopt.is_interactive = 1;
				break;
			case 'C':
				gopt.is_no_encryption = 1;
				break;
			case 'A':
				gopt.is_client_or_server = 1;
				break;
			case 'w':
				gopt.is_sock_wait = 1;
				break;
			case 'a':
				/* This only becomes secure when the initial GS-network connection is done by TLS
				 * (at least for the listening server to submit the token securely to the server so that
				 * the server rejects any listening attempt that uses a bad token)
				 */
				VLOG("*** WARNING *** -a not fully supported yet. Trying our best...\n");
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
				printf("%s\n", GS_gen_secret());
				fflush(stdout);
				exit(0);
		}
	}

}

// static char stty_val[1024];
static int is_stty_set_raw;
struct termios tios_saved;

/*
 * Client only: Save TTY state and set raw mode.
 */
void
stty_set_raw(void)
{
	int ret;
	if (is_stty_set_raw)
		return;

	if (!isatty(STDIN_FILENO))
		return;

    struct termios tios;
    ret = tcgetattr(STDIN_FILENO, &tios);
    if (ret != 0)
    	return;
    memcpy(&tios_saved, &tios, sizeof tios_saved);
    tios.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
	tios.c_oflag &= ~(OPOST);
	tios.c_cflag |= (CS8);
	tios.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &tios);

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

/*
 * Create an envp list from existing env. This is a hack for cmd-execution.
 * 'blacklist' contains env-vars which should not be part of the new
 * envp for the shell (such as STY, a screen variable, which we must remove).
 */
char **
mk_env(char **blacklist)
{
	char **env;
	int total = 0;
	int i;
	char *end;

	for (i = 0; environ[i] != NULL; i++)
	{
		total++;
	}
	// DEBUGF("Number of environment variables: %d (calloc(%d, %zu)\n", total, total + 1, sizeof *env);

	env = calloc(total + 1, sizeof *env);

	int ii = 0;
	for (i = 0; i < total; i++)
	{
		char *s = environ[i];

		/* Check if we want this env variable and continue if not */
		end = strchr(s, '=');
		if (end == NULL)
			continue;			// Illegal enviornment variable
		char **b = blacklist;
		for (; *b != NULL; b++)
		{
			if (end - s > strlen(*b))
				continue;
			if (memcmp(s, *b, end - s) == 0)
				break;			// In the blacklist
		}
		if (*b != NULL)
			continue;			// Skip if in blacklist

		env[ii] = strdup(s);
		ii++;
	}

	return env;
}

static void
setup_cmd_child(void)
{
	/* Close all (but 1 end of socketpair) fd's */
	int i;
	for (i = 3; i < FD_SETSIZE; i++)
		close(i);

	signal(SIGCHLD, SIG_DFL);
	signal(SIGPIPE, SIG_DFL);
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
		setup_cmd_child();

		char *env_blacklist[] = {"STY", NULL};
		char **envp = mk_env(env_blacklist);

		char shell_name[64];
		const char *shell;
		shell = mk_shellname(shell_name, sizeof shell_name);

		execle(shell, shell_name, "-il", NULL, envp);
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
		dup2(fds[0], STDOUT_FILENO);
		dup2(fds[0], STDERR_FILENO);
		dup2(fds[0], STDIN_FILENO);
		setup_cmd_child();

		execl("/bin/sh", cmd, "-c", cmd, NULL);
		ERREXIT("exec(%s) failed: %s\n", cmd, strerror(errno));
	}

	/* HERE: Parent process */
	close(fds[0]);

	return fds[1];
}

// #ifndef int_ntoa
// const char *
// int_ntoa(uint32_t ip)
// {
// 	struct in_addr in;

// 	in.s_addr = ip;
// 	return inet_ntoa(in);
// }
// #endif


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
	DEBUGF("connect(%s:%d, fd = %d): %d (errno = %d)\n", int_ntoa(ip), ntohs(port), fd, ret, errno);
	if (ret != 0)
	{
		if ((errno == EINPROGRESS) || (errno == EAGAIN) || (errno == EINTR))
		{
			XFD_SET(fd, ctx->wfd);
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
fd_net_accept(int listen_fd)
{
	int sox;
	int ret;

	sox = accept(listen_fd, NULL, NULL);
	DEBUGF_B("accept(%d) == %d\n", listen_fd, sox);
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
fd_net_listen(int fd, uint16_t port)
{
	struct sockaddr_in addr;
	int ret;

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof (int));

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
	DEBUGF_W("socket() == %d\n", fd);

	ret = fcntl(fd, F_SETFL, O_NONBLOCK | fcntl(fd, F_GETFL, 0));
	if (ret != 0)
		return -2;

	return fd;
}


