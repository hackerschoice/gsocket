
#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <libgen.h>
#ifdef __CYGWIN__
# include <sys/cygwin.h>
# include <windows.h>
#endif
// #include <gsocket/gsocket.h>

static int is_init;
static int is_debug;
static int is_nohijack;

struct _fd_info
{
	struct sockaddr_in addr;
	int is_bind;
	int is_connect;
	int is_listen;
	uint16_t port;
};

static struct _fd_info fd_list[FD_SETSIZE];

#define DEBUGF(a...) do { if (is_debug == 0){break;} fprintf(stderr, "LDP %d:", __LINE__); fprintf(stderr, a); }while(0)

#ifdef __CYGWIN__
# define RTLD_NEXT dl_handle
static void *dl_handle;
static void
thc_init_cyg(void)
{
	dl_handle = dlopen("cygwin1.dll", RTLD_LAZY);
}
#else	/* !__CYGWIN__ */
static void thc_init_cyg(void) {}	// Do nothing.
#endif

typedef int (*real_bind_t)(int sox, const struct sockaddr *addr, socklen_t addr_len);
static int real_bind(int sox, const struct sockaddr *addr, socklen_t addr_len) { return ((real_bind_t)dlsym(RTLD_NEXT, "bind"))(sox, addr, addr_len); }
typedef int (*real_listen_t)(int sox, int backlog);
static int real_listen(int sox, int backlog) { return ((real_listen_t)dlsym(RTLD_NEXT, "listen"))(sox, backlog); }

static void
thc_init(void)
{
	if (is_init)
		return;

	thc_init_cyg();

	DEBUGF("%s called\n", __func__);
	if (getenv("GSOCKET_DEBUG"))
		is_debug = 1;

	if (getenv("_GSOCKET_NOHIJACK"))
		is_nohijack = 1;

	is_init = 1;
}

typedef int (*real_close_t)(int fd);
static int real_close(int fd) { return ((real_close_t)dlsym(RTLD_NEXT, "close"))(fd); }
static int
thc_close(const char *fname, int fd)
{
	if (fd >= 0)
	{
		fd_list[fd].is_connect = 0;
		fd_list[fd].is_bind = 0;
		fd_list[fd].is_listen = 0;
	}

	return real_close(fd);
}


typedef int (*real_connect_t)(int sox, const struct sockaddr *addr, socklen_t addr_len);
static int real_connect(int sox, const struct sockaddr *addr, socklen_t addr_len) { return ((real_connect_t)dlsym(RTLD_NEXT, "connect"))(sox, addr, addr_len); }
static int
thc_connect(const char *fname, int sox, const struct sockaddr *addr, socklen_t addr_len)
{
	uint16_t port;
	int rv;
	struct sockaddr_in *a;
	int fds[2];
	struct _fd_info *fdi;

	thc_init();

	if ((sox < 0) || (addr == NULL))
		return real_connect(sox, addr, addr_len);

	fdi = &fd_list[sox];

	// Check if bind() was called before connect().
	// bind() was prepared for 'listen' and bind() to a random port number.
	// For 'connect()' we do not want this. Undo.
	if (fdi->is_bind)
	{
		DEBUGF("FUCKME! Who does this\n");
		real_bind(sox, (struct sockaddr *)&fdi->addr, sizeof fdi->addr);
	}

	// GSOCKET_NOHIJACK is set...call original function immediately.
	int is_call_orig = 0;
	if (addr->sa_family == AF_INET)
	{
		if (((struct sockaddr_in *)addr)->sin_addr.s_addr != inet_addr("127.31.33.7"))
			is_call_orig = 1;
	} else {
		is_call_orig = 1;
	}
	if ((is_call_orig) || (is_nohijack))
		return real_connect(sox, addr, addr_len);

	fdi = &fd_list[sox];
	a = &fdi->addr;

	if (fdi->is_connect)
	{
		// Non-Blocking socket might call connect() until it's connected.
		return real_connect(sox, (struct sockaddr *)a, sizeof *a);
	}

	memset(a, 0, sizeof *a);
	a->sin_family = AF_INET;
	a->sin_addr.s_addr = inet_addr("127.0.0.1");

	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

	pid_t pid;
	pid = fork();
	if (pid < 0)
		return -1;

	if (pid == 0)
	{

		int i;
		for (i = 3; i < FD_SETSIZE; i++)
		{
			if (i == fds[0])
				continue;
			close(i);
		}

		int ls;
		ls = socket(PF_INET, SOCK_STREAM, 0);
		if (ls < 0)
			exit(255);
		setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof (int));
		a->sin_port = 0;

		rv = real_bind(ls, (struct sockaddr *)a, sizeof *a);
		if (rv < 0)
			exit(255);
		struct sockaddr_in paddr;
		socklen_t plen = sizeof addr;
		rv = getsockname(ls, (struct sockaddr *)&paddr, &plen);
		port = ntohs(paddr.sin_port);
		DEBUGF("pid=%d Child listening on %u instead\n", getpid(), port);

		rv = real_listen(ls, 5);
		if (rv != 0)
			exit(255);

		write(fds[0], &port, sizeof port); // Send listening port to parent process

		DEBUGF("MARK ls=%d\n", ls);
		sox = accept(ls, NULL, NULL);
		DEBUGF("accepting new conn %d\n", sox);
		if (sox < 0)
			exit(255);
		close(ls);

		dup2(sox, STDOUT_FILENO);
		dup2(sox, STDIN_FILENO);
		// dup2(sox, STDERR_FILENO);
		// close(STDERR_FILENO);

		setenv("_GSOCKET_NOHIJACK", "1", 1);
		execlp("gs-netcat", "gs-netcat", "-s", "AD9GTBbL2VuapMHXUs6Fnt", NULL);
		// execl("/usr/local/bin/nc", "/usr/local/bin/nc", "127.0.0.1", "31337", NULL);
		DEBUGF("FAILED\n");

		// CHILD
		exit(255); // NOT REACHED
	}

	// PARENT
	close(fds[0]);
	if (read(fds[1], &port, sizeof port) != sizeof port)
		return -1;
	close(fds[1]);

	DEBUGF("Connecting to %u instead (sox=%d)\n", port, sox);
	a->sin_port = htons(port);

FIXME: solve this race condition with non-blocking sockets
	sleep(1); // FIXME: give child time to call accept()
	rv = real_connect(sox, (struct sockaddr *)a, sizeof *a);
	DEBUGF("real_connect()=%d\n", rv);
	fdi->is_connect = 1;

	return rv;
}

static void
gs_mgr_listen(const char *secret, uint16_t port)
{
	// Contact the GS-MGR and send him our port and secret (via local socket controller by this user! not tcp)
	// or use IPC / socketpair (FIXME: implement this!)

	// Quick hack for now is fork & gs-netcat pipe
	pid_t pid;

	pid = fork();
	if (pid < 0)
		return;
	if (pid == 0)
	{
		// CHILD

		int i;
		for (i = 3; i < FD_SETSIZE; i++)
			close(i);

		char port_str[16];
		snprintf(port_str, sizeof port_str, "%u", port);
		setenv("_GSOCKET_NOHIJACK", "1", 1);
		execlp("gs-netcat", "gs-netcat", "-s", secret, "-l", "-d", "127.0.0.1", "-p", port_str, NULL);
		DEBUGF("FAILED\n");

		exit(255); // NOT REACHED
	}
}

static int
thc_bind(const char *fname, int sox, const struct sockaddr *addr, socklen_t addr_len)
{
	struct sockaddr_in *a;
	int rv;
	struct _fd_info *fdi;

	thc_init();

	if ((sox < 0) || (addr == NULL))
		return real_bind(sox, addr, addr_len);

	fdi = &fd_list[sox];
	if ((is_nohijack) || (fdi->is_bind))
		return real_bind(sox, addr, addr_len);

	DEBUGF("FOOBAR\n");

	int is_call_hijack = 0;
	if (addr->sa_family == AF_INET)
	{

		if (((struct sockaddr_in *)addr)->sin_addr.s_addr == inet_addr("127.31.33.7"))
			is_call_hijack = 1;
		if (((struct sockaddr_in *)addr)->sin_port == ntohs(31337))
			is_call_hijack = 1;
	}

	if (is_call_hijack == 0)
		return real_bind(sox, (struct sockaddr *)addr, addr_len);

	// Backup original address in case this bind() is followed by connect() and not listen().
	memcpy(&fdi->addr, addr, sizeof fdi->addr);

	a = (struct sockaddr_in *)addr;

	a->sin_addr.s_addr = inet_addr("127.0.0.1");
	a->sin_port = 0; // Pick any port at random.
	rv = real_bind(sox, (struct sockaddr *)a, sizeof *a);
	if (rv != 0)
		return rv;

	struct sockaddr_in paddr;
	socklen_t plen = sizeof addr;
	rv = getsockname(sox, (struct sockaddr *)&paddr, &plen);
	uint16_t port = ntohs(paddr.sin_port);
	DEBUGF("Bind to port=%u (rv=%d)\n", port, rv);
	fdi->port = port;
	fdi->is_bind = 1;

	return 0;
}

static int
thc_listen(const char *fname, int sox, int backlog)
{
	struct _fd_info *fdi;

	thc_init();

	if (sox < 0)
		return real_listen(sox, backlog);

	fdi = &fd_list[sox];

	if ((is_nohijack) || (fdi->is_listen))
		return real_listen(sox, backlog);

	// Try to connect to gs_manager 
// STOP HERE: Start gs-netcat in child process to TCP forward to my local port number
// which secret to use? should it be SECRET+PORT?
// Setting _GSOCKET_NOHIJACK makes sense for now so we can hijack all LISTEN calls.

	fdi->is_listen = 1;
	// Send Secret and listening port to manager
	gs_mgr_listen("AD9GTBbL2VuapMHXUs6Fnt", fdi->port);

	return real_listen(sox, backlog);
}


// HOOKS
#ifndef __CYGWIN__
int connect(int socket, const struct sockaddr *addr, socklen_t addr_len) {return thc_connect(__func__, socket, addr, addr_len); }
int close(int fd) {return thc_close(__func__, fd); }
int bind(int socket, const struct sockaddr *addr, socklen_t addr_len) {return thc_bind(__func__, socket, addr, addr_len); }
int listen(int socket, int backlog) {return thc_listen(__func__, socket, backlog); }
#endif

#ifdef __CYGWIN__
static int fci_connect(int socket, const struct sockaddr *addr, socklen_t addr_len) {return thc_connect("connect", socket, addr, addr_len); }
static int fci_close(int fd) {return thc_close("close", fd); }
static int fci_bind(int fd, sockaddr *addr, socklen_t addr_len) {return thc_bind("bind", fd, addr, addr_len); }
static int fci_listen(int socket, int backlog) {return thc_listen("listen", socket, backlog); }

static void
__attribute__((constructor))
fci_init(void)
{
	cygwin_internal(CW_HOOK, "connect", fci_connect);
	cygwin_internal(CW_HOOK, "close", fci_close);
	cygwin_internal(CW_HOOK, "bind", fci_bind);
	cygwin_internal(CW_HOOK, "listen", fci_listen);
}

#endif
