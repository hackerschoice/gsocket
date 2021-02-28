
#define _GNU_SOURCE
#include "common.h"


// #include <sys/types.h>
// #include <sys/socket.h>
// #include <sys/stat.h>
// #include <arpa/inet.h>
// #include <fcntl.h>
// #include <errno.h>
#include <dlfcn.h>
// #include <stdio.h>
// #include <stdlib.h>
// #ifdef HAVE_UNISTD_H
// # include <unistd.h>
// #endif
// #include <errno.h>
#include <limits.h>
#include <netdb.h>
// #include <string.h>
// #include <libgen.h>
#ifdef __CYGWIN__
# include <sys/cygwin.h>
# include <windows.h>
#endif
// #include <openssl/sha.h>
// #include "gs_so-protocol.h"
#include "gs_so-lib.h"

#define GS_WITH_AUTHCOOKIE   1

// Infos for tracking FDs
struct _fd_info
{
	struct sockaddr_in addr;
	int is_bind;
	int is_connect;
	int is_listen;
	int is_tor;
	uint16_t port_orig; // Fixme, this is confusing with gs_so_mgr. duplicate?
	uint16_t port_fake;
};

// GS_SO Manager
enum gs_so_mgr_type_t {
	GS_SO_MGR_TYPE_LISTEN,
	GS_SO_MGR_TYPE_CONNECT
};

struct _gs_so_mgr
{
	pid_t pid;
	char *secret;
	uint16_t port_orig;
	uint16_t port_fake;
	int ipc_fd;
	int is_used;
	int is_tor;
	enum gs_so_mgr_type_t gs_type;
};

// HOOK definitions
typedef int (*real_bind_t)(int sox, const struct sockaddr *addr, socklen_t addr_len);
static int real_bind(int sox, const struct sockaddr *addr, socklen_t addr_len) { return ((real_bind_t)dlsym(RTLD_NEXT, "bind"))(sox, addr, addr_len); }
typedef int (*real_listen_t)(int sox, int backlog);
static int real_listen(int sox, int backlog) { return ((real_listen_t)dlsym(RTLD_NEXT, "listen"))(sox, backlog); }
typedef int (*real_connect_t)(int sox, const struct sockaddr *addr, socklen_t addr_len);
static int real_connect(int sox, const struct sockaddr *addr, socklen_t addr_len) { return ((real_connect_t)dlsym(RTLD_NEXT, "connect"))(sox, addr, addr_len); }
typedef int (*real_accept_t)(int sox, const struct sockaddr *addr, socklen_t *addr_len);
static int real_accept(int sox, const struct sockaddr *addr, socklen_t *addr_len) { return ((real_accept_t)dlsym(RTLD_NEXT, "accept"))(sox, addr, addr_len); }
typedef struct hostent *(*real_gethostbyname_t)(const char *name);
static struct hostent *real_gethostbyname(const char *name) { return ((real_gethostbyname_t)dlsym(RTLD_NEXT, "gethostbyname"))(name); }
typedef int (*real_getaddrinfo_t)(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);
static int real_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) { return ((real_getaddrinfo_t)dlsym(RTLD_NEXT, "getaddrinfo"))(node, service, hints, res); }

// FUNCTION definitions
static void gs_so_listen(const char *secret, uint16_t port_orig, uint16_t *port_fake, int is_tor);
static void gs_so_connect(const char *secret, uint16_t port_orig, uint16_t *port_fake, int is_tor);
static struct _gs_so_mgr *gs_mgr_lookup(const char *secret, uint16_t port_orig, enum gs_so_mgr_type_t gs_type, int is_tor);
static struct _gs_so_mgr *gs_mgr_new_by_ipc(int ipc_fd, int is_tor);
static struct _gs_so_mgr *gs_mgr_new(const char *secret, uint16_t port_orig, uint16_t *port_fake, enum gs_so_mgr_type_t gs_type, int is_tor);

// STATIC variables
static int is_init;
static int is_debug;
static int is_nohijack;
static struct _fd_info fd_list[FD_SETSIZE];
static struct _gs_so_mgr mgr_list[FD_SETSIZE];
static char *g_secret; // global secret

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

static void
thc_init(void)
{
	if (is_init)
		return;

	gopt.err_fp = stderr;
	thc_init_cyg();

	if (getenv("GSOCKET_DEBUG"))
		is_debug = 1;
	DEBUGF("%s called\n", __func__);

	if (getenv("_GSOCKET_NOHIJACK"))
		is_nohijack = 1;

	g_secret = getenv("GSOCKET_SECRET");

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

static int
thc_connect(const char *fname, int sox, const struct sockaddr *addr, socklen_t addr_len)
{
	int rv;
	struct _fd_info *fdi;

	thc_init();

	// DEBUGF("-> %s (nohijack=%d, sox=%d, af-family=%d)\n", fname, is_nohijack, sox, addr->sa_family);
	if ((sox < 0) || (addr == NULL))
		return real_connect(sox, addr, addr_len); // Let glibc deal with crap
	struct sockaddr_in *a;

	if (addr->sa_family != AF_INET)
		return real_connect(sox, addr, addr_len);

	a = (struct sockaddr_in *)addr;
	DEBUGF("connect(%s:%d)\n", int_ntoa(a->sin_addr.s_addr), ntohs(a->sin_port));

	fdi = &fd_list[sox];

	// Check if bind() was called before connect().
	// bind() was prepared for 'listen' and bind() to a random port number.
	// For 'connect()' we do not want this. Undo.
	if (fdi->is_bind)
	{
		DEBUGF("Who calls connect() after bind?\n"); // FIXME: can we bind() again with new ip?
		real_bind(sox, (struct sockaddr *)&fdi->addr, sizeof fdi->addr);
		fdi->is_bind = 0;
	}

	// GSOCKET_NOHIJACK is set...call original function immediately.
	int is_call_orig = 1;
	if (((struct sockaddr_in *)addr)->sin_addr.s_addr == inet_addr("127.31.33.7"))
		is_call_orig = 0;
	if (((struct sockaddr_in *)addr)->sin_addr.s_addr == inet_addr("127.31.33.8"))
	{
		is_call_orig = 0;
		fdi->is_tor = 1;
	}
	if ((is_call_orig) || (is_nohijack))
		return real_connect(sox, addr, addr_len);

	fdi = &fd_list[sox];
	a = &fdi->addr;
	memcpy(a, addr, sizeof *a);
	fdi->port_orig = ntohs(((struct sockaddr_in *)addr)->sin_port);

	if (fdi->is_connect)
	{
		// Non-Blocking socket might call connect() until it's connected.
		DEBUGF_W("DOUBLE call to connect()?\n");
		rv = real_connect(sox, (struct sockaddr *)a, sizeof *a);
		if (rv != 0)
			goto err;
	}

	gs_so_connect(g_secret, fdi->port_orig, &fdi->port_fake, fdi->is_tor);

	DEBUGF("Connecting to 127.0.0.1:%u instead (sox=%d)\n", fdi->port_fake, sox);
	a->sin_port = htons(fdi->port_fake);
	a->sin_addr.s_addr = inet_addr("127.0.0.1");

	// Must force to BLOCKING so that sox becomes available and we can send our auth-cookie.
	// We can not intercept write() and to the auth-cookie there because the caller
	// may never call 'write()' and might be receiving only.
	int flags = fcntl(sox, F_GETFL, 0);
	if (flags & O_NONBLOCK)
		fcntl(sox, F_SETFL, ~O_NONBLOCK & flags);
	rv = real_connect(sox, (struct sockaddr *)a, sizeof *a);
	if (rv != 0)
	{
		DEBUGF("%s\n", strerror(errno));
		if (flags & O_NONBLOCK)
			fcntl(sox, F_SETFL, O_NONBLOCK | flags);

		goto err;
	}
	fdi->is_connect = 1;
#ifdef GS_WITH_AUTHCOOKIE
	uint8_t cookie[GS_AUTHCOOKIE_LEN];

	authcookie_gen(cookie, g_secret, fdi->port_orig);
	rv = write(sox, cookie, sizeof cookie);
#endif
	if (flags & O_NONBLOCK)
		fcntl(sox, F_SETFL, O_NONBLOCK | flags);

	return 0;
err:
	DEBUGF_R("ERROR: connect()=%d\n", rv);
	return rv;
}

// Note: bind() might be called before connect() and this case needs to be considered.
static int
thc_bind(const char *fname, int sox, const struct sockaddr *addr, socklen_t addr_len)
{
	struct sockaddr_in *a;
	int rv;
	struct _fd_info *fdi;

	thc_init();
	DEBUGF_W("BIND  called\n");

	if ((sox < 0) || (addr == NULL))
		return real_bind(sox, addr, addr_len);

	fdi = &fd_list[sox];
	if ((is_nohijack) || (fdi->is_bind))
		return real_bind(sox, addr, addr_len);

	int is_call_hijack = 0;
	if (addr->sa_family == AF_INET)
	{
		if (((struct sockaddr_in *)addr)->sin_addr.s_addr == inet_addr("127.31.33.7"))
			is_call_hijack = 1;
		if (((struct sockaddr_in *)addr)->sin_addr.s_addr == inet_addr("127.31.33.8"))
		{
			is_call_hijack = 1;
			fdi->is_tor = 1;
		}
		if (((struct sockaddr_in *)addr)->sin_port == ntohs(31337))
			is_call_hijack = 1;
	}
	is_call_hijack = 1; // FIXME: For listen() we hijack all connections

	if (is_call_hijack == 0)
		return real_bind(sox, (struct sockaddr *)addr, addr_len);

	// Backup original address in case this bind() is followed by connect() and not listen().
	memcpy(&fdi->addr, addr, sizeof fdi->addr);
	a = (struct sockaddr_in *)addr;
	fdi->port_orig = ntohs(a->sin_port);

	a->sin_addr.s_addr = inet_addr("127.0.0.1");
	a->sin_port = 0; // Pick any port at random to listen on.
	rv = real_bind(sox, (struct sockaddr *)a, sizeof *a);
	if (rv != 0)
		return rv;

	struct sockaddr_in paddr;
	socklen_t plen = sizeof addr;
	rv = getsockname(sox, (struct sockaddr *)&paddr, &plen);
	uint16_t port = ntohs(paddr.sin_port);
	fdi->port_fake = port;
	fdi->is_bind = 1;
	DEBUGF_G("Bind to port=%u (orig=%u, rv=%d)\n", fdi->port_fake, fdi->port_orig, rv);

	return 0;
}

int g_ls = -1;

static void
cb_sigchld(int sig)
{

	// pid_t = wait find out pid but let caller still call wait()?
	DEBUGF("SIGNAL CHLD %d\n", sig);
	// FIXME: forward to original signal function (hijack it?)
	// if signal was set up for that...
	// FIXME: only close if this was our pid..
	XCLOSE(g_ls);

	// FIXME
}

static int
thc_listen(const char *fname, int sox, int backlog)
{
	struct _fd_info *fdi;

	thc_init();
	DEBUGF_W("LISTEN called\n");

	if (sox < 0)
		return real_listen(sox, backlog); // good luck! let glibc handle crap.

	fdi = &fd_list[sox];

	if ((is_nohijack) || (fdi->is_listen))
		return real_listen(sox, backlog);

	fdi->is_listen = 1;
	// The GS-Netcal process might exit (for example, if it cant connect to GSRN or
	// the gsocket-address is already taken.)
	// The caller might be waiting in signal() and we need a way to make it fail.
	// We detect by sigchld if our gs-netcat process died and then close the listening socket.
	// That will make the caller's select() return and the caller's call to accept() will fail.
	signal(SIGCHLD, cb_sigchld);
	g_ls = sox;
	// Send Secret and listening port to manager
	gs_so_listen(g_secret, fdi->port_orig, &fdi->port_fake, fdi->is_tor);

	int ret;
	ret = real_listen(sox, backlog);

	return ret;
}


static int
thc_accept(const char *fname, int ls, const struct sockaddr *addr, socklen_t *addr_len)
{
	int sox;

	thc_init();
	DEBUGF_W("ACCEPT called\n");

	if (ls < 0)
		return real_accept(ls, addr, addr_len);

	sox = real_accept(ls, addr, addr_len);
	DEBUGF("sox = %d\n", sox);
	if (sox < 0)
		return sox;

#ifdef GS_WITH_AUTHCOOKIE
	struct _fd_info *fdi;
	fdi = &fd_list[ls];
	uint8_t cookie[GS_AUTHCOOKIE_LEN];
	uint8_t ac_buf[GS_AUTHCOOKIE_LEN];
	int flags = fcntl(sox, F_GETFL, 0);
	if (flags & O_NONBLOCK)
		fcntl(sox, F_SETFL, ~O_NONBLOCK & flags);
	if (read(sox, ac_buf, sizeof ac_buf) != sizeof ac_buf)
		return -1;
	if (flags & O_NONBLOCK)
		fcntl(sox, F_SETFL, O_NONBLOCK | flags);

	authcookie_gen(cookie, g_secret, fdi->port_orig);
	if (memcmp(cookie, ac_buf, sizeof cookie) != 0)
		return -1;
	DEBUGF_Y("auth-cookie matches\n");
#endif

	return sox;
}

static struct hostent he;
static uint32_t thc_ip;
static uint32_t *ipl[] = {0, NULL};
char *thc_hostname;

static struct hostent *
gethostbyname_fake(const char *name, size_t len, uint32_t ip)
{
	memset(&he, 0, sizeof he);
	thc_hostname = realloc(thc_hostname, len + 1);
	memcpy(thc_hostname, name, len + 1);
	he.h_name = thc_hostname;
	he.h_addrtype = AF_INET;
	he.h_length = 4;
	thc_ip = ip;
	ipl[0] = &thc_ip;
	he.h_addr_list = (char **)&ipl;

	return &he;
}

#define GS_SO_ROT_DOMAIN	"gsocket"  // when not to go through TOR (server.foobar.gsocket)
#define GS_SO_TOR_DOMAIN	"thc"      // Use TOR if domains is like (server.foobar.thc)
// Return 0 on NONE hijack. Return 1 on .gsocket. Return 2 on .thc
static int
gs_type_hijack_domain(const char *name, size_t len)
{
	if ((len >= strlen(GS_SO_TOR_DOMAIN)) && (memcmp(name + len - strlen(GS_SO_TOR_DOMAIN), GS_SO_TOR_DOMAIN, strlen(GS_SO_TOR_DOMAIN)) == 0))
		return 2;
	if ((len >= strlen(GS_SO_ROT_DOMAIN)) && (memcmp(name + len - strlen(GS_SO_ROT_DOMAIN), GS_SO_ROT_DOMAIN, strlen(GS_SO_ROT_DOMAIN)) == 0))
		return 1;

	return 0;
}

// FIXME: getnameinfo()
struct hostent *
thc_gethostbyname(const char *fname, const char *name)
{
	thc_init();

	DEBUGF_W("GETHOSTBYNAME called\n");
	if (name == NULL)
		return NULL;

	size_t len = strlen(name);
	switch (gs_type_hijack_domain(name, len))
	{
	case 1:
		return gethostbyname_fake(name, len, inet_addr("127.31.33.7"));
	case 2:
		return gethostbyname_fake(name, len, inet_addr("127.31.33.8"));
	}

	return real_gethostbyname(name);
}

int
thc_getaddrinfo(const char *fname, const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res)
{
	thc_init();

	if (node == NULL)
		return real_getaddrinfo(node, service, hints, res);

	DEBUGF_W("GETADDRINFO called (%s:%s)\n", node?node:"", service?service:"");

	switch (gs_type_hijack_domain(node, strlen(node)))
	{
	case 0:
		return real_getaddrinfo(node, service, hints, res);
	case 1:
		return real_getaddrinfo("127.31.33.7", service, hints, res);
	case 2:
		return real_getaddrinfo("127.31.33.8", service, hints, res);
	}
	return -1;
}

// GS_SO Manager
static struct _gs_so_mgr *
gs_mgr_lookup(const char *secret, uint16_t port_orig, enum gs_so_mgr_type_t gs_type, int is_tor)
{
	int i;
	struct _gs_so_mgr *m;

	for (i = 0; i < sizeof mgr_list / sizeof *mgr_list; i++)
	{
		m = &mgr_list[i];
		if (gs_type != m->gs_type)
			continue;
		if (port_orig != m->port_orig)
			continue;
		if (m->secret == NULL)
			continue;
		if (m->is_tor != is_tor)
			continue;
		if (strcmp(secret, m->secret) != 0)
			continue;

	}

	if (i >= sizeof mgr_list / sizeof *mgr_list)
		return NULL; // not found.

	return m;
}

// Allocate an Manager/IPC structure
static struct _gs_so_mgr *
gs_mgr_new_by_ipc(int ipc_fd, int is_tor)
{
	if (mgr_list[ipc_fd].is_used)
	{
		DEBUGF("ERROR: IPC already assigned (%d)", ipc_fd);
		return NULL;
	}

	mgr_list[ipc_fd].ipc_fd = ipc_fd;
	mgr_list[ipc_fd].is_used = 1;
	mgr_list[ipc_fd].is_tor = 1;

	return &mgr_list[ipc_fd]; 
}

// close all but 1 fd
static void
close_all_fd(int fd)
{
	int i;
	for (i = 2; i < FD_SETSIZE; i++)
	{
#ifdef DEBUG
		// Leave STDERR open when debugging
		if (i == STDERR_FILENO)
			continue;
#endif
		if (i == fd)
			continue;
		close(i);
	}
}

// Open an IPC connection to the Manager
static struct _gs_so_mgr *
gs_mgr_new(const char *secret, uint16_t port_orig, uint16_t *port_fake, enum gs_so_mgr_type_t gs_type, int is_tor)
{
	int fds[2];

	// This socketpair ensures that the client can detect if the parent
	// exits.
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
	struct _gs_so_mgr *m;
	m = gs_mgr_new_by_ipc(fds[1], is_tor);
	if (m == NULL)
		return NULL;

	DEBUGF_C("IS_TOR=%d\n", is_tor);
	// FIXME: For now we spawn a gs-netcat for each port number & type
	// Later we may unify this into a single new 'gsd' daemon
	pid_t pid;
	pid = fork();
	if (pid < 0)
		return NULL;

	if (pid == 0)
	{
		// CHILD

		m->ipc_fd = fds[0];
		dup2(m->ipc_fd, STDOUT_FILENO);
		dup2(m->ipc_fd, STDIN_FILENO);

		close_all_fd(fds[0] /*except this one*/);

		char *env_args = getenv("GSOCKET_ARGS");
		char buf[1024];
		char prg[256];
		if (gs_type == GS_SO_MGR_TYPE_LISTEN)
		{
			// The Caller wants to listen(). We redirect to listen on any random free port (fake_port)
			// and instruct gs-netcat to forward TCP to that port.
#ifdef GS_WITH_AUTHCOOKIE
			setenv("_GSOCKET_SEND_AUTHCOOKIE", "1", 1);
#endif
			unsetenv("_GSOCKET_WANT_AUTHCOOKIE");
			snprintf(buf, sizeof buf, "%s %s-s%u-%s -l -d127.0.0.1 -p%u", env_args?env_args:"", is_tor?"-T ":"", port_orig, secret, *port_fake);
			snprintf(prg, sizeof prg, "gs-netcat [S-%u]", port_orig);
		}
			
		if (gs_type == GS_SO_MGR_TYPE_CONNECT)
		{
			// The Caller wants to connect(). We redirect to connect to local listening
			// gs-netcat port forward. gs-netcat randomly allocates a fake listening port and
			// returns it to us via stdout/stdin (IPC).
#ifdef GS_WITH_AUTHCOOKIE
			setenv("_GSOCKET_WANT_AUTHCOOKIE", "1", 1);
#endif
			unsetenv("_GSOCKET_SEND_AUTHCOOKIE");
			snprintf(buf, sizeof buf, "%s %s-s%u-%s -p0", env_args?env_args:"", is_tor?"-T ":"", port_orig, secret);
			snprintf(prg, sizeof prg, "gs-netcat [C-%u]", port_orig);
		}
		setenv("GSOCKET_ARGS", buf, 1);

		setenv("_GSOCKET_NOHIJACK", "1", 1);
		setenv("_GSOCKET_INTERNAL", "1", 1);
		setenv("GSOCKET_NO_GREETINGS", "1", 1);
		unsetenv("LD_PRELOAD");
		unsetenv("DYLD_INSERT_LIBRARIES");
		char *bin = getenv("GS_NETCAT_BIN");
		if (bin == NULL)
			bin = "gs-netcat";
		DEBUGF("ARGS='%s' bin=%s prg=%s\n", buf, bin, prg);
		execlp(bin, prg, NULL); // Try local dir first
		DEBUGF("FAILED\n");

		exit(255); // NOT REACHED
	}
	// PARENT
	close(fds[0]);
	if (gs_type == GS_SO_MGR_TYPE_CONNECT)
	{
		read(fds[1], port_fake, sizeof *port_fake);
		DEBUGF("Received port %u\n", *port_fake);
		m->port_fake = *port_fake;
	}

	return m;
}

static void
gs_mgr_connect(const char *secret, uint16_t port_orig, uint16_t *port_fake, enum gs_so_mgr_type_t gs_type, int is_tor)
{
	struct _gs_so_mgr *m;
	m = gs_mgr_lookup(secret, port_orig, gs_type, is_tor);
	if (m != NULL)
		return;

	gs_mgr_new(secret, port_orig, port_fake, gs_type, is_tor);
}

// Send a message to the Manager for a listening port.
// This function is called by the hijacked listen() to request a new GS-Listen()
// forward from the daemon.
static void
gs_so_listen(const char *secret, uint16_t port_orig, uint16_t *port_fake, int is_tor)
{
	// Contact the GS-MGR and send him our port and secret (via local socket controller by this user! not tcp)
	// or use IPC / socketpair (FIXME: implement this!)
	gs_mgr_connect(secret, port_orig, port_fake, GS_SO_MGR_TYPE_LISTEN, is_tor);

	// Nothing to send or do at we are (currently, as a hack) using
	// gs-netcat (a new gs-netcat process for every [port_orig, type] combination
}

static void
gs_so_connect(const char *secret, uint16_t port_orig, uint16_t *port_fake, int is_tor)
{
	gs_mgr_connect(secret, port_orig, port_fake, GS_SO_MGR_TYPE_CONNECT, is_tor);
}

// HOOKS
#ifndef __CYGWIN__
int connect(int socket, const struct sockaddr *addr, socklen_t addr_len) {return thc_connect(__func__, socket, addr, addr_len); }
int close(int fd) {return thc_close(__func__, fd); }
int bind(int socket, const struct sockaddr *addr, socklen_t addr_len) {return thc_bind(__func__, socket, addr, addr_len); }
int listen(int socket, int backlog) {return thc_listen(__func__, socket, backlog); }
int accept(int socket, struct sockaddr *addr, socklen_t *addr_len) {return thc_accept(__func__, socket, addr, addr_len); }
struct hostent *gethostbyname(const char *name) {return thc_gethostbyname(__func__, name); }
int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {return thc_getaddrinfo(__func__, node, service, hints, res); }

#endif

#ifdef __CYGWIN__
static int fci_connect(int socket, const struct sockaddr *addr, socklen_t addr_len) {return thc_connect("connect", socket, addr, addr_len); }
static int fci_close(int fd) {return thc_close("close", fd); }
static int fci_bind(int fd, sockaddr *addr, socklen_t addr_len) {return thc_bind("bind", fd, addr, addr_len); }
static int fci_listen(int socket, int backlog) {return thc_listen("listen", socket, backlog); }
static int fci_accept(int fd, sockaddr *addr, socklen_t addr_len) {return thc_accept("accept", fd, addr, addr_len); }
static struct hostend *fci_gethostbyname(const char *name) {return thc_gethostbyname("gethostbyname", name); }
static int fci_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {return thc_getaddrinfo("getaddrinfo", node, service, hints, res); }
__attribute__((constructor))
fci_init(void)
{
	cygwin_internal(CW_HOOK, "connect", fci_connect);
	cygwin_internal(CW_HOOK, "close", fci_close);
	cygwin_internal(CW_HOOK, "bind", fci_bind);
	cygwin_internal(CW_HOOK, "listen", fci_listen);
	cygwin_internal(CW_HOOK, "accept", fci_accept);
	cygwin_internal(CW_HOOK, "gethostbyname", fci_gethostbyname);
	cygwin_internal(CW_HOOK, "getaddrinfo", fci_getaddrinfo);
}

#endif
