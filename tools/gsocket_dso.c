

// TODO:
// - Support IPv6
// - Suppport UDP

#define _GNU_SOURCE
#include "common.h"

#include <sys/wait.h>
#include <dlfcn.h>
#include <limits.h>
#include <netdb.h>
#ifdef __CYGWIN__
# include <sys/cygwin.h>
# include <windows.h>
#endif
#include "gsocket_dso-lib.h"

#define GS_WITH_AUTHCOOKIE   1

// Infos for tracking FDs
struct _fd_info
{
	struct sockaddr_in addr;
	int is_bind;
	int is_connect;
	int is_listen;
	int is_tor;
	int is_hijack;
	sa_family_t sa_family;
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

#if defined(__CYGWIN__) || defined(__APPLE__)
# define THC_USE_FCI
#endif

#ifndef __APPLE__
# define THC_USE_DLSYM
#endif

#ifdef THC_USE_DLSYM
# define REAL(xn, a...) ((t_real_##xn)dlsym(RTLD_NEXT, #xn))(a)  
#else
# define REAL(xn, a...) xn(a)
#endif

// HOOK definitions
// Note: Set errno=0 before libcall => Some programs (e.g. netcat) ignore
// return value of listen() and just check if errno has changed.
// Our .so may have changed errno...
typedef int (*t_real_bind)(int sox, const struct sockaddr *addr, socklen_t addr_len);
static int real_bind(int sox, const struct sockaddr *addr, socklen_t addr_len) { errno=0; return REAL(bind, sox, addr, addr_len); }

typedef int (*t_real_listen)(int sox, int backlog);
static int real_listen(int sox, int backlog) { errno=0; return REAL(listen, sox, backlog); }

typedef int (*t_real_connect)(int sox, const struct sockaddr *addr, socklen_t addr_len);
static int real_connect(int sox, const struct sockaddr *addr, socklen_t addr_len) { errno=0; return REAL(connect, sox, addr, addr_len); }

typedef int (*t_real_close)(int fd);
static int real_close(int fd) { return REAL(close, fd); }

#if defined(HAVE_CONNECTX)
  typedef int (*t_real_connectx)(int sox, const sa_endpoints_t *ep, sae_associd_t aid, unsigned int flags, const struct iovec *iov, unsigned int iovcnt, size_t *len, sae_connid_t *cid);
  static int real_connectx(int sox, const sa_endpoints_t *ep, sae_associd_t aid, unsigned int flags, const struct iovec *iov, unsigned int iovcnt, size_t *len, sae_connid_t *cid) { errno=0; return REAL(connectx, sox, ep, aid, flags, iov, iovcnt, len, cid); }
#endif
#if defined(HAVE_ACCEPT4)
  typedef int (*t_real_accept4)(int sox, const struct sockaddr *addr, socklen_t *addr_len, int flags);
  static int real_accept4(int sox, const struct sockaddr *addr, socklen_t *addr_len, int flags) { errno=0; return REAL(accept4, sox, addr, addr_len, flags); }
#else
  // Solaris10 & OSX do not have accept4()
  typedef int (*t_real_accept)(int sox, struct sockaddr *addr, socklen_t *addr_len);
  static int real_accept4(int sox, struct sockaddr *addr, socklen_t *addr_len, int flags) { errno=0; return REAL(accept, sox, addr, addr_len); }
#endif

typedef struct hostent *(*t_real_gethostbyname)(const char *name);
static struct hostent *real_gethostbyname(const char *name) { errno=0; return REAL(gethostbyname, name); }

typedef int (*t_real_getaddrinfo)(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);
static int real_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) { errno=0; return REAL(getaddrinfo, node, service, hints, res); }

// FUNCTION definitions
static struct _gs_so_mgr *gs_so_listen(const char *secret, uint16_t port_orig, uint16_t *port_fake, int is_tor);
static struct _gs_so_mgr *gs_so_connect(const char *secret, uint16_t port_orig, uint16_t *port_fake, int is_tor);
static struct _gs_so_mgr *gs_mgr_lookup(const char *secret, uint16_t port_orig, enum gs_so_mgr_type_t gs_type, int is_tor);
static struct _gs_so_mgr *gs_mgr_new_by_ipc(int ipc_fd, uint16_t port_orig, enum gs_so_mgr_type_t gs_type, int is_tor);

static struct _gs_so_mgr *gs_mgr_new(const char *secret, uint16_t port_orig, uint16_t *port_fake, enum gs_so_mgr_type_t gs_type, int is_tor);
static void gs_mgr_free(struct _gs_so_mgr *m);

// STATIC variables
static int is_init;
static struct _fd_info *fd_list;
static int g_fd_max;
static struct _gs_so_mgr mgr_list[MAX(1024, FD_SETSIZE)];
static char *g_secret; // global secret
static struct _gs_portrange_list hijack_ports;
static int is_debug;

static void
thc_init(const char *fname)
{
	if (is_init)
		return;
	is_init = 1;

	thc_init_cyg();

#ifdef DEBUG
	if (gs_getenv("GSOCKET_DEBUG"))
	{
		is_debug = 1;
		char *ptr = gs_getenv("GSOCKET_LOGFILE");
		if (ptr)
			gopt.err_fp = fopen(ptr, "w");
		if (gopt.err_fp == NULL)
			gopt.err_fp = stderr;
	}
	DEBUGF("%s called from %s()\n", __func__, fname);
#endif

	// struct sigaction sa;
	// memset(&sa, 0, sizeof sa);
	// sa.sa_sigaction = &cb_sigchld;
	// sa.sa_flags = SA_SIGINFO | SA_RESTART | SA_NOCLDWAIT;
	// sigaction(SIGCHLD, &sa, NULL);

	// Disable LD_PRELOAD so that any further exec*() is not hijacked again.
	// (e.g. when starting gs-netcat or when ssh starts a /bin/bash...)
	unsetenv("LD_PRELOAD");
	unsetenv("DYLD_INSERT_LIBRARIES");
	unsetenv("DYLD_FORCE_FLAT_NAMESPACE");

	char *ptr = gs_getenv("GS_HIJACK_PORTS");
	GS_portrange_new(&hijack_ports, ptr?ptr:"1-65535");

	g_secret = gs_getenv("GSOCKET_SECRET");
}

static struct _fd_info *
fdi_get(int fd)
{
	if (is_init == 0)
		return NULL; // OSX: See OSX-BUG-MALLOC1

	if (fd_list == NULL)
	{
		g_fd_max = MAX(FD_SETSIZE, getdtablesize());
		fd_list = calloc(g_fd_max, sizeof (struct _fd_info));
		if (fd_list == NULL)
			return NULL;
	}

	if (fd < 0)
		return NULL;
	if (fd >= g_fd_max)
		return NULL;

	return &fd_list[fd];
}

static int
thc_close(const char *fname, int fd)
{
	// OSX-BUG-MALLOC1
	// thc_init(fname); // OSX: segfault. strdup() and unsetenv() seem to segfault.
	// OSX seems to call close() before libc has fully initialized the malloc-subsystem
	// and segfaults on malloc...which is used by thc_init in strdup() and unsetenv()...
	DEBUGF_Y("close(%d)\n", fd);
	struct _fd_info *fdi = fdi_get(fd);
	if (fdi != NULL)
		memset(fdi, 0, sizeof *fdi);

	return real_close(fd);
}

// Return 0 if this should be hijacked
static int
hijack_conn(int *is_tor, struct sockaddr_in *addr)
{
	// GSOCKET_NOHIJACK is set...call original function immediately.
	if (addr->sin_addr.s_addr == inet_addr("127.31.33.7"))
		return 0;
	if (addr->sin_addr.s_addr == inet_addr("127.31.33.8"))
	{
		*is_tor = 1;
		return 0;
	}

	return -1; // Call original
}

static int
redir_conn(int sox, struct sockaddr_in *a, struct _fd_info *fdi)
{
	int rv;

	if (fdi->port_fake == 0)
	{
		// could not start gs-netcat port forwarding sub-process
		errno = ECONNREFUSED;
		return -1;
	}

	DEBUGF("Connecting to 127.0.0.1:%u instead (sox=%d)\n", fdi->port_fake, sox);
	a->sin_port = htons(fdi->port_fake);
	a->sin_addr.s_addr = inet_addr("127.0.0.1");

	// Must force to BLOCKING so that sox becomes available and we can send our auth-cookie.
	// We can not intercept write() and to the auth-cookie there because the caller
	// may never call 'write()' and might be receiving only.
	int flags = fcntl(sox, F_GETFL, 0);
	if (flags & O_NONBLOCK)
	{
		DEBUGF_B("Setting sox=%d to BLOCKING\n", sox);
		fcntl(sox, F_SETFL, ~O_NONBLOCK & flags);
	}
	rv = real_connect(sox, (struct sockaddr *)a, sizeof *a);
	if (rv != 0)
	{
		DEBUGF("%s\n", strerror(errno));
		if (flags & O_NONBLOCK)
			fcntl(sox, F_SETFL, O_NONBLOCK | flags);

		return rv;
	}
	fdi->is_connect = 1;
#ifdef GS_WITH_AUTHCOOKIE
	uint8_t cookie[GS_AUTHCOOKIE_LEN];

	authcookie_gen(cookie, g_secret, fdi->port_orig);
	rv = write(sox, cookie, sizeof cookie);
#endif
	if (flags & O_NONBLOCK)
	{
		DEBUGF_B("Setting sox=%d to NONBLOCKING\n", sox);
		fcntl(sox, F_SETFL, O_NONBLOCK | flags);
	}

	return 0;
}

#if defined(HAVE_CONNECTX)
// OSX has a fancy connectx() function
static int
thc_connectx(const char *fname, int sox, const sa_endpoints_t *ep, sae_associd_t aid, unsigned int flags, const struct iovec *iov, unsigned int iovcnt, size_t *len, sae_connid_t *cid)
{
	int rv;
	struct _fd_info *fdi;
	struct sockaddr *addr;

	thc_init(fname);
	addr = (struct sockaddr *)ep->sae_dstaddr;

	if ((sox < 0) || (addr == NULL) || (addr->sa_family != AF_INET))
		return real_connectx(sox, ep, aid, flags, iov, iovcnt, len, cid);

	struct sockaddr_in *a = (struct sockaddr_in *)ep->sae_dstaddr;
	DEBUGF("connect(%s:%d)\n", int_ntoa(a->sin_addr.s_addr), ntohs(a->sin_port));

	fdi = fdi_get(sox);
	if (fdi == NULL)
		return real_connectx(sox, ep, aid, flags, iov, iovcnt, len, cid);

	rv = hijack_conn(&fdi->is_tor, (struct sockaddr_in *)addr);
	if (rv != 0)
		return real_connectx(sox, ep, aid, flags, iov, iovcnt, len, cid);

	a = &fdi->addr;
	memcpy(a, ep->sae_dstaddr, sizeof *a);
	fdi->port_orig = ntohs(((struct sockaddr_in *)ep->sae_dstaddr)->sin_port);

	if (fdi->is_connect)
	{
		rv = real_connect(sox, addr, sizeof *a);
		if (rv != 0)
			return rv;
	}

	gs_so_connect(g_secret, fdi->port_orig, &fdi->port_fake, fdi->is_tor);

	return redir_conn(sox, a, fdi);
}
#endif

static int
thc_connect(const char *fname, int sox, const struct sockaddr *addr, socklen_t addr_len)
{
	int rv;
	struct _fd_info *fdi;

	thc_init(fname);

	// DEBUGF("-> %s (nohijack=%d, sox=%d, af-family=%d)\n", fname, is_nohijack, sox, addr->sa_family);
	if ((sox < 0) || (addr == NULL) || (addr->sa_family != AF_INET))
		return real_connect(sox, addr, addr_len); // Let glibc deal with crap

	struct sockaddr_in *a = (struct sockaddr_in *)addr;
	DEBUGF("connect(%s:%d)\n", int_ntoa(a->sin_addr.s_addr), ntohs(a->sin_port));

	fdi = fdi_get(sox);
	if (fdi == NULL)
		return real_connect(sox, addr, addr_len);

	// Check if bind() was called before connect().
	// bind() was prepared for 'listen' and bind() to a random port number.
	// For 'connect()' we do not want this. Undo.
	if (fdi->is_bind)
	{
		DEBUGF("Who calls connect() after bind?\n"); // FIXME: can we bind() again with new ip?
		real_bind(sox, (struct sockaddr *)&fdi->addr, sizeof fdi->addr);
		fdi->is_bind = 0;
	}

	rv = hijack_conn(&fdi->is_tor, (struct sockaddr_in *)addr);
	if (rv != 0)
		return real_connect(sox, addr, addr_len);

	a = &fdi->addr;
	memcpy(a, addr, sizeof *a);
	fdi->port_orig = ntohs(((struct sockaddr_in *)addr)->sin_port);

	if (fdi->is_connect)
	{
		// Non-Blocking socket might call connect() until it's connected.
		DEBUGF_W("DOUBLE call to connect()?\n");
		rv = real_connect(sox, (struct sockaddr *)a, sizeof *a);
		if (rv != 0)
			return rv;
	}

	gs_so_connect(g_secret, fdi->port_orig, &fdi->port_fake, fdi->is_tor);

	return redir_conn(sox, a, fdi);
}

// Note: bind() might be called before connect() and this case needs to be considered.
static int
thc_bind(const char *fname, int sox, const struct sockaddr *addr, socklen_t addr_len)
{
	struct sockaddr_in *a;
	struct sockaddr_in6 *a6;
	int rv;
	struct _fd_info *fdi;

	thc_init(fname);
	DEBUGF_W("BIND  called (sox=%d, addr=%p, family=%d (%s))\n", sox, addr, addr?addr->sa_family:0, addr?addr->sa_family==AF_INET?"IPv4":"IPv6":"NULL");

	if ((sox < 0) || (addr == NULL))
		return real_bind(sox, addr, addr_len);

	fdi = fdi_get(sox);
	if ((fdi == NULL) || (fdi->is_bind) || !( (addr->sa_family == AF_INET) || (addr->sa_family == AF_INET6)) )
	{
		DEBUGF("is_bind=%d, family=%d\n", fdi->is_bind, addr->sa_family);
		return real_bind(sox, addr, addr_len);
	}

	int is_call_hijack = 0;
	a = (struct sockaddr_in *)addr;
	a6 = (struct sockaddr_in6 *)addr;
	if (addr->sa_family == AF_INET)
	{
		if (a->sin_addr.s_addr == inet_addr("127.31.33.8"))
			fdi->is_tor = 1;
	}
	if (GS_portrange_is_match(&hijack_ports, ntohs(a->sin_port)))
		is_call_hijack = 1;

	if (is_call_hijack == 0)
		return real_bind(sox, (struct sockaddr *)addr, addr_len);

	// Backup original address in case this bind() is followed by connect() and not listen().
	memcpy(&fdi->addr, addr, sizeof fdi->addr);
	fdi->port_orig = ntohs(a->sin_port);

	if (addr->sa_family == AF_INET6)
	{
		// a6->sin6_addr = in6addr_any;
#ifndef IS_SOLARIS
		// NOT Solaris. Solaris creates an IPv4 _and_ IPv6 listening socket
		// when AF_INET6 is set and addr==in6addr_any. Thus on SOLARIS we keep it
		// on in6addr_any and not to localhost. FIXME: Can remove once gs-netcat
		// supports IPv6.
		inet_pton(AF_INET6, "::1", (void *)&a6->sin6_addr);
#endif
		a6->sin6_port = 0;
	} else {
		a->sin_addr.s_addr = inet_addr("127.0.0.1");
		a->sin_port = 0; // Pick any port at random to listen on.
	}
	rv = real_bind(sox, (struct sockaddr *)addr, addr_len);
	if (rv != 0)
	{
		DEBUGF_R("bind(): %s\n", strerror(errno));
		return rv;
	}

	// Retrieve (random) local port we bind() to.
	socklen_t plen;
	uint16_t port;
	if (addr->sa_family == AF_INET)
	{
		struct sockaddr_in paddr;
		plen = sizeof paddr;
		rv = getsockname(sox, (struct sockaddr *)&paddr, &plen);
		port = ntohs(paddr.sin_port);
	} else {
		struct sockaddr_in6 paddr6;
		plen = sizeof paddr6;
		rv = getsockname(sox, (struct sockaddr *)&paddr6, &plen);
		port = ntohs(paddr6.sin6_port);
	}
	fdi->port_fake = port;
	fdi->is_bind = 1;
	fdi->is_hijack = 1;
	fdi->sa_family = addr->sa_family;
	DEBUGF_G("Bind to port=%u (orig=%u, rv=%d)\n", fdi->port_fake, fdi->port_orig, rv);

	return 0;
}


static int
thc_listen(const char *fname, int sox, int backlog)
{
	struct _fd_info *fdi;

	thc_init(fname);
	DEBUGF_W("LISTEN called (sox=%d)\n", sox);

	if (sox < 0)
		return real_listen(sox, backlog); // good luck! let glibc handle crap.

	fdi = fdi_get(sox);

	if ((fdi == NULL) || (fdi->is_listen) || (fdi->is_hijack == 0))
		return real_listen(sox, backlog);

#ifndef IS_SOLARIS
	// Anyone (but solaris) returns here.
	// Solaris uses AF_INET6 to listen to IPv4 _and_ IPv6 port with
	// single syscall.
	if (fdi->sa_family == AF_INET6)
		return real_listen(sox, backlog);
#endif

	// HERE: IPv6 or IPv4
	fdi->is_listen = 1;
	// Send Secret and listening port to manager
	gs_so_listen(g_secret, fdi->port_orig, &fdi->port_fake, fdi->is_tor);

	int ret;
	ret = real_listen(sox, backlog);
	DEBUGF("listen(%d)=%d, %s\n", sox, ret, strerror(errno));

	return ret;
}


static int
thc_accept4(const char *fname, int ls, struct sockaddr *addr, socklen_t *addr_len, int flags)
{
	int sox;

	errno = 0;
	thc_init(fname);
	DEBUGF_W("%s called (ls=%d)\n", fname, ls);

	if (ls < 0)
		return real_accept4(ls, addr, addr_len, flags);

	// IPv4 or IPv6
	sox = real_accept4(ls, addr, addr_len, flags);
	DEBUGF("%s()=%d (new socket)\n", fname, sox);
	if (sox < 0)
		return sox;

#ifdef GS_WITH_AUTHCOOKIE
	struct _fd_info *fdi;
	fdi = fdi_get(ls);
	if (fdi == NULL)
		return sox;
	int rv;
	uint8_t cookie[GS_AUTHCOOKIE_LEN];
	uint8_t ac_buf[GS_AUTHCOOKIE_LEN];
	int fl = fcntl(sox, F_GETFL, 0);
	if (fl & O_NONBLOCK)
		fcntl(sox, F_SETFL, ~O_NONBLOCK & fl);
	rv = read(sox, ac_buf, sizeof ac_buf);
	if (rv != sizeof ac_buf)
	{
		DEBUGF("read(%d)=%d\n", sox, rv);
		real_close(sox);
		return -1;
	}
	if (fl & O_NONBLOCK)
		fcntl(sox, F_SETFL, O_NONBLOCK | fl);

	authcookie_gen(cookie, g_secret, fdi->port_orig);
	if (memcmp(cookie, ac_buf, sizeof cookie) != 0)
	{
		DEBUGF_R("AUTH-COOKIE MISMATCH\n");
		HEXDUMP(cookie, sizeof cookie);
		HEXDUMP(ac_buf, sizeof cookie);
		real_close(sox);
		return -1;
	}
	DEBUGF_Y("auth-cookie matches\n");
#endif

	return sox;
}

// static int
// thc_accept(const char *fname, int ls, const struct sockaddr *addr, socklen_t *addr_len)
// {
// 	return thc_accept4(fname, ls, addr, addr_len, 0);
// }

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

struct hostent *
thc_gethostbyname(const char *fname, const char *name)
{
	thc_init(fname);

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
	thc_init(fname);

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
		if (m->gs_type != gs_type)
			continue;
		if (m->port_orig != port_orig)
			continue;
		if (m->secret == NULL)
			continue;
		if (m->is_tor != is_tor)
			continue;
		if (strcmp(secret, m->secret) != 0)
			continue;

	}
	if (i >= sizeof mgr_list / sizeof *mgr_list)
	{
		DEBUGF("MGR not found (secret=%s, port_orig=%u, gs_type=%d, is_tor=%d)\n", secret, port_orig, gs_type, is_tor);
		return NULL; // not found.
	}
	DEBUGF("MGR found with IPC_ID=%d\n", m->ipc_fd);

	// FOUND but check if this one is still alive:
	char c;
	int rv;
	rv = read(m->ipc_fd, &c, sizeof c);
	if (rv == sizeof c)
		return m; // SHOULD NOT HAPPEN. Child never sends us data via stdin
	if ((rv < 0) && (errno == EWOULDBLOCK))
		return m; // still alive

	DEBUGF("MGR dead (pid=%d)? %s\n", m->pid, strerror(errno));
	int wstatus;
	waitpid(m->pid, &wstatus, WNOHANG); // No defunct/zombie children

	gs_mgr_free(m);

	return NULL; // DIED. Will create new MGR
}

// Allocate an Manager/IPC structure
static struct _gs_so_mgr *
gs_mgr_new_by_ipc(int ipc_fd, uint16_t port_orig, enum gs_so_mgr_type_t gs_type, int is_tor)
{
	if (mgr_list[ipc_fd].is_used)
	{
		DEBUGF("ERROR: IPC already assigned (%d)\n", ipc_fd);
		return NULL;
	}

	mgr_list[ipc_fd].ipc_fd = ipc_fd;
	mgr_list[ipc_fd].is_used = 1;
	mgr_list[ipc_fd].is_tor = is_tor;
	mgr_list[ipc_fd].port_orig = port_orig;

	return &mgr_list[ipc_fd]; 
}

// close all but 1 fd
static void
close_all_fd(int fd)
{
	int i;

	for (i = 2; i < MIN(getdtablesize(), FD_SETSIZE); i++)
	{
		// Leave STDERR open when debugging
#ifdef DEBUG
		if (i == STDERR_FILENO)
		{
			DEBUGF_B("NOT closing %d\n", STDERR_FILENO);
			continue;
		}
#endif
		if (i == fd)
			continue;
		real_close(i);
	}
}

// Close FD and clear memory
static void
gs_mgr_free(struct _gs_so_mgr *m)
{
	if (m->ipc_fd >= 0)
		real_close(m->ipc_fd);

	memset(m, 0, sizeof *m);
	m->ipc_fd = -1;
}

// Open an IPC connection to the Manager
static struct _gs_so_mgr *
gs_mgr_new(const char *secret, uint16_t port_orig, uint16_t *port_fake, enum gs_so_mgr_type_t gs_type, int is_tor)
{
	int fds[2];

	// This socketpair ensures that the client can detect if the parent
	// exits. Creates fds = [4, 5].
	socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
	DEBUGF("fds[%d, %d]\n", fds[0], fds[1]);
	// OpenSSH calls dup2(10, 5 [REEXEC_STARTUP_PIPE_FD]) in sshd.c for rexec.
	// That dup2() call will first close fd==5. However, that might be our fd from the socketpair!
	// REEXEC_STARTUP_PIPE_FD is defined as STDOUT + 3 and OpenSSH does not give a damn if that socket
	// is already used or not. It blindly calls dup2(, 5). Instead we do a hack to use
	// a high socket number for our IPC comm.
	int free_fd;
	for (free_fd = MIN(getdtablesize(), FD_SETSIZE) - 1; free_fd >= 0; free_fd--)
	{
		if (fcntl(free_fd, F_GETFD, 0) != 0)
			break;
	}

	dup2(fds[1], free_fd);
	DEBUGF("Moved fd=%d to fd=%d\n", fds[1], free_fd);
	real_close(fds[1]);
	fds[1] = free_fd;

	struct _gs_so_mgr *m;
	m = gs_mgr_new_by_ipc(fds[1], port_orig, gs_type, is_tor);
	if (m == NULL)
		return NULL;

	DEBUGF_C("IS_TOR=%d, port_fake=%d, [%d, %d]\n", is_tor, *port_fake, fds[0], fds[1]);
	// FIXME: For now we spawn a gs-netcat for each port number & type
	// Later we may unify this into a single new 'gsd' daemon
	pid_t pid;
	pid = fork();
	if (pid < 0)
		return NULL;

	if (pid == 0)
	{
		// CHILD
		close_all_fd(fds[0]);

		// STDOUT: gs-netcat allocates a random port number and outputs that port number (16 bit) to stdout.
		// The parent process will read it from ipc_fd to then redirect that connect() call to that
		// port number.
		dup2(fds[0], STDOUT_FILENO);
		// STDIN: gs-netcat monitors stdin to check if parent dies.
		dup2(fds[0], STDIN_FILENO);

		char *env_args = gs_getenv("GSOCKET_ARGS");
		if (env_args == NULL)
			gs_getenv("GS_ARGS");
		char buf[1024];
		char prg[256];
		char *quiet_str = is_debug?"":"-q ";

		if (gs_type == GS_SO_MGR_TYPE_LISTEN)
		{
			// The Caller wants to listen(). We redirect to listen on any random free port (fake_port)
			// and instruct gs-netcat to forward TCP to that port.
#ifdef GS_WITH_AUTHCOOKIE
			setenv("_GSOCKET_SEND_AUTHCOOKIE", "1", 1);
#endif
			unsetenv("_GSOCKET_WANT_AUTHCOOKIE");
			// Note: Must start with -q: We close(stderr) and gs-netcat
			// will SIGPIPE (on OSX) when trying to write stats to stderr.
			snprintf(buf, sizeof buf, "%s %s-s%u-%s  %s-W -l -d127.0.0.1 -p%u", env_args?env_args:"", is_tor?"-T ":"", port_orig, secret, quiet_str, *port_fake);
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
			snprintf(buf, sizeof buf, "%s %s-s%u-%s %s-p0", env_args?env_args:"", is_tor?"-T ":"", port_orig, secret, quiet_str);
			snprintf(prg, sizeof prg, "gs-netcat [C-%u]", port_orig);
		}
		setenv("GSOCKET_ARGS", buf, 1);

		// unsetenv("LD_PRELOAD");
		setenv("_GSOCKET_INTERNAL", "1", 1);
		setenv("GSOCKET_NO_GREETINGS", "1", 1);
		char *bin = gs_getenv("GS_NETCAT_BIN");
		if (bin == NULL)
			bin = "gs-netcat";
		DEBUGF("ARGS='%s' bin=%s prg=%s\n", buf, bin, prg);
		execlp(bin, prg, NULL); // Try local dir first
		DEBUGF("FAILED\n");

		sleep(1); // Good to sleep to prevent rapit auto-restart
		exit(EX_EXECFAILED); // NOT REACHED 
	}
	// PARENT
	real_close(fds[0]);

	m->ipc_fd = fds[1];
	DEBUGF_W("IPC_FD=%d\n", fds[1]);
	if (gs_type == GS_SO_MGR_TYPE_CONNECT)
	{
		int rv;
		rv = read(m->ipc_fd, port_fake, sizeof *port_fake);
		if (rv != sizeof *port_fake)
		{
			*port_fake = 0;
			DEBUGF_R("read(%d)=%d: %s\n", fds[1], rv, strerror(errno));
			gs_mgr_free(m);
			return NULL;
		}
		DEBUGF("Received port %u\n", *port_fake);
		m->port_fake = *port_fake;
	}

	// Set Parent's IPC FD to non-blocking so that we can read() and check
	// if child is still alive...
	fcntl(m->ipc_fd, F_SETFL, O_NONBLOCK | fcntl(m->ipc_fd, F_GETFL, 0));

	return m;
}

static struct _gs_so_mgr *
gs_mgr_connect(const char *secret, uint16_t port_orig, uint16_t *port_fake, enum gs_so_mgr_type_t gs_type, int is_tor)
{
	struct _gs_so_mgr *m;
	m = gs_mgr_lookup(secret, port_orig, gs_type, is_tor);
	if (m != NULL)
		return m;

	return gs_mgr_new(secret, port_orig, port_fake, gs_type, is_tor);
}

// Send a message to the Manager for a listening port.
// This function is called by the hijacked listen() to request a new GS-Listen()
// forward from the daemon.
static struct _gs_so_mgr *
gs_so_listen(const char *secret, uint16_t port_orig, uint16_t *port_fake, int is_tor)
{
	// Contact the GS-MGR and send him our port and secret (via local socket controller by this user! not tcp)
	// or use IPC / socketpair (FIXME: implement this!)
	return gs_mgr_connect(secret, port_orig, port_fake, GS_SO_MGR_TYPE_LISTEN, is_tor);

	// Nothing to send or do at we are (currently, as a hack) using
	// gs-netcat (a new gs-netcat process for every [port_orig, type] combination
}

static struct _gs_so_mgr *
gs_so_connect(const char *secret, uint16_t port_orig, uint16_t *port_fake, int is_tor)
{
	return gs_mgr_connect(secret, port_orig, port_fake, GS_SO_MGR_TYPE_CONNECT, is_tor);
}

// HOOKS
// - UNIX/Linux overwrites the function names directly
// - OSX requires DYLD_INTERPOSE, jumping via fci_<name>()
// - CYGWIN requires cygwin_internal(CW_HOOK), jumping via fci_<name>()
#ifndef THC_USE_FCI
// HERE: UNIX/Linux
int connect(int socket, const struct sockaddr *addr, socklen_t addr_len) {return thc_connect(__func__, socket, addr, addr_len); }
#if defined(HAVE_CONNECTX)
  int connectx(int socket, const sa_endpoints_t *endpoints, sae_associd_t associd, unsigned int flags, const struct iovec *iov, unsigned int iovcnt, size_t *len, sae_connid_t *connid) {return thc_connectx(__func__, socket, endpoints, associd, flags, iov, iovcnt, len, connid); }
#endif
int close(int fd) { return thc_close(__func__, fd); }
int bind(int socket, const struct sockaddr *addr, socklen_t addr_len) {return thc_bind(__func__, socket, addr, addr_len); }
int listen(int socket, int backlog) {return thc_listen(__func__, socket, backlog); }
#if !defined(IS_SOL10)
  int accept(int socket, struct sockaddr *addr, socklen_t *addr_len) {return thc_accept4(__func__, socket, addr, addr_len, 0); }
#else
  int accept(int socket, struct sockaddr *addr, Psocklen_t addr_len) {return thc_accept4(__func__, socket, addr, addr_len, 0); }
#endif
int accept4(int socket, struct sockaddr *addr, socklen_t *addr_len, int flags) {return thc_accept4(__func__, socket, addr, addr_len, flags); }
struct hostent *gethostbyname(const char *name) {return thc_gethostbyname(__func__, name); }
int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {return thc_getaddrinfo(__func__, node, service, hints, res); }
#endif // !THC_USE_FCI

#ifdef THC_USE_FCI
static int fci_connect(int socket, const struct sockaddr *addr, socklen_t addr_len) {return thc_connect("connect", socket, addr, addr_len); }
#if defined(HAVE_CONNECTX)
static int fci_connectx(int socket, const sa_endpoints_t *endpoints, sae_associd_t associd, unsigned int flags, const struct iovec *iov, unsigned int iovcnt, size_t *len, sae_connid_t *connid) { return thc_connectx("connectx", socket, endpoints, associd, flags, iov, iovcnt, len, connid); }
#endif
static int fci_close(int fd) {return thc_close("close", fd); }
static int fci_bind(int fd, const struct sockaddr *addr, socklen_t addr_len) {return thc_bind("bind", fd, addr, addr_len); }
static int fci_listen(int socket, int backlog) {return thc_listen("listen", socket, backlog); }
static int fci_accept(int fd, struct sockaddr *addr, socklen_t *addr_len) {return thc_accept4("accept", fd, addr, addr_len, 0); }
#if defined(HAVE_ACCEPT4)
static int fci_accept4(int fd, struct sockaddr *addr, socklen_t *addr_len, int flags) {return thc_accept4("accept4", fd, addr, addr_len, flags); }
#endif
static struct hostent *fci_gethostbyname(const char *name) {return thc_gethostbyname("gethostbyname", name); }
static int fci_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {return thc_getaddrinfo("getaddrinfo", node, service, hints, res); }
#endif // THC_USE_FCI

#ifdef __APPLE__
DYLD_INTERPOSE(fci_connect, connect);
#if defined(HAVE_CONNECTX)
DYLD_INTERPOSE(fci_connectx, connectx);
#endif
DYLD_INTERPOSE(fci_close, close);
DYLD_INTERPOSE(fci_bind, bind);
DYLD_INTERPOSE(fci_listen, listen);
DYLD_INTERPOSE(fci_accept, accept);
#if defined(HAVE_ACCEPT4)
DYLD_INTERPOSE(fci_accept4, accept4);
#endif
DYLD_INTERPOSE(fci_gethostbyname, gethostbyname);
DYLD_INTERPOSE(fci_getaddrinfo, getaddrinfo);
#endif

#ifdef __CYGWIN__
__attribute__((constructor))
int
fci_init(void)
{
	cygwin_internal(CW_HOOK, "connect", fci_connect);
	cygwin_internal(CW_HOOK, "close", fci_close);
	cygwin_internal(CW_HOOK, "bind", fci_bind);
	cygwin_internal(CW_HOOK, "listen", fci_listen);
	cygwin_internal(CW_HOOK, "accept", fci_accept);
	cygwin_internal(CW_HOOK, "accept4", fci_accept4);
	cygwin_internal(CW_HOOK, "gethostbyname", fci_gethostbyname);
	cygwin_internal(CW_HOOK, "getaddrinfo", fci_getaddrinfo);

	return 0;
}

#endif
