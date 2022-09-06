
#ifndef __GST_COMMON_H__
#define __GST_COMMON_H__ 1

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#ifdef HAVE_SYS_LOADAVG_H
# include <sys/loadavg.h> // Solaris11
#endif
#ifdef HAVE_SYS_ENDIAN_H
# include <sys/endian.h>
#endif
#include <netinet/in.h>
#ifdef HAVE_NETINET_IN_SYSTM_H
# include <netinet/in_systm.h>
#endif
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#ifdef HAVE_FNMATCH_H
#include <fnmatch.h>
#endif
#include <stdio.h>
#include <string.h>
#include <strings.h>    // Solaris11
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <inttypes.h>
#include <signal.h>
#include <libgen.h>		/* basename() */
#include <termios.h>
#include <pwd.h>
#include <wordexp.h>
#ifdef HAVE_UTMPX_H
# include <utmpx.h>
#endif
#ifdef HAVE_UTMP_H
# include <utmp.h>
#endif
#ifdef HAVE_LIBUTIL_H
# include <libutil.h>	/* FreeBSD */
#endif
#ifdef HAVE_PTY_H
# include <pty.h>
#endif
#ifdef HAVE_UTIL_H
# include <util.h>		/* MacOS */
#endif
#if defined __sun || defined __hpux /* Solaris, HP-UX */
# include <stropts.h>
#endif
#include <locale.h>
#include <openssl/ssl.h>
#include <openssl/srp.h>
#include <gsocket/gsocket.h>
#include <gsocket/gs-select.h>
#include "filetransfer.h"

#ifdef __sun
# ifdef HAVE_OPEN64
#  define IS_SOL10      1   // Solaris 10
# else
#  define IS_SOL11      1   // Solaris 11
# endif
# define IS_SOLARIS     1
#endif

#ifndef O_NOCTTY
# warning "O_NOCTTY not defined. Using 0."
# define O_NOCTTY 0
#endif

// Older fbsd's dont have this defined
#ifndef UT_NAMESIZE
# define UT_NAMESIZE	32
#endif

// debian-hurd does not define PATH_MAX (and has no limit on filename length)
#ifndef PATH_MAX
# define GS_PATH_MAX      4096
#else
# define GS_PATH_MAX      PATH_MAX
#endif

#if defined(__sun)
# if !defined(be64toh) // Solaris11
#  define be64toh(x) ntohll(x)
#  define htobe64(x) htonll(x)
# endif
# if !defined(htonll) // Solaris10
#  if __BIG_ENDIAN__
#   define htonll(x) (x)
#   define ntohll(x) (x)
#  else
#   define htonll(x) ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((uint64_t)(x) >> 32)
#   define ntohll(x) ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((uint64_t)(x) >> 32)
#  endif
# endif
#endif

#ifndef htonll
# define htonll(x)	htobe64(x)
#endif
#ifndef ntohll
# define ntohll(x)  be64toh(x)
#endif

struct _gopt
{
	GS_CTX gs_ctx;
	GS *gsocket;	/* Listening gsocket */

	FILE *log_fp;
	FILE *err_fp;
	int verbosity;        // verbosity level (-v => 1, -vv => 2 etc)
	int flags;
	int verboselevel;
	const char *sec_str;
	const char *sec_file;
	GS_ADDR gs_addr;
	char *token_str;
	int is_sock_wait;
	int is_client_or_server;
	int is_no_encryption;
	int is_blocking;
	int is_interactive;	/* PTY interactive shell? */
	int is_receive_only;
	int is_use_tor;
	int is_socks_server;	/* -S flag */
	int is_multi_peer;		/* -p / -S / -d [client & server] */
	int is_daemon;
	int is_watchdog;        // Never die but die if stdin closes
	int is_logfile;
	int is_quiet;
	int is_win_resized;     // window size changed (signal)
	int is_console;		    // console is being displayed
	int is_pong_pending;    // Server: Answer to PING waiting to be send
	int is_status_nopty_pending;
	int is_pty_failed;      // Tried to create PTY but failed. Dump terminal.
	int is_want_pwd;        // Client: Wants server to send cwd
	int is_pwdreply_pending; // Server: Answer to pwd-request
	int is_want_chdir; 
	int is_want_ids_on;     
	int is_want_authcookie;
	int is_send_authcookie;
	int is_internal;        // -I flag
	int is_udp;             // Port forwarding only. GSRN is always TCP.
	int is_built_debug;     // DEBUG is set
	int is_greetings;
	int is_try_server;      // Check with GSRN is server is listening.
	int gs_server_check_sec;
	char *prg_name;         // argv[0]
	uint64_t ts_ping_sent;  // TimeStamp ping sent
	fd_set rfd, r;
	fd_set wfd, w;
	struct timeval tv_now;
	const char *cmd;
	uint32_t dst_ip;	/* NBO */
	uint16_t port;		/* NBO */
	int listen_fd;
	struct winsize winsize;
	struct winsize winsize_prev;
	int row_total; // Rows including console
	int peer_count;
	int peer_id_counter;
	GS_EVENT event_ping;
	GS_EVENT event_bps;
	GS_EVENT *event_ids;
	GS_LIST ids_peers;
	char *ids_active_user;
	int ids_idle;
	int n_users;             // Number of unique logged in users (from utmp)
	int app_keepalive_sec;   // Interval for app-keepalive
};

#ifdef DEBUG
#define GS_APP_KEEPALIVE        10 // If no activty send app-layer ping (-i needed)
#else
#define GS_APP_KEEPALIVE        GSRN_DEFAULT_PING_INTERVAL // If no activty send app-layer ping (-i needed)
#endif
// Let the client be in control to send PING's to keep the connection busy
// but if the client is 5 sec late then start sending PINGS to client.
#define GS_APP_KEEPALIVE_SERVER   (GS_APP_KEEPALIVE + 5)

#define EX_CONNREFUSED  61  // Used by deploy.sh to verify that server is responding
#define EX_BAD_AUTH    201  // Used to terminate watchdog/daemon
#define EX_ALARM       202
#define EX_NETERROR    203  // likely TCP ECONNREFUSED
#define EX_EXECFAILED  248
#define EX_NOTREACHED  249
#define EX_BADWRITE    250  // write() failed
#define EX_UNKNWNCMD   251  // Unknown command line parameter

#define EX_BADSELECT   253
#define EX_SIGTERM     254
#define EX_FATAL       255

struct _socks
{
	uint32_t dst_ip;
	uint16_t dst_port;
	char dst_hostname[256];	// dst host name. 
	int state;
};

#define GSNC_STATE_AWAITING_MSG_AUTH        (0x01)
#define GSNC_STATE_AWAITING_MSG_CONNECT     (0x02)
#define GSNC_STATE_RESOLVING_DN	            (0x03)
#define GSNC_STATE_CONNECTING               (0x04)
#define GSNC_STATE_CONNECTED                (0x05)


/* gs-netcat peers */
struct _peer
{
	/* A peer is connected to a gsocket and the a cmd_fd */
	GS *gs;
	int fd_in;
	int fd_out;	/* Same as fd_in unless client reads from stdin/stdout */
	uint8_t rbuf[2048];	/* from GS, to fd */
	size_t r_max;
	ssize_t rlen;
	uint8_t wbuf[2048];	/* from fd, to GS */
	size_t w_max;
	ssize_t wlen;
	uint8_t pbuf[2048];	/* for pkt-encode/decode */
	int is_network_forward;
	int is_stdin_forward;
	int is_app_forward;
	int is_fd_connected;
	int is_pty_first_read;		/* send stty hack */
	int is_stty_set_raw;		/* Client only */
	int is_received_gs_eof;     // EOF from GSRN
	int is_want_ping;       // Client: Wants to send a ping
	/* For Statistics */
	int id;			/* Stats: assign an ID to each pere */
	struct _socks socks;
	GS_PKT pkt;		// In-band data for interactive shell (-i)
	GS_FT ft;       // Filetransfer (-i)
	GS_LIST logs;   // Queue for log messages from Server to Client (-i)
	int is_pending_logs; // Log files need to be send to peer.
	GS_LIST_ITEM *ids_li;  // Peer is interested in global IDS logs
	pid_t pid;
	uint64_t ts_peer_io;   // TimeStamp of last peer I/O (e.g. UDP, stdin, ...)
	GS_BUF udp_buf;         // UDP un-stacker (for -u)
	GS_EVENT event_peer_timeout;
};

#define GSC_FL_IS_SERVER		(0x01)


extern struct _gopt gopt; // declared in utils.c

#define xfprintf(fp, a...) do {if (fp != NULL) { fprintf(fp, a); fflush(fp); } } while (0)

#define int_ntoa(x)	inet_ntoa(*((struct in_addr *)&x))

#ifndef MAX
# define MAX(X, Y) (((X) < (Y)) ? (Y) : (X))
#endif

#ifndef MIN
# define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
#endif

#define D_RED(a)	"\033[0;31m"a"\033[0m"
#define D_GRE(a)	"\033[0;32m"a"\033[0m"
#define D_YEL(a)	"\033[0;33m"a"\033[0m"
#define D_BLU(a)	"\033[0;34m"a"\033[0m"
#define D_MAG(a)	"\033[0;35m"a"\033[0m"
#define D_BRED(a)	"\033[1;31m"a"\033[0m"
#define D_BGRE(a)	"\033[1;32m"a"\033[0m"
#define D_BYEL(a)	"\033[1;33m"a"\033[0m"
#define D_BBLU(a)	"\033[1;34m"a"\033[0m"
#define D_BMAG(a)	"\033[1;35m"a"\033[0m"

#ifdef DEBUG
struct _g_debug_ctx
{
	struct timeval tv_last;
	struct timeval tv_now;
};

extern struct _g_debug_ctx g_dbg_ctx; // declared in utils.c

#define DEBUGF_T(xcolor, a...) do { \
	gettimeofday(&g_dbg_ctx.tv_now, NULL); \
	if (g_dbg_ctx.tv_last.tv_sec == 0) { memcpy(&g_dbg_ctx.tv_last, &g_dbg_ctx.tv_now, sizeof g_dbg_ctx.tv_last); } \
	xfprintf(gopt.err_fp, "DEBUG %4"PRIu64" %s:%d %s", GS_TV_TO_MSEC(&g_dbg_ctx.tv_now) - GS_TV_TO_MSEC(&g_dbg_ctx.tv_last), __func__, __LINE__, xcolor?xcolor:""); \
	memcpy(&g_dbg_ctx.tv_last, &g_dbg_ctx.tv_now, sizeof g_dbg_ctx.tv_last); \
	xfprintf(gopt.err_fp, a); \
	if (xcolor) { xfprintf(gopt.err_fp, "\033[0m"); } \
} while (0)

# define DEBUGF(a...) do{DEBUGF_T(NULL, a); } while(0)
# define DEBUGF_R(a...) do{DEBUGF_T("\033[1;31m", a); } while(0)
# define DEBUGF_G(a...) do{DEBUGF_T("\033[1;32m", a); } while(0)
# define DEBUGF_B(a...) do{DEBUGF_T("\033[1;34m", a); } while(0)
# define DEBUGF_Y(a...) do{DEBUGF_T("\033[1;33m", a); } while(0)
# define DEBUGF_M(a...) do{DEBUGF_T("\033[1;35m", a); } while(0)
# define DEBUGF_C(a...) do{DEBUGF_T("\033[1;36m", a); } while(0)
# define DEBUGF_W(a...) do{DEBUGF_T("\033[1;37m", a); } while(0)
#else // DEBUG
# define DEBUGF(a...)
# define DEBUGF_R(a...)
# define DEBUGF_G(a...)
# define DEBUGF_B(a...)
# define DEBUGF_Y(a...)
# define DEBUGF_M(a...)
# define DEBUGF_C(a...)
# define DEBUGF_W(a...)
# define DEBUGF_A(a...)
#endif

// Increase ptr by number of characters added to ptr.
#define SXPRINTF(ptr, len, a...) do {\
	size_t n = snprintf(ptr, len, a); \
	ptr += MIN(n, len); \
} while(0)

// Overcome GCC warning for truncation. Abort() if truncation happen.
#define SNPRINTF_ABORT(...)	(snprintf(__VA_ARGS__) < 0 ? abort() : (void)0)

#define VOUT(level, a...) do { \
	if (level > gopt.verboselevel) \
		break; \
	xfprintf(gopt.out, a); \
	fflush(gopt.out); \
} while (0)

#define XFREE(ptr)  do{if(ptr) free(ptr); ptr = NULL;}while(0)

#define ERREXITC(code, a...)   do { \
		xfprintf(gopt.err_fp, "ERROR(%d): ", code); \
        xfprintf(gopt.err_fp, a); \
        exit(code); \
} while (0)

#ifdef DEBUG
# define ERREXIT(a...)   do { \
		xfprintf(gopt.err_fp, "ERROR "); \
        xfprintf(gopt.err_fp, "%s():%d ", __func__, __LINE__); \
        xfprintf(gopt.err_fp, a); \
        exit(255); \
} while (0)
#else
# define ERREXIT(a...)   do { \
		xfprintf(gopt.err_fp, "ERROR: "); \
        xfprintf(gopt.err_fp, a); \
        exit(255); \
} while (0)
#endif

#ifndef XASSERT
# define XASSERT(expr, a...) do { \
	if (!(expr)) { \
		xfprintf(gopt.err_fp, "%s:%d:%s() ASSERT(%s) ", __FILE__, __LINE__, __func__, #expr); \
		xfprintf(gopt.err_fp, a); \
		xfprintf(gopt.err_fp, " Exiting...\n"); \
		exit(255); \
	} \
} while (0)
#endif

#define XCLOSE(fd)      do { \
        if (fd < 0) { DEBUGF_R("*** WARNING *** CLosing BAD fd\n"); break; } \
        DEBUGF_W("Closing fd = %d\n", fd); \
        close(fd); \
        fd = -1; \
} while (0)

#define XFCLOSE(fp)		do { \
		if (fp == NULL) { DEBUGF_R("*** WARNING *** Closing BAD fp\n"); break; } \
		fclose(fp); \
		fp = NULL; \
} while (0)


#define XFD_SET(fd, set) do { \
        if (fd < 0) { DEBUGF_R("WARNING: FD_SET(%d, )\n", fd); break; } \
        FD_SET(fd, set); \
} while (0)

#ifdef DEBUG
# define HEXDUMP(a, _len)        do { \
        size_t _n = 0; \
        xfprintf(gopt.err_fp, "%s:%d HEX[%zd] ", __FILE__, __LINE__, _len); \
        while (_n < (_len)) xfprintf(gopt.err_fp, "%2.2x", ((unsigned char *)a)[_n++]); \
        xfprintf(gopt.err_fp, "\n"); \
} while (0)
# define HEXDUMPF(a, len, m...) do{xfprintf(gopt.err_fp, m); HEXDUMP(a, len);}while(0)
#else
# define HEXDUMP(a, len)
# define HEXDUMPF(a, len, m...)
#endif

#endif /* !__GST_COMMON_H__ */
