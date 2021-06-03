
#ifndef __GS_COMMON_H__
#define __GS_COMMON_H__ 1

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#if defined(__FREEBSD__)
# include <sys/sysctl.h>
# include <sys/caprights.h>
# include <sys/param.h>
# include <sys/queue.h>
#endif // __FREEBSD__
#include <netinet/in.h>
#ifdef HAVE_NETINET_IN_SYSTM_H
# include <netinet/in_systm.h>
#endif
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>              // gethostbyname
#include <errno.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <inttypes.h>
#include <signal.h>
#include <libgen.h>		/* basename() */
#if defined(__APPLE__) && defined(HAVE_LIBPROC_H)
# include <libproc.h>          // getpidwd(pid_t)
#endif
#if defined(__FREEBSD__)
// FIXME: Please tell me where this is defined? fbsd 12-1 complains:
// /usr/include/libprocstat.h:122:15: error: field 'fs_cap_rights' has incomplete type
# ifndef cap_rights_t
typedef struct cap_rights       cap_rights_t;
# endif
# include <libprocstat.h>
#endif
#include <openssl/srp.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#ifndef MAX
# define MAX(X, Y) (((X) < (Y)) ? (Y) : (X))
#endif

#ifndef MIN
# define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
#endif

// debian-hurd does not define PATH_MAX (and has no limit on filename length)
#ifndef PATH_MAX
# define GS_PATH_MAX      4096
#else
# define GS_PATH_MAX      PATH_MAX
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
# define DEBUGF(a...)   do{ xfprintf(gs_dout, D_BLU("LIB")"-%d %s:%d: ", gs_did, __func__, __LINE__); xfprintf(gs_dout, a); }while(0)
# define DEBUGF_R(a...) do{ xfprintf(gs_dout, D_BLU("LIB")"-%d %s:%d: ", gs_did, __func__, __LINE__); xfprintf(gs_dout, "\033[1;31m"); xfprintf(gs_dout, a); xfprintf(gs_dout, "\033[0m"); }while(0)
# define DEBUGF_G(a...) do{ xfprintf(gs_dout, D_BLU("LIB")"-%d %s:%d: ", gs_did, __func__, __LINE__); xfprintf(gs_dout, "\033[1;32m"); xfprintf(gs_dout, a); xfprintf(gs_dout, "\033[0m"); }while(0)
# define DEBUGF_B(a...) do{ xfprintf(gs_dout, D_BLU("LIB")"-%d %s:%d: ", gs_did, __func__, __LINE__); xfprintf(gs_dout, "\033[1;34m"); xfprintf(gs_dout, a); xfprintf(gs_dout, "\033[0m"); }while(0)
# define DEBUGF_Y(a...) do{ xfprintf(gs_dout, D_BLU("LIB")"-%d %s:%d: ", gs_did, __func__, __LINE__); xfprintf(gs_dout, "\033[1;33m"); xfprintf(gs_dout, a); xfprintf(gs_dout, "\033[0m"); }while(0)
# define DEBUGF_M(a...) do{ xfprintf(gs_dout, D_BLU("LIB")"-%d %s:%d: ", gs_did, __func__, __LINE__); xfprintf(gs_dout, "\033[1;35m"); xfprintf(gs_dout, a); xfprintf(gs_dout, "\033[0m"); }while(0)
# define DEBUGF_C(a...) do{ xfprintf(gs_dout, D_BLU("LIB")"-%d %s:%d: ", gs_did, __func__, __LINE__); xfprintf(gs_dout, "\033[1;36m"); xfprintf(gs_dout, a); xfprintf(gs_dout, "\033[0m"); }while(0)
# define DEBUGF_W(a...) do{ xfprintf(gs_dout, D_BLU("LIB")"-%d %s:%d: ", gs_did, __func__, __LINE__); xfprintf(gs_dout, "\033[1;37m"); xfprintf(gs_dout, a); xfprintf(gs_dout, "\033[0m"); }while(0)
# define DEBUG_SETID(xgs)    gs_did = (xgs)->fd
#else
# define DEBUGF(a...)
# define DEBUGF_R(a...)
# define DEBUGF_G(a...)
# define DEBUGF_B(a...)
# define DEBUGF_Y(a...)
# define DEBUGF_M(a...)
# define DEBUGF_C(a...)
# define DEBUGF_W(a...)
# define DEBUG_SETID(xgs)
#endif

#define SXPRINTF(ptr, len, a...) do {\
        size_t n = snprintf(ptr, len, a); \
        ptr += MIN(n, len); \
} while(0)

#define XFREE(ptr)  do{if(ptr) free(ptr); ptr = NULL;}while(0)

#define xfprintf(fp, a...) do {if (fp != NULL) { fprintf(fp, a); fflush(fp); } } while (0)

#ifdef DEBUG
# define ERREXIT(a...)   do { \
	xfprintf(gs_errfp, "ERROR "); \
        xfprintf(gs_errfp, "%s():%d ", __func__, __LINE__); \
        xfprintf(gs_errfp, a); \
        exit(255); \
} while (0)
#else
# define ERREXIT(a...)   do { \
	xfprintf(gs_errfp, "ERROR: "); \
        xfprintf(gs_errfp, a); \
        exit(255); \
} while (0)
#endif

#ifndef XASSERT
# define XASSERT(expr, a...) do { \
	if (!(expr)) { \
		xfprintf(gs_errfp, "%s:%d:%s() ASSERT(%s) ", __FILE__, __LINE__, __func__, #expr); \
		xfprintf(gs_errfp, a); \
		xfprintf(gs_errfp, " Exiting...\n"); \
		exit(255); \
	} \
} while (0)
#endif

#define XCLOSE(fd)      do { \
        if (fd < 0) { break; } \
        DEBUGF_W("Closing fd = %d\n", fd); \
        close(fd); \
        fd = -1; \
} while (0)

#define XFD_SET(fd, set) do { \
        /*if (fd <= 0) { DEBUGF_R("WARNING: FD_SET(%d, )\n", fd); } */ \
        if (fd < 0) { break; } \
        FD_SET(fd, set); \
} while (0)

#define XFD_CLR(fd, set) do { \
        if (fd <= 0) { DEBUGF_R("WARNING: FD_CLR(%d, )\n", fd); } \
        if (fd < 0) { break; } \
        FD_CLR(fd, set); \
} while (0)

#ifdef DEBUG
# define HEXDUMP(a, len)        do { \
        int n = 0; \
        xfprintf(gs_dout, D_BLU("LIB")" %s:%d HEX ", __FILE__, __LINE__); \
        while (n < len) { xfprintf(gs_dout, "%2.2x", ((unsigned char *)a)[n]); n++; } \
        xfprintf(gs_dout, "\n"); \
} while (0)

# define HEXDUMPF(a, len, m...) do{xfprintf(gs_dout, m); HEXDUMP(a, len);}while(0)
#else
# define HEXDUMP(a, len)
# define HEXDUMPF(a, len, m...)
#endif

#endif /* !__GS_COMMON_H__ */
