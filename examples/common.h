
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
#include <netinet/in.h>
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
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <inttypes.h>
#include <signal.h>
#include <libgen.h>		/* basename() */
#include <termios.h>
#ifdef HAVE_PTY_H
# include <pty.h>
#endif
#ifdef HAVE_UTIL_H
# include <util.h>		/* MacOS */
#endif
#include <openssl/ssl.h>
#include <openssl/srp.h>
#include <gsocket/gsocket.h>
#include <gsocket/gs-select.h>

#ifndef O_NOCTTY
#define O_NOCTTY 0
#endif

struct _gopt
{
	GS_CTX gs_ctx;
	GS *gsocket;	/* Listening gsocket */

	int flags;
	int verboselevel;
	const char *sec_str;
	const char *sec_file;
	GS_ADDR gs_addr;
	char *token_str;
	int is_sock_wait;
	int is_client_or_server;
	int is_encryption;
	int is_interactive;	/* PTY interactive shell? */
	int is_receive_only;
	fd_set rfd, r;
	fd_set wfd, w;
	struct timeval tv_now;
	const char *cmd;
	uint32_t dst_ip;	/* NBO */
	uint16_t port;		/* NBO */
	struct winsize winsize;
	int peer_count;
};

#define GSC_FL_IS_SERVER		(0x01)


extern struct _gopt gopt;

#ifndef MAX
# define MAX(X, Y) (((X) < (Y)) ? (Y) : (X))
#endif

#ifndef MIN
# define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
#endif

#ifdef DEBUG
# define D_RED(a)	"\033[0;31m"a"\033[0m"
# define D_GRE(a)	"\033[0;32m"a"\033[0m"
# define D_YEL(a)	"\033[0;33m"a"\033[0m"
# define D_BLU(a)	"\033[0;34m"a"\033[0m"
# define D_MAG(a)	"\033[0;35m"a"\033[0m"
# define D_BRED(a)	"\033[1;31m"a"\033[0m"
# define D_BGRE(a)	"\033[1;32m"a"\033[0m"
# define D_BYEL(a)	"\033[1;33m"a"\033[0m"
# define D_BBLU(a)	"\033[1;34m"a"\033[0m"
# define D_BMAG(a)	"\033[1;35m"a"\033[0m"
# define DEBUGF(a...) do{fprintf(stderr, "DEBUG %s:%d: ", __func__, __LINE__); fprintf(stderr, a); }while(0)
# define DEBUGF_R(a...) do{fprintf(stderr, "DEBUG %s:%d: ", __func__, __LINE__); fprintf(stderr, "\033[1;31m"); fprintf(stderr, a); fprintf(stderr, "\033[0m"); }while(0)
# define DEBUGF_G(a...) do{fprintf(stderr, "DEBUG %s:%d: ", __func__, __LINE__); fprintf(stderr, "\033[1;32m"); fprintf(stderr, a); fprintf(stderr, "\033[0m"); }while(0)
# define DEBUGF_B(a...) do{fprintf(stderr, "DEBUG %s:%d: ", __func__, __LINE__); fprintf(stderr, "\033[1;34m"); fprintf(stderr, a); fprintf(stderr, "\033[0m"); }while(0)
# define DEBUGF_Y(a...) do{fprintf(stderr, "DEBUG %s:%d: ", __func__, __LINE__); fprintf(stderr, "\033[1;33m"); fprintf(stderr, a); fprintf(stderr, "\033[0m"); }while(0)
# define DEBUGF_M(a...) do{fprintf(stderr, "DEBUG %s:%d: ", __func__, __LINE__); fprintf(stderr, "\033[1;35m"); fprintf(stderr, a); fprintf(stderr, "\033[0m"); }while(0)
#else
# define DEBUGF(a...)
# define DEBUGF_R(a...)
# define DEBUGF_G(a...)
# define DEBUGF_B(a...)
# define DEBUGF_Y(a...)
# define DEBUGF_M(a...)
#endif

#define VOUT(level, a...) do { \
	if (level > gopt.verboselevel) \
		break; \
	fprintf(gopt.out, a); \
	fflush(gopt.out); \
} while (0)

#define XFREE(ptr)  do{if(ptr) free(ptr); ptr = NULL;}while(0)

#ifdef DEBUG
# define ERREXIT(a...)   do { \
		fprintf(stderr, "ERROR "); \
        fprintf(stderr, "%s():%d ", __func__, __LINE__); \
        fprintf(stderr, a); \
        exit(255); \
} while (0)
#else
# define ERREXIT(a...)   do { \
		fprintf(stderr, "ERROR: "); \
        fprintf(stderr, a); \
        exit(255); \
} while (0)
#endif

#ifndef XASSERT
# define XASSERT(expr, a...) do { \
	if (!(expr)) { \
		fprintf(stderr, "%s:%d:%s() ASSERT(%s) ", __FILE__, __LINE__, __func__, #expr); \
		fprintf(stderr, a); \
		fprintf(stderr, " Exiting...\n"); \
		exit(255); \
	} \
} while (0)
#endif

#ifdef DEBUG
# define HEXDUMP(a, len)        do { \
        int n = 0; \
        fprintf(stderr, "%s:%d HEX ", __FILE__, __LINE__); \
        while (n < len) fprintf(stderr, "%2.2x", ((unsigned char *)a)[n++]); \
        fprintf(stderr, "\n"); \
} while (0)
#else
# define HEXDUMP(a, len)
#endif

#endif /* !__GST_COMMON_H__ */
