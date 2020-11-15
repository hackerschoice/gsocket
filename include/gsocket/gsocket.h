
#ifndef __LIBGSOCKET_H__
#define __LIBGSOCKET_H__ 1


#if 0
#if defined __has_include
#   if __has_include (<openssl/srp.h>)
#       define HAS_OPENSSL_SRP  1
#   endif
#	if __has_include ("gsocket-ssl.h")
#		define HAS_GSOCKET_SSL	1
#	endif
#	if __has_include (<gsocket/gsocket-ssl.h>)
#		define HAS_GSOCKET_SSL	1
#	endif
#endif

/* The user can delete gsocket-ssl.h to build his project without OpenSSL */
#ifdef HAS_OPENSSL_SRP
#	ifdef HAS_GSOCKET_SSL
#		define WITH_GSOCKET_SSL		1
#	endif
#endif
#endif

#define WITH_GSOCKET_SSL 1

#ifndef GS_MAX
# define GS_MAX(X, Y) (((X) < (Y)) ? (Y) : (X))
#endif

#ifndef GS_MIN
# define GS_MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
#endif

#define GS_ADDR_SIZE				(16)	/* 128 bit */
#define GS_ADDR_B58_LEN 			(GS_ADDR_SIZE) * 138 / 100 + 1
#define GS_ADDR_PROTO_SIZE			(32)	/* 256 bit */
#define GS_MAX_SOX_BACKLOG			(5)		/* Relevant for GS_listen() only */
#define GS_TOKEN_SIZE 				(16)	/* 128 bit */

#define GS_TV_TO_USEC(tv)		((uint64_t)(tv)->tv_sec * 1000000 + (tv)->tv_usec)
#define GS_TV_DIFF(tv_a, tv_b)	(GS_TV_TO_USEC(tv_b) - GS_TV_TO_USEC(tv_a))
#define GS_SEC_TO_USEC(sec)		((uint64_t)sec * 1000000)
#define GS_USEC_TO_SEC(usec)	(usec / 1000000)

#define GS_SECRET_MAX_LEN               (256 / 8)       /* max length in bytes */
#define GS_DFL_CIPHER                  "SRP-AES-256-CBC-SHA"
#define GS_DFL_CIPHER_STRENGTH         "4096"

#include <gsocket/gs-select.h>
#include <gsocket/packet.h>

/* ###########################
 * ### PROTOCOL DEFINITION ###
 * ###########################
 */
/* First message from Listening Client (LC) to GS-Network (GN) [server]
 * LC2GN: Register a GS-Address for listening.
 */
struct _gs_listen		/* 128 bytes */
{
	uint8_t type;
	uint8_t version_major;
	uint8_t version_minor;
	uint8_t flags;
	uint8_t reserved1[4];

	uint8_t reserved2[8];

	uint8_t token[GS_TOKEN_SIZE];
	uint8_t addr[GS_ADDR_PROTO_SIZE];		/* 32 bytes */
	uint8_t reserved3[64];
};

/*
 * First message from Connecting Client (CC) to GS-Network (GN) [server]
 * CC2GN: Connect a listening GS-Address.
 * CC awaiting _gs_start from GN.
 */
struct _gs_connect
{
	uint8_t type;
	uint8_t version_major;
	uint8_t version_minor;
	uint8_t flags;

	uint8_t reserved2[28];

	uint8_t addr[GS_ADDR_PROTO_SIZE];		/* 32 bytes */
	uint8_t reserved3[64];
};
#define GS_PKT_PROTO_VERSION_MAJOR		(0x01)
#define GS_PKT_PROTO_VERSION_MINOR		(0x02)

#define GS_FL_PROTO_WAIT				(0x01)	/* Wait for LC to connect */

/* Client allowed to become a Server if Server does not exist.
 * Or Server allowed to become a Client if Server already exists.
 */
#define GS_FL_PROTO_CLIENT_OR_SERVER	(0x02)

/*
 * all2GN
 */
struct _gs_ping
{
	uint8_t type;
	uint8_t reserved[3];

	uint8_t payload[28];
};

/*
 * GN2all
 */
struct _gs_pong
{
	uint8_t type;
	uint8_t reserved[3];

	uint8_t payload[28];
};

/* GN2all: New incoming connection.
 * GN must not send any further GS messages.
 */
struct _gs_start
{
	uint8_t type;
	uint8_t flags;
	uint8_t reserved[2];

	uint8_t reserved2[28];
};
#define GS_FL_PROTO_START_SERVER		(0x01)	/* Act as a Server [ssl] */
#define GS_FL_PROTO_START_CLIENT		(0x02)	/* Act as a Client [ssl] */

/* GN2all: Status (error)
 */
struct _gs_status
{
	uint8_t type;
	uint8_t err_type;
	uint8_t code;
	uint8_t reserved[1];

	uint8_t msg[28];	
};

/* err_type */
#define GS_STATUS_TYPE_WARN			(0x01)
#define GS_STATUS_TYPE_FATAL		(0x02)	// Must exit.

#define GS_STATUS_CODE_BAD_AUTH		(0x01)	// Auth Token mismatch
#define GS_STATUS_CODE_CONNREFUSED	(0x02)	// No server listening
#define GS_STATUS_CODE_IDLE_TIMEOUT (0x03)	// Timeout

/*
 * all2GN: Accepting incoming connection.
 * LC/CC must not send any further GS messages.
 */
struct _gs_accept
{
	uint8_t type;
	uint8_t reserved[3];

	uint8_t reserved2[28];
};

#define GS_PKT_TYPE_LISTEN	(0x01)	// LC2GN
#define GS_PKT_TYPE_CONNECT	(0x02)	// CC2GN
#define GS_PKT_TYPE_PING	(0x03)	// all2GN
#define GS_PKT_TYPE_PONG	(0x04)  // GN2all
#define GS_PKT_TYPE_START	(0x05)	// GN2all
#define GS_PKT_TYPE_ACCEPT	(0x06)	// all2GN
#define GS_PKT_TYPE_STATUS	(0x07)	// GN2all


#define GS_MAX_MSG_LEN	GS_MAX(sizeof (struct _gs_listen), GS_MAX(sizeof (struct _gs_ping), GS_MAX(sizeof (struct _gs_pong), sizeof (struct _gs_start))))

enum gs_ctx_flags_t {GS_CTX_FL_RFD_INTERNAL};
enum gs_flags_t {
	GS_FL_TCP_CONNECTED 		= 0x01,  // App TCP sockets are connected
	GSC_FL_NONBLOCKING 			= 0x02,  // Do not Block on socket IO
	GS_FL_CALLED_NET_CONNECT 	= 0x04,  // GS_connect() already called GS_FL_CALLED_NET_CONNECT
	GS_FL_IS_CLIENT 			= 0x08,
	GS_FL_CALLED_NET_NEW_SOCKET = 0x10,
	GSC_FL_USE_SRP 				= 0x20,
	GSC_FL_CLIENT_OR_SERVER 	= 0x40,
	GS_FL_IS_SERVER 			= 0x80,  // A GS-CLient (the first connected) is an SRP-Server
	GS_FL_AUTO_RECONNECT 		= 0x100, // GS_accept() to reconnect on GS-NET errors
	GS_FL_SINGLE_SHOT			= 0x200  // single GS_listen(). (for stdin/stdout)
};

/*
 * - GS-Network host/port
 * - Handle TCP sockets (non-blocking)
 */
typedef struct
{
	int max_sox;
	fd_set *rfd;
	fd_set *wfd;
	fd_set *r;
	fd_set *w;
	int gsocket_success_count;	/* Successfull connection counter */
	GS_SELECT_CTX *gselect_ctx;
	/* Listening CB and values */
	gselect_cb_t func_listen;
	int cb_val_listen;

	struct timeval *tv_now;
	char err_buf[1024];
	char err_buf2[1024];

	enum gs_ctx_flags_t flags;	// CTX specific flags

	enum gs_flags_t gs_flags;	// GS specific flags. Copied to GS on creation.
	uint32_t flags_proto;

	uint32_t socks_ip;			// NBO. Use Socks5
	uint16_t socks_port;		// Socks5
	uint16_t gs_port;			// 7350 or GSOCKET_PORT
} GS_CTX;


enum sox_state_t {
	GS_STATE_SYS_NONE,		// We are idle...
	GS_STATE_SYS_CONNECT,	// need call to 'connect()' _again_.
	GS_STATE_SYS_RECONNECT,	// Re-connecting to GS-NET
	GS_STATE_PKT_LISTEN,	// listen_write() did not complete
	GS_STATE_PKT_PING,		// ping_write() did not complete
	GS_STATE_APP_CONNECTED,	// Application is connected. Passingthrough of data (no pkt any longer)
	GS_STATE_PKT_CONNECT,
	GS_STATE_PKT_ACCEPT,
	GS_STATE_SOCKS			// TOR
};

enum sox_flags_t {
	GS_SOX_FL_AWAITING_PONG,	// Waiting for PONG
	GS_SOX_FL_AWAITING_SOCKS	// Waiting for Socks5 (TOR) reply
};

/* TCP network address may depend on GS_ADDR (load balancing) */
struct gs_sox
{
	int fd;
	enum sox_state_t state;
	enum sox_flags_t flags;
	uint8_t rbuf[GS_MAX_MSG_LEN];
	size_t rlen;
	uint8_t wbuf[GS_MAX_MSG_LEN];
	size_t wlen;
	struct timeval tv_last_data;		/* For KeepAlive */
};

struct gs_net
{
	uint16_t port;	/* NBO */
	uint32_t addr;	/* IPv4, NBO */
	int conn_count;
	struct gs_sox sox[GS_MAX_SOX_BACKLOG];
	int n_sox;				/* Number of sox[n] entries */
	int fd_accepted;
	char *hostname;			/* xxx.gs.thc.org */
	uint64_t tv_connect;			// Time connect() was called
	uint64_t tv_gs_hton;			// Time hostname was resolved last.			
	int is_connect_error_warned;	// 'Re-connecting...' warning issued
};


typedef struct
{
	uint8_t addr[GS_ADDR_SIZE];
	char b58str[GS_ADDR_B58_LEN + 1];		/* Base58 string representation of gs-address + \0-terminated. */
	size_t b58sz;							/* Base58 size */
} GS_ADDR;

#ifdef WITH_GSOCKET_SSL
enum ssl_state_t {
	GS_SSL_STATE_ACCEPT,	/* Call SSL_accpet() again */
	GS_SSL_STATE_CONNECT,	/* Call SSL_connect() again */
	GS_SSL_STATE_RW,		/* Call SSL_read/SSL_write again */
	GS_SSL_STATE_SHUTDOWN   /* Call SSL_shutdown() again */
};
#endif

/*
 * A specific GS connection with a single GSOCKET-ID.
 * There can be multiple connection per GSOCKET-ID (eventually).
 */
typedef struct
{
	GS_CTX *ctx;
	GS_ADDR gs_addr;
	enum gs_flags_t flags;
	int id;					/* ID of this gsocket. Set AFTER conn success */
	struct gs_net net;		/* fd's for listening tcp_fd */
	int fd;					/* Only set if this is a 'connected' tcp_fd (not listening socket) */
	int64_t bytes_read;
	int64_t bytes_written;
	struct timeval tv_connected;	/* TV when GS entered CONNECTED state */
	int read_pending;
	int write_pending;
	int is_sent_shutdown;
	int is_want_shutdown;	/* Call GS_shutdown() after SRP completion */
	uint8_t token[GS_TOKEN_SIZE];
	int eof_count;			/* How many EOF received (needed for ssl compat) */
#ifdef WITH_GSOCKET_SSL
	SSL_CTX *ssl_ctx;
	SRP_VBASE *srpData;		/* Verifier is identical 4 all conns on same GS */
	SSL *ssl;
	enum ssl_state_t ssl_state;
	char srp_sec[128];		/* SRP Secret */
	int ssl_shutdown_count;	// Calls to gs_ssl_close 
#endif
} GS;


/* #####################################
 * ### GSOCKET FUNCTION DECLARATIONS ###
 * #####################################
 */

void GS_library_init(FILE *err_fp, FILE *dout_fp);
int GS_CTX_init(GS_CTX *, fd_set *rfd, fd_set *wfd, fd_set *r, fd_set *w, struct timeval *tv_now);
void GS_CTX_use_gselect(GS_CTX *ctx, GS_SELECT_CTX *gselect_ctx);
int GS_CTX_free(GS_CTX *);
GS *GS_new(GS_CTX *ctx, GS_ADDR *addr);		/* Connect to GS-Network */
const char *GS_CTX_strerror(GS_CTX *gs_ctx);
const char *GS_strerror(GS *gsocket);

int GS_connect(GS *gsocket);	/* Fail if no such GS-ID is listening */
int GS_get_fd(GS *gsocket);
int GS_listen(GS *gsocket, int backlog);	/* Listen for an incoming GS connection */
void GS_listen_add_gs_select(GS *gs, GS_SELECT_CTX *ctx, gselect_cb_t func, void *arg, int val);
GS *GS_accept(GS *gsocket, int *error);	/* Wait until client connects by GS-ID and return Unix fileno */
int GS_close(GS *gsocket);		/* close() and free() a connected GS */
int GS_shutdown(GS *gsocket);
void GS_heartbeat(GS *gsocket);
void GS_set_token(GS *gsocket, const void *buf, size_t num);
/* Logging */
char *GS_usecstr(char *dst, size_t len, uint64_t usec);
char *GS_bytesstr(char *dst, size_t len, int64_t bytes);
char *GS_bytesstr_long(char *dst, size_t len, int64_t bytes);
const char *GS_logtime(void);

int GS_CTX_setsockopt(GS_CTX *ctx, int level, const void *opt_value, size_t opt_len);

#define GS_OPT_SOCKWAIT				(0x02)
#define GS_OPT_BLOCK				(0x04)	/* Blocking TCP */
#define GS_OPT_NO_ENCRYPTION		(0x08)
#define GS_OPT_CLIENT_OR_SERVER		(0x10)	/* Whoever connects first acts as a Server */
#define GS_OPT_USE_SOCKS			(0x20)	// Use TOR (Socks5)
#define GS_OPT_SINGLESHOT			(0x40)

ssize_t GS_write(GS *gsocket, const void *buf, size_t num);
ssize_t GS_read(GS *gsocket, void *buf, size_t num);
GS_ADDR *GS_ADDR_bin2addr(GS_ADDR *addr, const void *data, size_t len);
GS_ADDR *GS_ADDR_str2addr(GS_ADDR *addr, const char *str);
GS_ADDR *GS_ADDR_ipport2addr(GS_ADDR *addr, uint32_t ip, uint16_t port);
uint32_t GS_hton(const char *hostname);
void GS_SELECT_FD_SET_W(GS *gs);

void GS_daemonize(FILE *logfp);

const char *GS_gen_secret(void);
const char *GS_user_secret(GS_CTX *ctx, const char *file, const char *sec_str);

#ifdef WITH_GSOCKET_SSL
const char *GS_SSL_strerror(int err);
void GS_srp_setpassword(GS *gsocket, const char *pwd);
const char *GS_get_cipher(GS *gs);
int GS_get_cipher_strength(GS *gs);
int GS_is_server(GS *gs);
#endif /* !WITH_GSOCKET_SSL */

#endif /* !__LIBGSOCKET_H__ */
