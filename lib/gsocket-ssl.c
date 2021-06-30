

#include "gs-common.h"
#include <gsocket/gsocket.h>
#include "gsocket-engine.h"
#include "gs-externs.h"

#ifdef HAVE_LIBCRYPTO

#include <openssl/srp.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>

/*
 * Called by the SSL object when a SRP negotiation is requested by peer.
 * ### SERVER ###
 */
static int
srp_username_cb(SSL *ssl, int *ad, void *arg)
{
	SRP_user_pwd *p;
	SRP_VBASE *lsrpData = (SRP_VBASE *)arg;

	if (ssl == NULL)
		return -1;

	if (lsrpData == NULL)
		return -1;	// Not ready yet.

	p = SRP_VBASE_get1_by_user(lsrpData, "user");
	if (p == NULL)
		return -1;	// Bad User.

	if (SSL_set_srp_server_param(ssl, p->N, p->g, p->s, p->v, NULL) != 1)
        ERREXIT("SSL_set_srp_server_param() failed...\n");
    SRP_user_pwd_free(p);
	// DEBUGF("SUCCESS, returning SSL_ERROR_NONE\n");

    return SSL_ERROR_NONE;
}

/*
 * ### CLIENT ###
 */
static char *
srp_client_pwd_cb(SSL *ssl, void *arg)
{
	GS *gs = (GS *)arg;
	DEBUGF("Called in CLIENT only??? ssl = %p, arg = %p, pwd='%s'\n", ssl, arg, gs->srp_sec);
	return OPENSSL_strdup(gs->srp_sec);
}

/*
 * ### SERVER ###
 */
static void
gs_srp_setpassword(GS *gs, const char *pwd_str)
{
	SRP_gN *gN;
	SRP_user_pwd *p;

	DEBUGF("Setting SRP password to '%s'\n", pwd_str);
	if (gs->srpData != NULL)
	{
		DEBUGF("WARNING: srpData already initizalied\n");
		return;
	}

	gs->srpData = SRP_VBASE_new(NULL);
	XASSERT(gs->srpData != NULL, "\n");

	p = (SRP_user_pwd *)OPENSSL_malloc(sizeof (SRP_user_pwd));
	XASSERT(p != NULL, "\n");

	gN = SRP_get_default_gN(GS_DFL_CIPHER_STRENGTH);
	XASSERT(gN != NULL, "SRP_get_default_gN()\n");

	char *srpCheck = SRP_check_known_gN_param(gN->g, gN->N);
	XASSERT(srpCheck != NULL, "Bad Crypto SRP_check_known_gN_param() failed.\n");

	BIGNUM *salt = NULL;
	BIGNUM *verifier = NULL;

	SRP_create_verifier_BN("user", pwd_str, &salt, &verifier, gN->N, gN->g);

	p->id = "user";
    p->g = gN->g;
    p->N = gN->N;
    p->s = salt;
    p->v = verifier;
    p->info = NULL;

    sk_SRP_user_pwd_push(gs->srpData->users_pwd, p);
}


static void
gs_ssl_ctx_init(GS *gs, int is_server)
{
	int ret;

	if (gs->ssl_ctx != NULL)
	{
		DEBUGF("SHOULD NOT HAPPEN\n");
		return;	/* Already got a SSL CTX */
	}

	SSL_CTX *ctx = NULL;

	ctx = SSL_CTX_new(SSLv23_method());
	XASSERT(ctx != NULL, "SSL_CTX_new() failed.\n");

	long options = 0;
	options |= SSL_OP_NO_SSLv2;
	options |= SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;
	options |= SSL_OP_NO_TICKET;
	options |= SSL_OP_CIPHER_SERVER_PREFERENCE;
	options |= SSL_OP_SINGLE_DH_USE; 
	SSL_CTX_set_options(ctx, options);

	ret = SSL_CTX_set_cipher_list(ctx, GS_DFL_CIPHER);
	XASSERT(ret == 1, "SSL_CTX_set_cipher_list()\n");

#if 1
	/* AUTO_RETRY for blocking SRP is easier */
	long mode;
	mode = SSL_CTX_get_mode(ctx);
	mode |= SSL_MODE_AUTO_RETRY;	/* Let OpenSSL handle all writes internally */
	SSL_CTX_set_mode(ctx, mode);
#endif

	if (is_server)
	{
		DEBUGF("...SRP SERVER...\n");
		/* SERVER */
		SSL_CTX_set_srp_username_callback(ctx, srp_username_cb);
		gs_srp_setpassword(gs, gs->srp_sec);
		/* The user's SRP password is set per SSL_CTX. This means
		 * we need a new SSL_CTX for every GS connection :/
		 * The only time we re-use a CTX is when gsocket 
		 * is in server mode and using SSL_accept() from
		 * multiple TCP connections and all using the same
		 * Global Socket address.
		 */
		ret = SSL_CTX_set_srp_cb_arg(ctx, gs->srpData);
		XASSERT(ret == 1, "SSL_CTX_set_srp_cb_arg()\n");


	} else {
		DEBUGF("...SRP CLIENT...\n");
		/* CLIENT */
		SSL_CTX_set_srp_username(ctx, "user");
		SSL_CTX_set_srp_cb_arg(ctx, gs);
		SSL_CTX_set_srp_client_pwd_callback(ctx, srp_client_pwd_cb);
	}

	gs->ssl_ctx = ctx;
}


static void
gs_ssl_init(GS *gsocket)
{
	SSL *ssl = gsocket->ssl;

	if (ssl != NULL)
		return;

	ssl = SSL_new(gsocket->ssl_ctx);
	gsocket->ssl = ssl;
}

const char *
GS_SSL_strerror(int err)
{
	switch (err)
	{
		case SSL_ERROR_NONE:
			return D_GRE("None");
		case SSL_ERROR_ZERO_RETURN:
			return "ZERO_RETURN (close-notify recv)";
		case SSL_ERROR_WANT_READ:
			return D_YEL("WANT_READ");
		case SSL_ERROR_WANT_WRITE:
			return D_YEL("WANT_WRITE");
		case SSL_ERROR_WANT_CONNECT:
			return "WANT CONNECT";
		case SSL_ERROR_WANT_ACCEPT:
			return "WANT ACCEPT";
		case SSL_ERROR_WANT_X509_LOOKUP:
			return "WANT X509 LOOKUP";
#ifdef SSL_ERROR_WANT_ASYNC
		case SSL_ERROR_WANT_ASYNC:
			return "WANT_ASYNC";
#endif
		case SSL_ERROR_SYSCALL:
			return D_RED("SYSCALL");
		case SSL_ERROR_SSL:
			return D_RED("FATAL ERROR");
	}
	return "unknown :/";
}


/*
 * Determine if a call to SSL_* triggered WANT-READ or WANT-WRITE
 * for the underlying I/O. WANT-READ does not mean that
 * SSL_read() needs to be called but rather that the underlying
 * tcp_fd needs to be ready for reading and that the original
 * SSL_* function needs to be called - which could have been
 * SSL_write() - Yes, SSL_write() might return WANT-READ
 * and SSL_write() needs to be called again once the underlying
 * socket has data ready for reading.
 * 
 * Return 0 on success.
 * Return -1 on fatal error.
 */
int
gs_ssl_want_io_rw(GS_SELECT_CTX *ctx, int fd, int err)
{
	if (ctx == NULL)
		return GS_ERR_FATAL;

	char *ptr = NULL;
#ifdef DEBUG
	char buf[128];
	ptr = buf;
	snprintf(buf, sizeof buf, "I/O SSL_%s", GS_SSL_strerror(err));
#endif
	gs_select_rw_save_state(ctx, fd, ptr);

	if (err == SSL_ERROR_WANT_READ)
	{
		XFD_SET(fd, ctx->rfd);
		ctx->want_io_read[fd] = 1;
		return 0;
	}
	if (err == SSL_ERROR_WANT_WRITE)
	{
		XFD_SET(fd, ctx->wfd);
		ctx->want_io_write[fd] = 1;
		DEBUGF_B("ctx->want_io_write[fd=%d] := %d\n", fd, ctx->want_io_write[fd]);
		return 0;
	}

	return GS_ERR_FATAL;
}

void
gs_ssl_want_io_finished(GS *gs)
{
	// DEBUGF_B("want_io_finished fd = %d\n", gs->fd);
	/* Return if we do not track WANT-READ/WANT-WRITE */
	if (gs->ctx->gselect_ctx == NULL)
		return;

	gs->ctx->gselect_ctx->want_io_read[gs->fd] = 0;
	gs->ctx->gselect_ctx->want_io_write[gs->fd] = 0;
	gs_select_rw_restore_state(gs->ctx->gselect_ctx, gs->fd, "X");
}

/*
 * See GS_shutdown() for return values.
 */
int
gs_ssl_shutdown(GS *gsocket)
{
	int ret;
	int err;

	gsocket->ssl_shutdown_count++;

	DEBUGF_Y("%d. call to gs_ssl_shutdown\n", gsocket->ssl_shutdown_count);
	if (gsocket->ssl == NULL)
	{
		DEBUGF_Y("*** WARNING ****: ssl == NULL\n");
		return GS_ERR_FATAL;
	}

	/* SSL_shutdown() only closes the write direction. It is not possible
	 * to call SSL_write() after calling SSL_shutdown. The read directio is
	 * closed by the peer.
	 */
	ret = SSL_shutdown(gsocket->ssl);
	DEBUGF_Y("SSL_shutdown() = %d (%s)\n", ret, ret==1?"COMPLETE":"waiting (stopped writing)");
	/* 1 == SUCCESS (close notify received)
	 * 0 == Close-sent (check SSL_read() for EOF).
	 *      Do not send any further data (but still receive data)
	 */
	gsocket->is_sent_shutdown = 1;
	if (ret == 1)
	{
		/* SUCCESS (close notify received & sent) */
		return GS_ERR_FATAL;	/* SUCCESSFULL Shutdown. Ready to destroy connection now */
	}
	if (ret == 0)
	{
		gsocket->is_want_shutdown = 0;
		/* HERE: Expecting more data (check SSL_read() */
		// gsocket->ssl_wait_for_eof = 1;
		return GS_SUCCESS;		/* Connection open for reading only */
	}

	err = SSL_get_error(gsocket->ssl, ret);
	DEBUGF_Y("SSL Error: %d\n", err);

	ret = gs_ssl_want_io_rw(gsocket->ctx->gselect_ctx, gsocket->fd, err);
	if (ret != 0)
		return GS_ERR_FATAL;

	gsocket->ctx->gselect_ctx->blocking_func[gsocket->fd] |= GS_CALLWRITE;
	gsocket->write_pending = 1;
	gsocket->is_want_shutdown = 1;

	return GS_ERR_WAITING;	/* Waiting for I/O */ 
}

static int
ssl_accept(GS *gsocket)
{
	int ret;

	ret = SSL_accept(gsocket->ssl);
	DEBUGF("Call to SSL_accept() = %d\n", ret);
	if (ret != 1)
	{
		gsocket->ssl_state = GS_SSL_STATE_ACCEPT;
		return ret;
	}

	/* Check that is is a SRP connection (not x509) */
	char *user = SSL_get_srp_username(gsocket->ssl);
	if (user == NULL)
		return -31337;

	/* HERE: SSL SRP accepted and valid */
	gsocket->ssl_state = GS_SSL_STATE_RW;

	return 1;	/* SUCCESS */
}

static int
ssl_connect(GS *gsocket)
{
	int ret;

	ret = SSL_connect(gsocket->ssl);
	DEBUGF("SSL_connect() = %d\n", ret);
	if (ret != 1)
	{
		gsocket->ssl_state = GS_SSL_STATE_CONNECT;
		return ret;
	}

	gsocket->ssl_state = GS_SSL_STATE_RW;

	return 1;	/* SUCCESS */
}

static int
ssl_shutdown(GS *gs)
{
	int ret;

	ret = SSL_shutdown(gs->ssl);
	DEBUGF_Y("SSL_shutdown() = %d\n", ret);
	/* 0 = Not yet finished. (do not call SSL_get_error())
	 * 1 = complete
	 * <0 = would-block (WANT-WRITE or WANT-READ)
	 */
	if (ret < 0)
		return ret; // WANT-WRITE or WANT-READ

	gs->is_sent_shutdown = 1;

	return 1;
}

static const char *
ssl_state_str(enum ssl_state_t state)
{
	switch (state)
	{
		case GS_SSL_STATE_ACCEPT:
			return "accept";
		case GS_SSL_STATE_CONNECT:
			return "connect";
		case GS_SSL_STATE_RW:
			return "read/write";
		case GS_SSL_STATE_SHUTDOWN:
			return "shutdown";
	}
	return "UNKNOWN";
}

/*
 * Continue an interrupted state (SSL_accpet/SSL_connect)
 *
 * Return 0 when done (state recovered).
 * Return -1 on fatal error.
 * Return 1 if unknown state (and SSL_read() or SSL_write() should handle it.
 */
int
gs_ssl_continue(GS *gsocket, enum gs_rw_state_t rw_state)
{
	int ret;
	int state = gsocket->ssl_state;

	/* FIXME: This check could be done in the calling function for speedup */
	// DEBUGF("ssl-state=%d, rw_state=%d\n", state, rw_state);
	if (rw_state == GS_CAN_WRITE)
	{
		// write wont block.
		if (gsocket->is_want_shutdown == 0)
		{
			// Not a SSL_shutdown()
			if ((state != GS_SSL_STATE_ACCEPT) && (state != GS_SSL_STATE_CONNECT) && (state != GS_SSL_STATE_SHUTDOWN))
			{
				// DEBUGF("ssl_continue: nothing to continue\n");
				return 1; // nothing to do
			}
		}
	} else {
		if ((state != GS_SSL_STATE_ACCEPT) && (state != GS_SSL_STATE_CONNECT) && (state != GS_SSL_STATE_SHUTDOWN))
			return 1;
	}

	/* SSL Handshake not yet complete. Complete it. */
	if (state == GS_SSL_STATE_ACCEPT)
	{
		ret = ssl_accept(gsocket);
	} else if (state == GS_SSL_STATE_CONNECT) {	/* GS_SSL_STATE_CONNECT */
		ret = ssl_connect(gsocket);
	} else {
		ret = ssl_shutdown(gsocket);
		gsocket->is_want_shutdown = 0;
	}
	if (ret == 1)
	{
		DEBUGF_G("*** SUCCESS *** [SSL_%s()]\n", ssl_state_str(state));
		gs_ssl_want_io_finished(gsocket);
		if ((gsocket->is_want_shutdown != 0) && (state != GS_SSL_STATE_SHUTDOWN))
		{
			DEBUGF_Y("SHUTDOWN was requested earlier. Doing it now.\n");
			GS_shutdown(gsocket);
		}
		/* SSL_accept()/SSL_connect() has finished. Drop into SSL_read()/SSL_write */
		return 0;
	}

	/* From ssl_accept() if user was not found.
	 * No need to check SSL_get_error.
	 * This is fatal.
	 */
	if (ret == -31337)
		return GS_ERR_FATAL;

	/* SSL_connect()/SSL_accept() can return 1 on SUCCESS or <0 if WOULD-BLOCK */
	/* A return value of 0 however means that the SSL was shut-down gracefully */
	int err = SSL_get_error(gsocket->ssl, ret);
	DEBUGF("SSL_ERROR SSL_%s() = SSL_%s(ret=%d, err=%d)\n", ssl_state_str(state), GS_SSL_strerror(err), ret, err);
	if (ERR_peek_last_error())
		DEBUGF_Y(" %s\n", ERR_error_string(ERR_peek_last_error(), NULL));
	if ((err != SSL_ERROR_WANT_READ) && (err != SSL_ERROR_WANT_WRITE))
		gs_set_errorf(gsocket, "SSL_%s: %s", ssl_state_str(state), GS_SSL_strerror(err));

	ret = gs_ssl_want_io_rw(gsocket->ctx->gselect_ctx, gsocket->fd, err);
	DEBUGF("gs_ssl_continue will return = %d (%s)\n", ret, ret<0?"FATAL":"continue");

	if (ret != 0)
		return GS_ERR_FATAL;	/* Return a fatal error if SSL was shut-down */

	return ret;
}

/*
 * Initialize SSL Library if it hasnt been done so already.
 * Create SSL_CTX on GS_CTX if it hasnt been done so already.
 * Create SSL on GS if it hasnt been done so already.
 *
 * This is called at the start of GS_listen() or GS_connect().
 *
 * Return 0 on success.
 * Return 1 if SSL_read/SSL_write is next
 * Return -1 on fata error
 *
 */
int
gs_srp_init(GS *gsocket)
{
	gs_ssl_ctx_init(gsocket, gsocket->flags & GS_FL_IS_SERVER?1:0);
	gs_ssl_init(gsocket);	/* Call to SSL_new() */
	DEBUGF("AFTER SSL init\n");

	if (gsocket->fd < 0)
		ERREXIT("can not happen, fd = %d\n", gsocket->fd);
	SSL_set_fd(gsocket->ssl, gsocket->fd);
	/* SRP client starts the handshake */
	gsocket->ssl_state = GS_SSL_STATE_CONNECT;
	if (gsocket->flags & GS_FL_IS_SERVER)
	{
		DEBUGF("This is SSL-SERVER (call SSL_accept()\n");
		gsocket->ssl_state = GS_SSL_STATE_ACCEPT;
	}
	int ret;
	ret = gs_ssl_continue(gsocket, GS_CAN_RW);
	DEBUGF("gs_srp_init() will return %d\n", ret);

	return ret;
}

void
GS_srp_setpassword(GS *gsocket, const char *pwd)
{
	snprintf(gsocket->srp_sec, sizeof gsocket->srp_sec, "%s.%s.%s", "Blah", pwd, "blubb-SRPSEC");
	DEBUGF("'%s'\n", gsocket->srp_sec);
}

const char *
GS_get_cipher(GS *gs)
{
	if (gs->flags & GSC_FL_USE_SRP)
		return GS_DFL_CIPHER"-End2End";

	return "NO ENCRYPTION";
}

int
GS_get_cipher_strength(GS *gs)
{
	if (gs->flags & GSC_FL_USE_SRP)
		return atoi(GS_DFL_CIPHER_STRENGTH);

	return 0;
}

#endif /* HAVE_LIBCRYPTO */

