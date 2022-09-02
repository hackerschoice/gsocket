#include "common.h"
#include "pkt_mgr.h"
#include "event_mgr.h"
#include "console.h"
#include "console_display.h"
#include "utils.h"
#include "gs-netcat.h"
#include "filetransfer_mgr.h"

extern GS_CONDIS gs_condis;  // defined in console.c

/* SERVER - client changed window size. Adjust pty. */
void
pkt_app_cb_wsize(uint8_t msg, const uint8_t *data, size_t len, void *ptr)
{
	struct _peer *p = (struct _peer *)ptr;

	uint16_t col, row;

	memcpy(&col, data, 2);
	memcpy(&row, data + 2, 2);

	col = ntohs(col);
	row = ntohs(row);
	DEBUGF_W("cols = %u, rows = %u\n", col, row);

	int ret;
	struct winsize ws;
	ret = ioctl(p->fd_in, TIOCGWINSZ, &ws);
	if (ret != 0)
		DEBUGF_R("ioctrl() %s\n", strerror(errno));
	ws.ws_col = col;
	ws.ws_row = row;
	ret = ioctl(p->fd_in, TIOCSWINSZ, &ws);
	if (ret != 0)
		DEBUGF_R("ioctl()-2 %s\n", strerror(errno));
}

/* SERVER - answer to PING request on channel */
void
pkt_app_cb_ping(uint8_t msg, const uint8_t *data, size_t len, void *ptr)
{
	struct _peer *p = (struct _peer *)ptr;

	DEBUGF_C("APP-PING received\n");
	gopt.is_pong_pending = 1;
	GS_SELECT_FD_SET_W(p->gs);
}

/* CLIENT - Received PONG */
void
pkt_app_cb_pong(uint8_t msg, const uint8_t *data, size_t len, void *ptr)
{
	struct _peer *p = (struct _peer *)ptr;
	struct _pkt_app_pong pong;
	// Check if we were waiting at all!
	if (gopt.ts_ping_sent == 0)
		return;

	memcpy(&pong, data, sizeof pong);

	float ms = (float)(GS_TV_TO_USEC(&gopt.tv_now) - gopt.ts_ping_sent) / 1000;

	uint8_t buf[sizeof (pong.user) + 1];
	memcpy(buf, pong.user, sizeof pong.user);
	GS_sanitize_fname_str((char *)buf, sizeof buf);

	CONSOLE_update_pinginfo(p, ms, ntohs(pong.load), (char *)buf, ntohs(pong.idle), pong.n_users);

	// DEBUGF_C("PONG received (% 6.03fms) (load % 4.02f, idle %u)\n", ms, (float)ntohs(pong.load) / 100, ntohs(pong.idle));
	gopt.ts_ping_sent = 0;
}

void
pkt_app_cb_log(uint8_t msg, const uint8_t *data, size_t len, void *ptr)
{
	// struct _peer *p = (struct _peer *)ptr;
	struct _pkt_app_log *log = (struct _pkt_app_log *)data;

	GS_sanitize_fname_str((char *)log->msg, sizeof log->msg);
	GS_condis_log(&gs_condis, log->type, (const char *)log->msg);
	CONSOLE_draw(gs_condis.fd);

	DEBUGF_G("LOG (%d) '%s'\n", log->type, log->msg);
}

void
pkt_app_cb_status(uint8_t msg, const uint8_t *data, size_t len, void *ptr)
{
	struct _pkt_app_status *status = (struct _pkt_app_status *)data;

	DEBUGF_Y("Received STATUS.type=%u\n", status->type);
	if (status->type == GS_PKT_APP_STATUS_TYPE_NOPTY)
	{
		stty_switch_nopty();
	}	
}

/* SERVER - Client is interested in IDS messages */
void
pkt_app_cb_ids(uint8_t msg, const uint8_t *data, size_t len, void *ptr)
{
	struct _peer *p = (struct _peer *)ptr;

	DEBUGF_R("Client is interested in IDS log messages\n");
	if (p->ids_li != NULL)
	{
		DEBUGF_R("Oops. client already receiving log messages\n");
		return;
	}
	p->ids_li = GS_LIST_add(&gopt.ids_peers, NULL, p, 0);
	if (gopt.event_ids == NULL)
	{
		gopt.event_ids = GS_EVENT_add_by_ts(&p->gs->ctx->gselect_ctx->emgr, NULL, 0, GS_APP_IDSFREQ, cbe_ids, NULL, 0);
		cbe_ids(NULL); // Immediately load utmp database
	}
}

// SERVER
void
pkt_app_cb_pwdrequest(uint8_t msg, const uint8_t *dataUNUSED, size_t lenUNUSED, void *ptr)
{
	struct _peer *p = (struct _peer *)ptr;

	gopt.is_pwdreply_pending = 1;
	GS_SELECT_FD_SET_W(p->gs);
}

// CLIENT
void
pkt_app_cb_pwdreply(uint8_t chn, const uint8_t *data, size_t len, void *ptr)
{
	if (len <= 0)
		return;

	if (data[len - 1] != '\0')
		return; // protocol error.
	
	DEBUGF_B("REMOTE WD=%s\n", data);
	GS_condis_add(&gs_condis, GS_PKT_APP_LOG_TYPE_DEFAULT, (char *)data);
	CONSOLE_draw(gs_condis.fd);
}

int
pkt_app_send_wsize(GS_SELECT_CTX *ctx, struct _peer *p, int row)
{
	p->wbuf[0] = GS_PKT_ESC;
	p->wbuf[1] = PKT_MSG_WSIZE;
	uint16_t c, r;
	c = htons(gopt.winsize.ws_col);
	r = htons(row);
	memcpy(p->wbuf + 2, &c, 2);
	memcpy(p->wbuf + 4, &r, 2);
	p->wlen = 2 + GS_PKT_MSG_size_by_type(PKT_MSG_WSIZE);
	return write_gs(ctx, p, NULL);
}

int
pkt_app_send_pong(GS_SELECT_CTX *ctx, struct _peer *p)
{
	double load;
	uint16_t l = 0;
	struct _pkt_app_pong pong;

	p->wbuf[0] = GS_PKT_ESC;
	p->wbuf[1] = PKT_MSG_PONG;

	// Get system load.
	if (getloadavg(&load, 1) == 1)
		l = (uint16_t)(load * 100);

	memset(&pong, 0, sizeof pong);
	pong.load = htons(l);
	pong.idle = htons(gopt.ids_idle);
	pong.n_users = MIN(255, gopt.n_users);
	if (gopt.ids_active_user != NULL)
		snprintf((char *)pong.user, sizeof pong.user, "%s", gopt.ids_active_user);

	memcpy(p->wbuf + 2, &pong, sizeof pong);

	p->wlen = 2 + GS_PKT_MSG_size_by_type(PKT_MSG_PONG);
	return write_gs(ctx, p, NULL);
}

int
pkt_app_send_ping(GS_SELECT_CTX *ctx, struct _peer *p)
{
	struct _pkt_app_ping ping;
	struct timeval tv;

	p->wbuf[0] = GS_PKT_ESC;
	p->wbuf[1] = PKT_MSG_PING;

	gettimeofday(&tv, NULL);
	gopt.ts_ping_sent = GS_TV_TO_USEC(&tv);

	memset(&ping, 0, sizeof ping);
	memcpy(p->wbuf + 2, &ping, sizeof ping);

	p->wlen = 2 + GS_PKT_MSG_size_by_type(PKT_MSG_PING);
	return write_gs(ctx, p, NULL);
}

int
pkt_app_send_ids(GS_SELECT_CTX *ctx, struct _peer *p)
{
	struct _pkt_app_ids ids;

	p->wbuf[0] = GS_PKT_ESC;
	p->wbuf[1] = PKT_MSG_IDS;

	memset(&ids, 0, sizeof ids);
	ids.flags = GS_PKT_APP_FL_IDS;  // Enable IDS

	memcpy(p->wbuf + 2, &ids, sizeof ids);
	p->wlen = 2 + GS_PKT_MSG_size_by_type(PKT_MSG_IDS);
	return write_gs(ctx, p, NULL);
}

int
pkt_app_send_pwdrequest(GS_SELECT_CTX *ctx, struct _peer *p)
{
	p->wbuf[0] = GS_PKT_ESC;
	p->wbuf[1] = PKT_MSG_PWD;
	p->wlen = 2 + GS_PKT_MSG_size_by_type(PKT_MSG_PWD);
	return write_gs(ctx, p, NULL);
}

int
pkt_app_send_pwdreply(GS_SELECT_CTX *ctx, struct _peer *p)
{
	struct gs_pkt_chn_hdr *hdr = (struct gs_pkt_chn_hdr *)p->wbuf;

	hdr->esc = GS_PKT_ESC;
	hdr->type = GS_PKT_CHN2TYPE(GS_CHN_PWD);

	char *wd = GS_getpidwd(p->pid);
	snprintf((char *)p->wbuf + sizeof *hdr, sizeof p->wbuf - sizeof *hdr, "%s", wd);
	size_t sz = strlen(wd) + 1; // including \0
	XFREE(wd);

	uint16_t len = htons(sz);
	memcpy(&hdr->len, &len, sizeof len);

	p->wlen = sizeof *hdr + sz;
	return write_gs(ctx, p, NULL);
}


// Loop until all FileTransfer data is written
// or the socket would block.
int
pkt_app_send_ft(GS_SELECT_CTX *ctx, struct _peer *p)
{
	ssize_t sz;
	int len;

	while (1)
	{
		sz = GS_FTM_mk_packet(&p->ft, p->wbuf, sizeof p->wbuf);
		if (sz == 0)
			return GS_SUCCESS;   // No data available.
		if (sz == -1)
			return GS_SUCCESS;   // All files have been transferred.
		if (sz < 0) // Catch All (-2 mostly/always)
			return GS_ERR_FATAL; // Not enough space.

		// Got data to write.
		p->wlen = sz;
		len = write_gs_atomic(ctx, p);
		if (len == -1)
			return GS_ECALLAGAIN;
		if (len != p->wlen)
			return GS_ERROR;
		p->wlen = 0; // SUCCESS.
		// Do a single write only. This function returns and enters the select() loop
		// again to check if there is any data on stdin. 
		// Otherwise the FileTransfer subsystem will keep sending data until write() would block
		// and then keep data in p->wbuf without the STDIN ever being checked for input until
		// the FileTransfer has completed. We like to check STDIN...
		// FIXME-PERFORMANCE: Could write() here until would-block but then do not
		// leave data in p->wbuf and instead use an internal buffer. This way select() is not
		// called for every write() from FileTransfer subsystem.
		return GS_SUCCESS;
	}

	return GS_SUCCESS; // NOT REACHED
}

static int
send_log(GS_SELECT_CTX *ctx, struct _peer *p, struct _pkt_app_log *log)
{
	int killed = 0;
	int ret;
	p->wbuf[0] = GS_PKT_ESC;
	p->wbuf[1] = PKT_MSG_LOG;

	XASSERT(GS_PKT_MSG_size_by_type(p->wbuf[1]) == sizeof *log, "Size does not fit\n");

	memcpy(p->wbuf + 2, log, sizeof *log);
	p->wlen = 2 + GS_PKT_MSG_size_by_type(p->wbuf[1]);

	ret = write_gs(ctx, p, &killed);
	if (killed)
		return GS_ERR_FATAL;

	return ret; // SUCCESS or WOUDLBLOCK
}

/*
 * Try to send all log files.
 */
int
pkt_app_send_all_log(GS_SELECT_CTX *ctx, struct _peer *p)
{
	GS_LIST_ITEM *li = NULL;
	int ret;

	// Stop being called recursively from within write_gs()
	p->is_pending_logs = 0;

	while (1)
	{
		li = GS_LIST_next(&p->logs, NULL);
		if (li == NULL)
			break;

		// FIXME-PERFORMANCE: Could add as much data to p->wbuf and then issue
		// a single write_gs() rather than a write_gs() for each log. WOuld
		// save on a bit of traffic and syscalls ...but then there are rarely any
		// logs send to peer anyway.....
		ret = send_log(ctx, p, li->data);
		if (ret == GS_ERR_FATAL)
			return GS_ERR_FATAL; // peer has been freed and destroyed.

		XFREE(li->data);
		GS_LIST_del(li);
	
		if (ret != GS_SUCCESS)
		{
			p->is_pending_logs = 1;
			return ret; // WOULDBLOCK
		}
	}

	return GS_SUCCESS;
}

int
pkt_app_send_status_nopty(GS_SELECT_CTX *ctx, struct _peer *p)
{
	struct _pkt_app_status status;

	p->wbuf[0] = GS_PKT_ESC;
	p->wbuf[1] = PKT_MSG_STATUS;

	memset(&status, 0, sizeof status);
	status.type = GS_PKT_APP_STATUS_TYPE_NOPTY;
	memcpy(p->wbuf + 2, &status, sizeof status);

	p->wlen = 2 + GS_PKT_MSG_size_by_type(PKT_MSG_STATUS);
	return write_gs(ctx, p, NULL);	
}
