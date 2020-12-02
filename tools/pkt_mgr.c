#include "common.h"
#include "pkt_mgr.h"
#include "event_mgr.h"
#include "console.h"
#include "console_display.h"
#include "utils.h"
#include "gs-netcat.h"

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

	DEBUGF_C("PING received\n");
	gopt.is_pong_pending = 1;
	GS_SELECT_FD_SET_W(p->gs);
}

/* CLIENT - Answer to PING received */
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
	sanitize_fname_to_str(buf, sizeof buf);

	CONSOLE_update_pinginfo(p, ms, ntohs(pong.load), (char *)buf, ntohs(pong.idle));

	// DEBUGF_C("PONG received (% 6.03fms) (load % 4.02f, idle %u)\n", ms, (float)ntohs(pong.load) / 100, ntohs(pong.idle));
	gopt.ts_ping_sent = 0;
}

void
pkt_app_cb_log(uint8_t msg, const uint8_t *data, size_t len, void *ptr)
{
	// struct _peer *p = (struct _peer *)ptr;
	struct _pkt_app_log *log = (struct _pkt_app_log *)data;

	sanitize_fname_to_str(log->msg, sizeof log->msg);
	GS_condis_log(&gs_condis, log->type, (const char *)log->msg);

	DEBUGF_G("LOG (%d) '%s'\n", log->type, log->msg);
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
	if (gopt.ids_active_user != NULL)
		snprintf((char *)pong.user, sizeof pong.user, "%s", gopt.ids_active_user);
	// for (int i = 0; i < sizeof pong.user; i++)
		// pong.user[i] = '0'+i%10;

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

		free(li->data);
		GS_LIST_del(li);
	
		if (ret != GS_SUCCESS)
		{
			p->is_pending_logs = 1;
			return ret; // WOULDBLOCK
		}
	}

	return GS_SUCCESS;
}

