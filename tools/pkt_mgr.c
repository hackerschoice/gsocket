#include "common.h"
#include "pkt_mgr.h"
#include "console.h"
#include "utils.h"
#include "gs-netcat.h"

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
	sanitize_fname_to_str(buf, sizeof buf - 1);

	CONSOLE_update_pinginfo(p, ms, ntohs(pong.load), (char *)buf, ntohs(pong.idle));

	DEBUGF_C("PONG received (% 6.03fms) (load % 4.02f, idle %u)\n", ms, (float)ntohs(pong.load) / 100, ntohs(pong.idle));
	gopt.ts_ping_sent = 0;
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
	return write_gs(ctx, p);
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

	pong.load = htons(l);
	pong.idle = htons(13);
	for (int i = 0; i < sizeof pong.user; i++)
		pong.user[i] = '0'+i%10;

	// snprintf(ong.user, sizeof pong.user, "roottoor3");

	memcpy(p->wbuf + 2, &pong, sizeof pong);

	p->wlen = 2 + GS_PKT_MSG_size_by_type(PKT_MSG_PONG);
	return write_gs(ctx, p);
}

int
pkt_app_send_ping(GS_SELECT_CTX *ctx, struct _peer *p)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	gopt.ts_ping_sent = GS_TV_TO_USEC(&tv);
	p->wbuf[0] = GS_PKT_ESC;
	p->wbuf[1] = PKT_MSG_PING;
	p->wlen = 2 + GS_PKT_MSG_size_by_type(PKT_MSG_PING);
	return write_gs(ctx, p);
}


