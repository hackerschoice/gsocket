/*
 * Filetransfer Manager - Initialize callbacks for filetransfer.h
 *
 * Used by gs-netcat and put/get file transfer
 */

#include "common.h"
#include "filetransfer.h"
#include "filetransfer_mgr.h"
#include "pkt_mgr.h"
#include "console.h"
#include "console_display.h"

extern GS_CONDIS gs_condis;  // defined in console.c


// SERVER receiving PUT from client
static void
pkt_cb_put(uint8_t chn, const uint8_t *data, size_t len, void *arg)
{
	struct _gs_ft_put *p = (struct _gs_ft_put *)data;
	struct _gs_ft_put hdr;
	struct _peer *peer = (struct _peer *)arg;
	GS_FT *ft = &peer->ft;

	if (len < sizeof hdr + 1)
		return;  // protocol error

	memcpy(&hdr, data, sizeof hdr);
	GS_FT_add_file(ft, ntohl(hdr.id), (char *)p->name, len - sizeof hdr - 1, ntohll(hdr.fsize), ntohl(hdr.mtime), ntohl(hdr.fperm), hdr.flags);	
	if (GS_FT_WANT_WRITE(ft))
		GS_SELECT_FD_SET_W(peer->gs);
}

// SERVER receiving DL from client
static void
pkt_cb_dl(uint8_t chn, const uint8_t *data, size_t len, void *arg)
{
	struct _gs_ft_dl *d = (struct _gs_ft_dl *)data;
	struct _gs_ft_dl hdr;
	struct _peer *peer = (struct _peer *)arg;
	GS_FT *ft = &peer->ft;

	if (len < sizeof hdr + 1)
		return;  // protocol error

	memcpy(&hdr, data, sizeof hdr);
	GS_FT_dl_add_file(ft, ntohl(hdr.id), (char *)d->name, len - sizeof hdr - 1, ntohll(hdr.offset));
	if (GS_FT_WANT_WRITE(ft))
		GS_SELECT_FD_SET_W(peer->gs);
}


// SERVER receiving a LIST request from client
static void
pkt_cb_listrequest(uint8_t chn, const uint8_t *data, size_t len, void *arg)
{
	DEBUGF_B("LIST-REQUEST received!\n");
	struct _gs_ft_list_request *lr = (struct _gs_ft_list_request *)data;
	struct _gs_ft_list_request hdr;
	struct _peer *peer = (struct _peer *)arg;
	GS_FT *ft = &peer->ft;
	
	if (len < sizeof hdr + 1)
		return; // protocol error

	memcpy(&hdr, data, sizeof hdr);
	GS_FT_list_add_files(ft, ntohl(hdr.globbing_id), (char *)lr->pattern, len - sizeof hdr - 1);
	if (GS_FT_WANT_WRITE(ft))
		GS_SELECT_FD_SET_W(peer->gs);
}

// CLIENT receiving answer to LIST request
static void
pkt_cb_listreply(uint8_t chn, const uint8_t *data, size_t len, void *arg)
{
	// DEBUGF_B("LIST-REPLY received\n");
	struct _gs_ft_list_reply *lr = (struct _gs_ft_list_reply *)data;
	struct _gs_ft_list_reply hdr;
	struct _peer *peer = (struct _peer *)arg;
	GS_FT *ft = &peer->ft;

	if (len < sizeof hdr + 1)
		return;

	memcpy(&hdr, data, sizeof hdr);
	GS_FT_list_add(ft, ntohl(hdr.globbing_id), (char *)lr->name, len - sizeof hdr - 1, ntohll(hdr.fsize), ntohl(hdr.mtime), ntohl(hdr.fperm), hdr.flags);
	if (GS_FT_WANT_WRITE(ft))
		GS_SELECT_FD_SET_W(peer->gs);
}

static void
pkt_cb_switch(uint8_t chn, const uint8_t *data, size_t len, void *arg)
{
	struct _gs_ft_switch hdr;
	struct _peer *peer = (struct _peer *)arg;
	GS_FT *ft = &peer->ft;

	if (len < sizeof hdr)
		return; // protocol error

	memcpy(&hdr, data, sizeof hdr);
	GS_FT_switch(ft, ntohl(hdr.id), ntohll(hdr.offset));
	if (GS_FT_WANT_WRITE(ft))
		GS_SELECT_FD_SET_W(peer->gs);
}

/* SERVER receiving DATA from client */
static void
pkt_cb_data(uint8_t chn, const uint8_t *data, size_t len, void *arg)
{
	struct _peer *peer = (struct _peer *)arg;
	GS_FT *ft = &peer->ft;

	// DEBUGF("Data chn %d, len %zu\n", chn, len);
	GS_FT_data(ft, data, len);
	if (GS_FT_WANT_WRITE(ft))
		GS_SELECT_FD_SET_W(peer->gs);
}

/* PUT, CLIENT receiving ACCEPT from server */
static void
pkt_cb_accept(uint8_t chn, const uint8_t *data, size_t len, void *arg)
{
	struct _gs_ft_accept hdr;
	struct _peer *peer = (struct _peer *)arg;
	GS_FT *ft = &peer->ft;

	if (len < sizeof hdr)
		return; // protocol error

	memcpy(&hdr, data, sizeof hdr);
	GS_FT_accept(ft, ntohl(hdr.id), ntohll(hdr.offset_dst));
	if (GS_FT_WANT_WRITE(ft))
		GS_SELECT_FD_SET_W(peer->gs);
}

// Client & Server
static void
pkt_cb_error(uint8_t chn, const uint8_t *data, size_t len, void *arg)
{
	struct _gs_ft_error *p = (struct _gs_ft_error *)data;
	struct _gs_ft_error hdr;
	struct _peer *peer = (struct _peer *)arg;
	GS_FT *ft = &peer->ft;

	if (len < sizeof hdr + 1)
		return; // protocol error

	memcpy(&hdr, data, sizeof hdr);
	GS_FT_status(ft, ntohl(hdr.id), hdr.code, (char *)p->str, len - sizeof hdr - 1);
	if (GS_FT_WANT_WRITE(ft))
	{
		// GS_FT-stack wants caller to call GS_FT_packet(). The only way we can
		// trigger this is to set FD_SET_W() and we know that after select()
		// we call GS_FT_packet()...
		GS_SELECT_FD_SET_W(peer->gs);
	}
}

// Output total stats
static void
print_stats_ft(GS_FT_stats *st)
{
	DEBUGF_Y("Speed  : %s\n", st->speed_str);
	DEBUGF_Y("Amount : %"PRIu64"/%"PRIu64"usec\n", st->xfer_amount, st->xfer_duration);
	DEBUGF_Y("Success: %d\n", st->n_files_success);
	DEBUGF_Y("Errors : %d\n", st->n_files_error);
}

// On file transfer completion (for each file)
static void
cb_stats(struct _gs_ft_stats_file *s, void *arg)
{
	struct _peer *p = (struct _peer *)arg;

	DEBUGF_C("%u stats: %s\n", s->id, s->fname);
	DEBUGF_C("Speed: %s\n", s->speed_str);
	print_stats_ft(&p->ft.stats);

	char buf[256];
	snprintf(buf, sizeof buf, "[%s] %s", s->speed_str, s->fname);
	GS_condis_log(&gs_condis, GS_PKT_APP_LOG_TYPE_DEFAULT, buf);
	CONSOLE_draw(gs_condis.fd);
}

// Status and Error messages
static void
cb_errors(void *ft_ptr, struct _gs_ft_status *s, void *arg)
{
	// struct _peer *p = (struct _peer *)arg;

	DEBUGF_M("Code  : %u\n", s->code);
	DEBUGF_M("Error : '%s'\n", s->err_str);
	DEBUGF_M("File  : %s\n", s->fname);

	// COMPLETE messages are not displayed as errors.
	if (s->code == GS_FT_ERR_COMPLETED)
		return;

	// char buf[256];
	// snprintf(buf, sizeof buf, "(%u)%s", s->code, s->err_str);
	GS_condis_log(&gs_condis, GS_PKT_APP_LOG_TYPE_NOTICE, s->err_str);
	CONSOLE_draw(gs_condis.fd);
}

// Return length of packet created.
// Return 0 on if not packet available.
// Return -1 if all files have been transferred (client only. Server never stops
// as server is always waiting for instructions by client to get/put more files).
// Return -2 if not enough space.
ssize_t
GS_FTM_mk_packet(GS_FT *ft, uint8_t *dst, size_t dlen)
{
	struct gs_pkt_chn_hdr *hdr = (struct gs_pkt_chn_hdr *)dst;
	int pkt_type;
	size_t max_len;
	char buf[256];
	GS_FT_stats *st = &ft->stats;

	if (dlen <= sizeof *hdr)
		return -2; // Insuficient space.

	max_len = MIN(GS_PKT_MAX_SIZE, dlen - sizeof *hdr);

	ssize_t sz;
	sz = GS_FT_packet(ft, dst + sizeof *hdr, max_len, &pkt_type);

	switch (pkt_type)
	{
	case GS_FT_TYPE_NONE:
		// Nothing to write...waiting for peer's reply.
		// DEBUGF_G("TYPE NONE\n");
		return 0;
	case GS_FT_TYPE_DONE:
		// DEBUGF_W("GS_FT_TYPE_DONE\n");
		// CLIENT only: done with all files.
		// FIXME: for a 'get' request this is triggered very late and not as soon
		// as the filetransfer is done (because select() only waits for reading
		// and while there is no data to write then GS_FTM_mk_packet is only called after
		// select() returns after 1sec idle.
		if (st->n_files_success + st->n_files_error >= 2) // Summary for Multi-file transfers only
		{
			// FIXME: turn /sec into h/min/sec etc (e.g. 99999.8h or 99.4 minutes or 99.5 sec or 0.102 sec)
			if (st->n_files_success > 0)
			{
				float ms = (float)st->xfer_duration / 1000;
				snprintf(buf, sizeof buf, "OK: %d/%d [%s] (%"PRIu64"/%1.03fsec)", st->n_files_success, st->n_files_success + st->n_files_error, st->speed_str, st->xfer_amount, ms / 1000);
				GS_condis_log(&gs_condis, GS_PKT_APP_LOG_TYPE_INFO, buf);
			}
			if (st->n_files_error > 0)
			{
				snprintf(buf, sizeof buf, "FAILED: %d", st->n_files_error);
				GS_condis_log(&gs_condis, GS_PKT_APP_LOG_TYPE_ALERT, buf);
			}
		}
		if (st->n_files_success + st->n_files_error > 0)
			GS_FT_stats_reset(ft);

		CONSOLE_draw(gs_condis.fd);
		// DEBUGF_G("All done (%d/%d)\n", st->n_files_success, st->n_files_error);
		return -1;
	case GS_FT_TYPE_PUT:
		hdr->type = GS_PKT_CHN2TYPE(GS_FT_CHN_PUT);
		break;
	case GS_FT_TYPE_ERROR:
		hdr->type = GS_PKT_CHN2TYPE(GS_FT_CHN_ERROR);
		break;
	case GS_FT_TYPE_SWITCH:
		hdr->type = GS_PKT_CHN2TYPE(GS_FT_CHN_SWITCH);
		break;
	case GS_FT_TYPE_ACCEPT:
		hdr->type = GS_PKT_CHN2TYPE(GS_FT_CHN_ACCEPT);
		break;
	case GS_FT_TYPE_DATA:
		hdr->type = GS_PKT_CHN2TYPE(GS_FT_CHN_DATA);
		break;
	case GS_FT_TYPE_LISTREQUEST:
		// GET (download), CLIENT
		hdr->type = GS_PKT_CHN2TYPE(GS_FT_CHN_LIST_REQUEST);
		break;
	case GS_FT_TYPE_LISTREPLY:
		// SERVER (reply to 'get' (list request))
		hdr->type = GS_PKT_CHN2TYPE(GS_FT_CHN_LIST_REPLY);
		break;
	case GS_FT_TYPE_DL:
		// CLIENT - download by filename
		hdr->type = GS_PKT_CHN2TYPE(GS_FT_CHN_DL);
		break;
	default:
		ERREXIT("unknown type %d\n", pkt_type);
	}

	hdr->esc = GS_PKT_ESC;
	uint16_t len = htons(sz);
	memcpy(&hdr->len, &len, sizeof len);

	return sz + sizeof *hdr;
}

void
GS_FTM_init(struct _peer *p, int is_server)
{
	GS_PKT_assign_chn(&p->pkt, GS_FT_CHN_ERROR, pkt_cb_error, p);
	if (is_server == 0)
	{
		// CLIENT
		GS_FT_init(&p->ft, cb_stats, cb_errors, 0 /*pid, unused*/, p, 0);

		// PUT (upload)
		GS_PKT_assign_chn(&p->pkt, GS_FT_CHN_ACCEPT, pkt_cb_accept, p);

		// GET (download)
		GS_PKT_assign_chn(&p->pkt, GS_FT_CHN_LIST_REPLY, pkt_cb_listreply, p);
		GS_PKT_assign_chn(&p->pkt, GS_FT_CHN_DATA, pkt_cb_data, p);
		GS_PKT_assign_chn(&p->pkt, GS_FT_CHN_SWITCH, pkt_cb_switch, p);
	} else {
		// SERVER
		GS_FT_init(&p->ft, NULL, cb_errors, p->pid, p, 1);

		// PUT (upload)
		GS_PKT_assign_chn(&p->pkt, GS_FT_CHN_PUT, pkt_cb_put, p);
		GS_PKT_assign_chn(&p->pkt, GS_FT_CHN_DATA, pkt_cb_data, p);
		GS_PKT_assign_chn(&p->pkt, GS_FT_CHN_SWITCH, pkt_cb_switch, p);

		// GET (download)
		GS_PKT_assign_chn(&p->pkt, GS_FT_CHN_LIST_REQUEST, pkt_cb_listrequest, p);
		GS_PKT_assign_chn(&p->pkt, GS_FT_CHN_DL, pkt_cb_dl, p);
	}
}

void
GS_FTM_free(struct _peer *p)
{
	GS_FT_free(&p->ft);
}



