/*
 * Test program to test gs filetransfer sub-system used by gs-netcat.
 *

mkdir -p test
rm -rf test/test*.dat
socat SYSTEM:'./filetransfer-test c test4k.dat test8k.dat 2>client.log' SYSTEM:'(cd test; ../filetransfer-test s 2>../server.log)'

 */

#include "common.h"
#include "filetransfer.h"
#include "utils.h"

#define BUF_LEN		(1024)

static GS_PKT pkt;
static GS_FT ft;
static int is_server;
static uint8_t wbuf[GS_PKT_MAX_SIZE];
static size_t wlen;

/* SERVER receiving PUT from client */
static void
pkt_cb_put(uint8_t chn, const uint8_t *data, size_t len, void *argNOTUSED)
{
	struct _gs_ft_put *p = (struct _gs_ft_put *)data;
	struct _gs_ft_put hdr;

	if (len < sizeof hdr + 1)
		return;  // protocol error

	memcpy(&hdr, data, sizeof hdr);
	GS_FT_add_file(&ft, ntohl(hdr.id), (char *)p->name, len - sizeof hdr - 1, ntohll(hdr.fsize), ntohl(hdr.mtime), ntohl(hdr.fperm));	
}

static void
pkt_cb_switch(uint8_t chn, const uint8_t *data, size_t len, void *argNOTUSED)
{
	struct _gs_ft_switch hdr;

	if (len < sizeof hdr)
		return; // protocol error

	memcpy(&hdr, data, sizeof hdr);
	GS_FT_switch(&ft, ntohl(hdr.id), /*ntohll(hdr.fsize), */ntohll(hdr.offset));
}

/* SERVER receiving DATA from client */
static void
pkt_cb_data(uint8_t chn, const uint8_t *data, size_t len, void *argNOTUSED)
{
	// DEBUGF("Data chn %d, len %zu\n", chn, len);
	GS_FT_data(&ft, data, len);
}

/* CLIENT receiving ACCEPT from server */
static void
pkt_cb_accept(uint8_t chn, const uint8_t *data, size_t len, void *argNOTUSED)
{
	struct _gs_ft_accept hdr;

	if (len < sizeof hdr)
		return; // protocol error

	memcpy(&hdr, data, sizeof hdr);
	GS_FT_accept(&ft, ntohl(hdr.id), ntohll(hdr.offset_dst));
}

// Client & Server
static void
pkt_cb_error(uint8_t chn, const uint8_t *data, size_t len, void *argNOTUSED)
{
	struct _gs_ft_error *p = (struct _gs_ft_error *)data;
	struct _gs_ft_error hdr;

	if (len < sizeof hdr + 1)
		return; // protocol error

	memcpy(&hdr, data, sizeof hdr);
	GS_FT_status(&ft, ntohl(hdr.id), hdr.code, (char *)p->str, len - sizeof hdr - 1);
}

// Output total stats
static void
stats_total(GS_FT_stats_total *st)
{
	DEBUGF_Y("Speed  : %s\n", st->speed_str);
	DEBUGF_Y("Amount : %"PRIu64"/%"PRIu64"usec\n", st->xfer_amount, st->xfer_duration);
	DEBUGF_Y("Success: %d\n", st->n_files_success);
	DEBUGF_Y("Errors : %d\n", st->n_files_error);
}

// On file transfer completion (for each file)
static void
cb_stats(struct _gs_ft_stats *s)
{
	DEBUGF_C("%u stats: %s\n", s->id, s->f->name);
	DEBUGF_C("Speed: %s\n", s->speed_str);

	stats_total(&ft.stats_total);
}

// Status and Error messages
static void
cb_status(void *ft_ptr, struct _gs_ft_status *s)
{
	DEBUGF_M("Status: %u\n", s->code);
	DEBUGF_M("error : '%s'\n", s->err_str);
	DEBUGF_M("File  : %s\n", s->file->name);
}

int
mk_packet(void)
{
	struct gs_pkt_chn_hdr *hdr = (struct gs_pkt_chn_hdr *)wbuf;
	int pkt_type;
	size_t sz;

	sz = GS_FT_packet(&ft, wbuf + sizeof *hdr, sizeof wbuf - sizeof *hdr, &pkt_type);
	XASSERT(sz <= sizeof wbuf - sizeof *hdr, "Oops, GS_FT_packet() to long. sz=%zu.\n", sz);

	// DEBUGF("sz %zu, type %d\n", sz, pkt_type);
	switch (pkt_type)
	{
	case GS_FT_TYPE_NONE:
		// Nothing to write...waiting for peer's reply.
		DEBUGF_G("TYPE NONE\n");
		return 0;
	case GS_FT_TYPE_PUT:
		hdr->type = GS_PKT_CHN2TYPE(GS_FT_CHN_PUT);
		// HEXDUMP(wbuf, sizeof *hdr + sz);
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
	case GS_FT_TYPE_DONE:
		// CLIENT only. Server always keeps listening.
		DEBUGF_G("All done.\n");
		return -1;
	default:
		ERREXIT("unknown type %d\n", pkt_type);
	}

	hdr->esc = GS_PKT_ESC;
	hdr->len = htons(sz);

	wlen = sizeof *hdr + sz;

	return 0;
}


int
main(int arc, char *argv[])
{
	int is_extra_puts = 0;
	uint8_t src[BUF_LEN];
	uint8_t dst[2 * sizeof src];
	ssize_t sz;
	size_t dsz;
	int ret;

	GS_library_init(stderr, stderr);
	gopt.err_fp = stderr;
	gopt.log_fp = stderr;

	GS_PKT_init(&pkt);

	GS_PKT_assign_chn(&pkt, GS_FT_CHN_ERROR, pkt_cb_error, NULL);
	if (*argv[1] == 'c')
	{
		GS_FT_init(&ft, cb_stats, cb_status);
		GS_PKT_assign_chn(&pkt, GS_FT_CHN_ACCEPT, pkt_cb_accept, NULL);
		// Add files to queue...
		char **ptr = &argv[2];
		while (*ptr != NULL)
		{
			if (GS_FT_put(&ft, *ptr) != 0)
				DEBUGF_Y("Not found: %s\n", *ptr);
			ptr++;
		}
	} else {
		GS_FT_init(&ft, NULL, cb_status);
		GS_PKT_assign_chn(&pkt, GS_FT_CHN_PUT, pkt_cb_put, NULL);
		GS_PKT_assign_chn(&pkt, GS_FT_CHN_DATA, pkt_cb_data, NULL);
		GS_PKT_assign_chn(&pkt, GS_FT_CHN_SWITCH, pkt_cb_switch, NULL);
		is_server = 1;
	}

	while (1)
	{
		// If there is data to write then write data first.
		if (wlen > 0)
		{
			sz = write(1, wbuf, wlen);
			// DEBUGF("write %zu\n", sz);
			if (sz <= 0)
				ERREXIT("write()\n");
			wlen = 0;
		}

		ret = mk_packet();

		if ((is_server == 0) && (ret != 0))
		{
			// No more files to transfer
			// (All data send. Not waiting for any reply).

			break;
			// HERE: test adding files after transfer completed...
			if (is_extra_puts >= 1)
				break;
			is_extra_puts++;
			if (GS_FT_put(&ft, "test1k-extra1.dat") != 0)
				DEBUGF_Y("Not found: test1k-extra1.dat\n");
			if (GS_FT_put(&ft, "test1k-extra2.dat") != 0)
				DEBUGF_Y("Not found: test1k-extra2.dat\n");
			continue;
		}
		if (wlen > 0)
			continue;

		sz = read(0, src, sizeof src);
		if (sz <= 0)
			ERREXIT("read()\n");
		ret = GS_PKT_decode(&pkt, src, sz, dst, &dsz);
		if (ret != 0)
			ERREXIT("GS_PKT_decode()\n");
	}

	// stats_total(&ft.stats_total);
	GS_FT_free(&ft);

	return 0;
}
