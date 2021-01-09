/*
 * Test program to test gs filetransfer sub-system used by gs-netcat.
 *

mkdir -p test
rm -rf test/test*.dat
socat SYSTEM:'./filetransfer-test c test4k.dat test8k.dat 2>client.log' SYSTEM:'(cd test; ../filetransfer-test s 2>../server.log)'

socat SYSTEM:'./filetransfer-test c /usr/share/man/./  2>client.log' SYSTEM:'(cd test; ../filetransfer-test s 2>../server.log)'
STOP HERE (not working): 
socat SYSTEM:'./filetransfer-test c /usr/share/man/mann  2>client.log' SYSTEM:'(cd test; ../filetransfer-test s 2>../server.log)'
is this a blocking problem? or some odd files that are not normal files?

FIXME:
- test that buffer does not go heywire when write() blocks or when write() is incomplete (8192).
   (i really should PAUSE transfer if write() is incomplete???)
- 
 */

#include "common.h"
#include "filetransfer.h"
#include "utils.h"

#define BUF_LEN		(250)
// #define BUF_LEN		(GS_PKT_MAX_SIZE)

static GS_PKT pkt;
static GS_FT ft;
static GS_BUF gsb;
static fd_set rfds, wfds;

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

/*
 * Return -1 when all done (must exit)
 * Return 0 on success.
 * Return 1 when waiting for data
 */
int
mk_packet(void)
{
	struct gs_pkt_chn_hdr *hdr = (struct gs_pkt_chn_hdr *)GS_BUF_WDST(&gsb);
	int pkt_type;
	size_t sz;

	size_t max_len;

	max_len = MIN(GS_PKT_MAX_SIZE, GS_BUF_UNUSED(&gsb) - sizeof *hdr);

	// if (GS_BUF_USED(&gsb) > 0)
	// 	DEBUGF_Y("%zu bytes already in buffer, max_len=%zu\n", GS_BUF_USED(&gsb), max_len);
	memset(GS_BUF_WDST(&gsb), 0, max_len); // FIXME
	sz = GS_FT_packet(&ft, GS_BUF_WDST(&gsb) + sizeof *hdr, max_len, &pkt_type);

	switch (pkt_type)
	{
	case GS_FT_TYPE_NONE:
		// Nothing to write...waiting for peer's reply.
		// DEBUGF_G("TYPE NONE\n");
		return 1;
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
	case GS_FT_TYPE_DONE:
		// CLIENT only: done with all files.
		DEBUGF_G("All done.\n");
		return -1;
	default:
		ERREXIT("unknown type %d\n", pkt_type);
	}

	hdr->esc = GS_PKT_ESC;
	uint16_t len = htons(sz);
	memcpy(&hdr->len, &len, sizeof len);
	// DEBUGF("Packet type=%u length %zu + %zu\n", hdr->type, sizeof *hdr, sz);

	// if (hdr->type == 131)
	// {
	// 	static FILE *dfp;
	// 	if (dfp == NULL)
	// 		dfp = fopen("packet-out.dat", "w");
	// 	fwrite(GS_BUF_WDST(&gsb), 1, sizeof *hdr + sz, dfp); fflush(dfp);
	// }
	// STOP HERE: packet-out.dat shows correct data but output.dat (from write()) does not..

	XASSERT(sz + sizeof *hdr <= GS_BUF_UNUSED(&gsb), "Oops, GS_FT_packet() to long. sz=%zu, unusued=%zu.\n", sz, GS_BUF_UNUSED(&gsb));
	GS_BUF_add(&gsb, sizeof *hdr + sz);

	// if (hdr->type == 131)
	// {
	// 	static FILE *dxfp;
	// 	if (dxfp == NULL)
	// 		dxfp = fopen("packet-out-after.dat", "w");
	// 	fwrite(GS_BUF_WDST(&gsb) - sizeof *hdr - sz, 1, sizeof *hdr + sz, dxfp); fflush(dxfp);
	// }

	return 0;
}

#include "globbing.h"
static void
glob_cb(GS_GL *res)
{
	DEBUGF("Inside Globbing CB %s\n", res->name);
	if (GS_FT_put(&ft, res->name) != 0)
		DEBUGF_Y("Not valid: %s\n", res->name); // not found or directory
}


static void
glob_cb_test(GS_GL *res)
{
	DEBUGF("Inside Globbing CB %s\n", res->name);
}
static void
do_test(const char *exp)
{
	if (exp == NULL)
		exp = "/tmp/fo*";
	GS_GLOBBING(glob_cb_test, exp);
	exit(0);
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
	int n;

	GS_library_init(stderr, stderr);
	gopt.err_fp = stderr;
	gopt.log_fp = stderr;

	// do_test(argv[2]);

	GS_BUF_init(&gsb, GS_PKT_MAX_SIZE + GS_PKT_HDR_MAX_SIZE);

	fcntl(1, F_SETFL, O_NONBLOCK | fcntl(1, F_GETFL, 0));
	GS_PKT_init(&pkt);

	GS_PKT_assign_chn(&pkt, GS_FT_CHN_ERROR, pkt_cb_error, NULL);
	if (*argv[1] == 'c')
	{
		GS_FT_init(&ft, cb_stats, cb_status, 0);
		GS_PKT_assign_chn(&pkt, GS_FT_CHN_ACCEPT, pkt_cb_accept, NULL);
		// Add files to queue...
		char **ptr = &argv[2];
		while (*ptr != NULL)
		{
			// DEBUGF_B("'%s'\n", *ptr);
			GS_GLOBBING(glob_cb, *ptr);
			ptr++;
		}
	} else {
		GS_FT_init(&ft, NULL, cb_status, 1);
		GS_PKT_assign_chn(&pkt, GS_FT_CHN_PUT, pkt_cb_put, NULL);
		GS_PKT_assign_chn(&pkt, GS_FT_CHN_DATA, pkt_cb_data, NULL);
		GS_PKT_assign_chn(&pkt, GS_FT_CHN_SWITCH, pkt_cb_switch, NULL);
	}

	while (1)
	{
		ret = mk_packet();
		if ((ft.is_server == 0) && (ret == -1))
		{
			// No more files to transfer
			// (All data send. Not waiting for any reply).

			break;
			#if 0
			// HERE: test adding files after transfer completed...
			if (is_extra_puts >= 1)
				break;
			is_extra_puts++;
			if (GS_FT_put(&ft, "test1k-extra1.dat") != 0)
				DEBUGF_Y("Not found: test1k-extra1.dat\n");
			if (GS_FT_put(&ft, "test1k-extra2.dat") != 0)
				DEBUGF_Y("Not found: test1k-extra2.dat\n");
			continue;
			#endif
		}

		// If there is data to write then write data first.
		FD_CLR(0, &rfds);
		FD_SET(0, &rfds);

		FD_CLR(1, &wfds);
		if (GS_BUF_USED(&gsb) > 0)
			FD_SET(1, &wfds);
		// DEBUGF("Write Data pending: %zu\n", GS_BUF_USED(&gsb));

		// Go into select if write-pending or waiting for data		
		if ((GS_BUF_USED(&gsb) > 0) || (ret == 1))
		{
			struct timeval tv;
			tv.tv_usec = 0;
			tv.tv_sec = 1;
			n = select(2, &rfds, &wfds, NULL, &tv);
			if (n < 0)
				ERREXIT("select(): %s\n", strerror(errno));
		}

		if (FD_ISSET(1, &wfds))
		{
			// HERE: Write what we can from io-write buffer (max 16k writes).
			// Adjust buffer of data successfully written.
			// FIXME: MIN(1024,, .. to trigger bug early. Remove. Always try to write all
			// sz = write(1, GS_BUF_RSRC(&gsb), MIN(1024, GS_BUF_USED(&gsb)));
			sz = write(1, GS_BUF_RSRC(&gsb), GS_BUF_USED(&gsb));
			// DEBUGF("write() == %zd of %zu\n", sz, GS_BUF_USED(&gsb));
			if (sz == 0)
				ERREXIT("write() EOF\n");

			if (sz < 0)
			{
				if (errno == EAGAIN)
				{
					DEBUGF_R("WOULD BLOCK..pausing data\n");
					exit(0); // FIXME
					// Stop sending data packets but keep queueing control
					// packets (e.g. replies to what we read()).
					GS_FT_pause_data(&ft);
				}
				ERREXIT("write(): %s\n", strerror(errno));
			}

			// HERE: write() was a success. Consume data.
			GS_BUF_del(&gsb, sz);
			// DEBUGF("Write Data pending [after write]: %zu\n", GS_BUF_USED(&gsb));

			GS_FT_unpause_data(&ft);
		}

		if (FD_ISSET(0, &rfds))
		{
			sz = read(0, src, sizeof src);
			// DEBUGF_G("read() == %zu\n", sz);
			if (sz <= 0)
				ERREXIT("read()\n");
			ret = GS_PKT_decode(&pkt, src, sz, dst, &dsz);
			if (ret != 0)
				ERREXIT("GS_PKT_decode()\n");
			if (dsz != 0)
			{
				HEXDUMP(src, sz);
				HEXDUMP(dst, dsz);
				ERREXIT("test program should contain only inband data...dsz=%zu\n", dsz);
			}
		}
	}

	// stats_total(&ft.stats_total);
	GS_FT_free(&ft);
	GS_BUF_free(&gsb);

	return 0;
}
