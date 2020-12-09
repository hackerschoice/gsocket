/*
 * Test program to test gs filetransfer sub-system used by gs-netcat.
 *
 * Client: socat SYSTEM:'./filetransfer-test c test1.dat' TCP:127.1:1337
 * Server: socat TCP-LISTEN:1337 SYSTEM:'./filetransfer-test s'
 * ...or in one line:

mkdir -p test
rm -rf test/test*.dat
socat SYSTEM:'./filetransfer-test c test4k.dat test8k.dat 2>client.log' SYSTEM:'(cd test; ../filetransfer-test s 2>server.log)'

rm -rf test/test*.dat
dd bs=1k count=5 if=test8k.dat of=test/test8k.dat
socat SYSTEM:'./filetransfer-test c test4k.dat test8k.dat 2>client.log' SYSTEM:'(cd test; ../filetransfer-test s 2>server.log)'
md5sum -q test8k.dat test/test8k.dat
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

// static void file_error(uint32_t id, const char *str);

/* SERVER receiving PUT from client */
static void
pkt_cb_put(uint8_t chn, const uint8_t *data, size_t len, void *argNOTUSED)
{
	struct _gs_ft_put *p = (struct _gs_ft_put *)data;
	struct _gs_ft_put hdr;

	if (len < sizeof hdr + 1)
		return;  // protocol error

	// HEXDUMP(data, len);
	if (data[len - 1] != '\0')
		return;  // protocol error

	memcpy(&hdr, data, sizeof hdr);
	// FIXME: sanitize file name
	DEBUGF("CB-PUT - umask 0x%x, id %u, '%s'\n", ntohl(hdr.umask), ntohl(hdr.id), p->name);
	GS_FT_add_file(&ft, ntohl(hdr.id), (char *)p->name, ntohl(hdr.umask));	
}

static void
pkt_cb_switch(uint8_t chn, const uint8_t *data, size_t len, void *argNOTUSED)
{
	struct _gs_ft_switch *p = (struct _gs_ft_switch *)data;
	struct _gs_ft_switch hdr;

	if (len < sizeof hdr)
		return; // protocol error

	memcpy(&hdr, data, sizeof hdr);
	GS_FT_switch(&ft, ntohl(hdr.id), ntohll(hdr.fsize));
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
	DEBUGF("acc offset = %lld\n", ntohll(hdr.offset));

	GS_FT_accept(&ft, ntohl(hdr.id), ntohll(hdr.offset));
}

// Client & Server
static void
pkt_cb_error(uint8_t chn, const uint8_t *data, size_t len, void *argNOTUSED)
{
	struct _gs_ft_error *p = (struct _gs_ft_error *)data;
	struct _gs_ft_error hdr;


	if (len < sizeof hdr + 1)
		return; // protocol error
	if (data[len - 1] != '\0')
		return; // protocol error

	memcpy(&hdr, data, sizeof hdr);
	DEBUGF_R("CB-ERROR: id %u code %u (%s)\n", ntohl(hdr.id), hdr.code, p->str);

	GS_FT_del_file(&ft, ntohl(hdr.id));
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
		return 0;
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
		DEBUGF_G("all done??\n");
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
	GS_FT_init(&ft);

	GS_PKT_assign_chn(&pkt, GS_FT_CHN_ERROR, pkt_cb_error, NULL);
	if (*argv[1] == 'c')
	{
		GS_PKT_assign_chn(&pkt, GS_FT_CHN_ACCEPT, pkt_cb_accept, NULL);
		// Add files to queue...
		char **ptr = &argv[2];
		while (*ptr != NULL)
		{
			if (GS_FT_put(&ft, *ptr) != 0)
				DEBUGF_Y("Not found: %s\n", *ptr);
			ptr++;
		}
		// GS_FT_put(&ft, "test1k.dat");
		// GS_FT_put(&ft, "test4k.dat");
	} else {
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
		if (mk_packet() != 0)
		{
			if (is_server)
				break;

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
		// DEBUGF_B("read %zu\n", sz);
		if (sz <= 0)
			ERREXIT("read()\n");
		ret = GS_PKT_decode(&pkt, src, sz, dst, &dsz);
		if (ret != 0)
			ERREXIT("GS_PKT_decode()\n");
	}

	return 0;
}
