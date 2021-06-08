/*
 * Test program to test gs packet sub-system
 *
 * Self-Test:
 * dd bs=1024k count=1024 if=/dev/urandom of=test1G.dat
 * ./packet-test encode <test1M.dat 2>/dev/null | ./packet-test >test1M_rec.dat && md5 test1M*.dat
 * ./packet-test encode <test1G.dat 2>/dev/null | ./packet-test >test1G_rec.dat && md5 test1G*.dat
 */
#include "common.h"
#include "utils.h"

#define PKT_TYPE_WSIZE	0x01

static void
pkt_cb_wsize(uint8_t type, const uint8_t *data, size_t len, void *arg)
{
	uint16_t cols, rows;

	memcpy(&cols, data, 2);
	memcpy(&rows, data + 2, 2);
	// DEBUGF("cols = %u, rows = %u\n", cols, rows);

	cols = ntohs(cols);
	rows = ntohs(rows);
}

static void
pkt_cb_channel(uint8_t channel, const uint8_t *data, size_t len, void *arg)
{
	if (channel >= GS_PKT_MAX_CHN)
		return;

	// DEBUGF("Channel #%u, length %zu\n", channel, len);
}

static void
my_write(int fd, void *data, size_t len)
{
	if (write(fd, data, len) != len)
		ERREXIT("write()\n");
}
/*
 */
int
main(int argc, char *argv[])
{
	size_t src_sz = 64;
	uint8_t src[src_sz];
	uint8_t dst[src_sz * 2];
	size_t sz;
	size_t dsz;
	int ret;
	GS_PKT pkt;
	int is_encode = 0;

	GS_library_init(stderr, stderr, NULL);  // Library debug output
	gopt.err_fp = stderr;
	gopt.log_fp = stderr;

	if (argc > 1)
		is_encode = 1;

	srand(time(NULL));
	GS_PKT_init(&pkt);
	GS_PKT_assign_msg(&pkt, PKT_TYPE_WSIZE, pkt_cb_wsize, NULL);
	GS_PKT_assign_chn(&pkt, 0, pkt_cb_channel, NULL);
	GS_PKT_assign_chn(&pkt, 1, pkt_cb_channel, NULL);
	while (1)
	{
		/* Read random number of bytes for shits and giggles */
		size_t rsz = rand() % src_sz + 1;
		sz = read(0, src, rsz);
		if (sz <= 0)
			break;

		if (is_encode)
		{
			GS_PKT_encode(&pkt, src, sz, dst, &dsz);
			my_write(1, dst, dsz);
			/* Randomly introduce an in-band packet */
			#if 1
			uint8_t buf[GS_PKT_MAX_SIZE];
			memset(buf, 0x41, sizeof buf);
			buf[0] = GS_PKT_ESC;
			if (rand() % 100 == 0)
			{
				/* in-band MSG of size 4 */
				buf[1] = 0x01;
				memcpy(buf + 2, "1234", 4);
				my_write(1, buf, 2 + 4);
			}	
			if (rand() % 100 == 0)
			{
				/* in-band MSG of size 512 bytes */
				buf[1] = 0x7f;
				/* Add a larger inband packet for shits and giggles */
				my_write(1, buf, 2 + 512);
			}
			if (rand() % 10 == 0)
			{
				/* in-band channel (stream) data on channel #1 */
				buf[1] = 1 | (1<<7);
				uint16_t len = rand() % (GS_PKT_MAX_SIZE);
				uint16_t nlen = htons(len);
				// DEBUGF("sending len = %u\n", len);
				memcpy(buf + 2, &nlen, 2);

				my_write(1, buf, 2 + 2 + len);

			}
			#endif		

			continue;
		}

		/* HERE: decode */
		ret = GS_PKT_decode(&pkt, src, sz, dst, &dsz);
		if (ret != 0)
			exit(-1);
		my_write(1, dst, dsz);
	}

	return 0;
}
