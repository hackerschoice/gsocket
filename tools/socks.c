
#include "common.h"
#include "utils.h"

int
SOCKS_init(struct _peer *p)
{
	p->socks.state = GSNC_STATE_AWAITING_MSG_AUTH;

	return GS_SUCCESS;
}

/*
 * Add data to write buffer
 */
static void
wmsg_add(struct _peer *p, char *src, ssize_t len)
{
	XASSERT(p->wlen + len < sizeof p->wbuf, "Tried to add to much data to wbuf (%zd + %zd)\n", p->wlen, len);

	memcpy(&p->wbuf[p->wlen], src, len);
	p->wlen += len;
}

static void
rmsg_consume(struct _peer *p, ssize_t len)
{
	XASSERT(p->rlen >= len, "p->rlen=%zd smaller than len=%zd\n", p->rlen, len);

	memmove(p->rbuf, &p->rbuf[len], p->rlen - len);
	p->rlen -= len;
}

/*
 * Search from ptr to end for a 0-terminated string.
 * Return GS_SUCCESS if more data is required.
 * Return GS_ERR_FATAL on error.
 * Return >0 for length of 0-terminated string found _INCLUDING_ \0.
 */
static int
getstr(uint8_t *ptr, uint8_t *end)
{
	uint8_t *start = ptr;

	if (ptr >= end)
		return GS_ERR_FATAL;

	while (ptr < end)
	{
		if (*ptr == '\0')
			break;
		ptr++;
	}
	if (*ptr != '\0')
		return GS_SUCCESS;	// More data needed

	return ptr - start + 1;	
}

static void
getip(struct _peer *p, uint8_t *ptr)
{
	memcpy(&p->socks.dst_ip, ptr, 4);
	snprintf(p->socks.dst_hostname, sizeof p->socks.dst_hostname, "%s", int_ntoa(p->socks.dst_ip));
}

static int
resolvehostname(struct _peer *p, uint8_t *ptr, ssize_t len)
{
	char *h = p->socks.dst_hostname;

	if (len >= sizeof p->socks.dst_hostname - 1)
		return GS_ERR_FATAL;
	memcpy(h, ptr, len);
	h[len] = '\0';
	DEBUGF_M("Socks4a/5 Domain Name (len=%zd): '%s'\n", len, h);

	/* Resolve hostname */
	uint32_t ip;
	ip = GS_hton(h);
	if (ip == -1)
		return GS_ERR_FATAL;

	p->socks.dst_ip = ip;

	return GS_SUCCESS;
}

static void
socks_done(struct _peer *p, char *reply, ssize_t len, ssize_t consumed)
{

	DEBUGF_M("Socks-Conn to %s:%d\n", int_ntoa(p->socks.dst_ip), ntohs(p->socks.dst_port));

	wmsg_add(p, reply, len);	// Reply 'Request granted'
	rmsg_consume(p, consumed);
	p->socks.state = GSNC_STATE_CONNECTING;
}

int
SOCKS4_add(struct _peer *p)
{
	uint8_t *end = p->rbuf + p->rlen;
	uint8_t *ptr = p->rbuf;
	uint8_t *ip_ptr;
	int ret;

	/* Socks4 :  VER + CMD + 16-Port + 32-IP + id\0
	 * Socks4a:  VER + CMD + 16-Port + 000x + id\0 hostname\0
	 */
	if (p->rlen < 9)
		return GS_SUCCESS;

	ptr += 2;
	memcpy(&p->socks.dst_port, ptr, 2);
	ptr += 2;
	ip_ptr = ptr;
	memcpy(&p->socks.dst_ip, ptr, 4);
	ptr += 4;

	ret = getstr(ptr, end);		// ID\0
	if (ret <= 0)
		return ret;
	DEBUGF_M("Socks4 ID (len=%d) '%s'\n", ret-1, ptr);

	ptr += ret;	// skip str length and \0
	/* Check if this is Socks4a */
	if (memcmp(ip_ptr, "\0\0\0", 3) == 0)
	{
		int hn_len;
		hn_len = getstr(ptr, end);
		if (hn_len <= 0)
			return hn_len;
		DEBUGF_M("Socks4a hostname (len=%d) '%s'\n", hn_len-1, ptr);

		ret = resolvehostname(p, ptr, hn_len-1);
		if (ret != GS_SUCCESS)
			return ret;
		ptr += hn_len;
	} else {
		getip(p, ip_ptr);
	}

	socks_done(p, "\x00\x5a" "\x00\x00" "\x00\x00\x00\x00", 8, ptr - p->rbuf);
	return GS_SUCCESS;
}

int
SOCKS5_add(struct _peer *p)
{
	uint8_t *end = p->rbuf + p->rlen;
	uint8_t *ptr = p->rbuf;
	int ret;

	if (p->socks.state == GSNC_STATE_AWAITING_MSG_AUTH)
	{
		ptr += 2;
		if (p->rlen < 1 + 1 + p->rbuf[1])
			return GS_SUCCESS;	// Need more data

		ptr += p->rbuf[1];
		/* Check if client supports NO AUTH */
		int i;
		for (i = 0; i < p->rbuf[1]; i++)
		{
			if (p->rbuf[1 + 1 + i] == 0x00)
				break;	// No-Auth offered by client
		}
		if (i > p->rbuf[1])
		{
			return GS_ERR_FATAL;	// No-Auth not offered by client
		}

		/* HERE: Reply to client with No-Auth selected */
		XASSERT(p->wlen <= 0, "Data already in output buffer\n");
		DEBUGF_M("SOCKS AUTH received\n");

		wmsg_add(p, "\x05\x00", 2);	// Reply 'No-Auth' Supported
		rmsg_consume(p, ptr - p->rbuf);

		p->socks.state = GSNC_STATE_AWAITING_MSG_CONNECT;
		/* FALL-THROUGH (to GSNC_STATE_AWAITING_MSG_CONNECT) */
	}

	if (p->socks.state == GSNC_STATE_AWAITING_MSG_CONNECT)
	{
		if (p->rlen < 3)
			return GS_SUCCESS;	// Need more data

		if (p->rbuf[0] != 0x05)
			return GS_ERR_FATAL;

		if (p->rbuf[1] != 0x01)
			return GS_ERR_FATAL;	// Only support stream connection

		ptr += 3;
		/* HERE: ptr == dst-address */
		if (ptr[0] == 0x01)
		{
			ptr += 1;
			if (end - ptr < 4)
				return GS_SUCCESS;	// Need more data

			getip(p, ptr);
			ptr += 4;
		} else if (ptr[0] == 0x03) {
			ptr += 1;

			if (end - ptr < 1)
				return GS_SUCCESS;	// Need more data

			int len;
			len = ptr[0];
			ptr += 1;
			if (end - ptr < len)
				return GS_SUCCESS;	// Need more data

			ret = resolvehostname(p, ptr, len);
			if (ret != GS_SUCCESS)
				return ret;

			ptr += len;
		} else {
			return GS_ERR_FATAL;
		}

		if (end - ptr < 2)
			return GS_SUCCESS;

		memcpy(&p->socks.dst_port, ptr, 2);
		ptr += 2;

		socks_done(p, "\x05\x00\x00" /*IPv4*/ "\x01" /*ip*/ "\x00\x00\x00\x00" /*port*/ "\x00\x00", 10, ptr - p->rbuf);
	}

	return GS_SUCCESS;
}

/*
 * Consume data from rbuf and check act on SOCKS messages accordingly
 * (by replying to them correctly).
 * There may be some app-data left in rbuf after all SOCKS messages have
 * been processed.
 */
int
SOCKS_add(struct _peer *p)
{
	int ret;
	HEXDUMPF(p->rbuf, p->rlen, "SOCKS_add (gs->fd = %d): ", p->gs->fd);

	if (p->rlen < 3)
		return GS_SUCCESS;	//  Need more data

	if (p->rbuf[0] == 0x04)
	{
		ret = SOCKS4_add(p);
	} else if (p->rbuf[0] == 0x05) {
		ret = SOCKS5_add(p);
	} else
		return GS_ERR_FATAL;

	return ret;
}
