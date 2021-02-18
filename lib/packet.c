/*
 * In-band packet stack.
 *
 * Used for transfering data (such as change in window size) to remote peer.
 */
#include "gs-common.h"
#include <gsocket/gsocket.h>
#include "gsocket-engine.h"
#include "gs-externs.h"

int
GS_PKT_init(GS_PKT *pkt)
{
	memset(pkt, 0, sizeof *pkt);

	return 0;
}

int
GS_PKT_close(GS_PKT *pkt)
{
	return 0;
}

/*
 * Assign call-back functions for different in-band signals.
 */
static int
gs_pkt_assign(GS_PKT *pkt, uint8_t type, gspkt_cb_t func, void *arg)
{
	pkt->funcs[type] = func;
	pkt->args[type] = arg;

	return 0;
}

int
GS_PKT_assign_msg(GS_PKT *pkt, uint8_t msg, gspkt_cb_t func, void *arg)
{
	return gs_pkt_assign(pkt, msg, func, arg);
}

int
GS_PKT_assign_chn(GS_PKT *pkt, uint8_t chn, gspkt_cb_t func, void *arg)
{
	return gs_pkt_assign(pkt, chn + GS_PKT_MAX_MSG, func, arg);
}

/*
 * Encode len bytes from src to dst.
 * dst must be 2x the size of src.
 *
 * FIXME: could make this more memory efficient by using src == dst
 * and start encoding from the rear end (reverse) and return pointer to
 * dst.
 */
void
GS_PKT_encode(GS_PKT *pkt, const uint8_t *src, size_t slen, uint8_t *dst, size_t *dlen)
{
	uint8_t *dst_orig = dst;
	const uint8_t *send = src + slen;

	/* Escape any occurance of PKT_ESC with PKT_ESC PKT_ESC (double) */
	while (src < send)
	{
		*dst = *src;
		if (*src == GS_PKT_ESC)
		{
			// DEBUGF_W("Encoding ESC\n");
			dst++;
			*dst = GS_PKT_ESC;
		}
		dst++;
		src++;
	}

	*dlen = dst - dst_orig;
}

int
GS_PKT_MSG_size_by_type(int type)
{
	if (type == GS_PKT_TYPE_NONE /* 0x00*/) {
		return -2; // Protocol Error (FATAL)
	} else if (type < 16) {
		return 4;   //   4 - chn 1..15
	} else if (type < 32) {
		return 16;  //  16 - chn 16..31
	} else if (type < 48) {
		return 64;  //  64 - chn 32..47
	} else if (type < 64) {
		return 128; //  128 - chn 48..63
	} else if (type < 80) {
		return 512; // 512 - chn 64..79
	} else if (type < 96) {
		return 1024; // 1024 - chn 80..95
	} else if (type < 112) {
		return 2048; // 2048 - chn 96..111
	}
	return 4196; // 4196 - chn 112..127
}

/*
 * Decode slen bytes into dst until an ESC-sequence is encountered.
 * Return the number of bytes consumed from src.
 *
 * ESC ESC => ESC
 * ESC [ 1 + 7bit CHN ] [ 16 bit length ] [ data ]
 * ESC [ 0 + 7bit TYPE] [ data ]
 */
ssize_t
GS_PKT_decode_single(GS_PKT *pkt, const uint8_t *src, size_t slen, uint8_t *dst, size_t *dlen)
{
	uint8_t *dst_orig = dst;
	const uint8_t *src_orig = src;
	const uint8_t *send = src + slen;

	while (src < send)
	{
		if (pkt->esc_len_rem > 0)
		{
			if (pkt->type != 0)
			{
				// HERE: Either channel or msg
				size_t len = MIN(pkt->esc_len_rem, send - src);

				/* Check for BO (should not never happen) */
				size_t available = sizeof pkt->inband - pkt->len;
				XASSERT(len <= available, "len = %zu, left = %zu\n", len, available);
				XASSERT(len <= pkt->esc_len_rem, "len=%zu, len_rem=%zu\n", len, pkt->esc_len_rem);

				// DEBUGF("Copying %zu to inband data (total after: %zu, dsz=%zu)\n", len, pkt->len + len, dst - dst_orig);
				memcpy(pkt->inband + pkt->len, src, len);
				pkt->len += len;
				src += len;
				pkt->esc_len_rem -= len;
				if (pkt->esc_len_rem <= 0)
				{
					if (GS_PKT_IS_CHANNEL(pkt->type) && (pkt->is_got_chn_len == 0))
					{
						uint16_t nlen;
						memcpy(&nlen, &pkt->inband, 2);
						pkt->is_got_chn_len = 1;
						pkt->esc_len_rem = ntohs(nlen);
						// DEBUGF_B("Len of channel message: %zu (dsz=%zu)\n", pkt->esc_len_rem, dst - dst_orig);
						pkt->len = 0;
						if (pkt->esc_len_rem != 0)
							continue;
						/* HERE: Zero length packet. Still call CallBack */
					}

					if (pkt->funcs[pkt->type] == NULL)
					{
						DEBUGF_R("No function assigned for type %u\n", pkt->type);
					} else {
						/* val is 0..127 for msg or 0..127 for channel */
						uint8_t val;
						val = pkt->type;
						if (val >= GS_PKT_MAX_MSG)
							val -= GS_PKT_MAX_MSG;
						// DEBUGF("PKT cb type %d, data left=%zu (dsz=%zu)\n", pkt->type, send - src, dst - dst_orig);
						(*pkt->funcs[pkt->type])(val, pkt->inband, pkt->len, pkt->args[pkt->type]);
					}

					// DEBUGF("%02x %02x %02x %02x\n", pkt->inband[0], pkt->inband[1], pkt->inband[2], pkt->inband[3]);
					pkt->len = 0;
					pkt->is_got_chn_len = 0;
				}
				continue;
			}
			if (*src == GS_PKT_ESC)
			{
				/* Was ESC ESC sequence */
				*dst = GS_PKT_ESC;
				dst++;
				src++;
				pkt->esc_len_rem = 0;
				continue;
			}

			/* First character after ESC is TYPE || CHN */			
			pkt->type = *src;
			if (pkt->type == 0x0)
			{
				DEBUGF_R("ERROR TYPE IS 0x00\n");
				return -1;	// Protocol Error (FATAL)
			}

			if (GS_PKT_IS_CHANNEL(pkt->type))
			{
				/* HERE: type == 128..255 (channel) */
				pkt->esc_len_rem = 2;		/* At least two bytes for length */
			} else {
				/* HERE: type == 0..127 (fixed length message) */
				// DEBUGF("type 0x%x\n", pkt->type);
				int len;
				len = GS_PKT_MSG_size_by_type(pkt->type);
				if (len < 0)
					return len;
				pkt->esc_len_rem = len;
			}
			/* HERE: It's an escape sequence */
			src++;
			/* Return any pending data in input buffer to caller before
			 * processing in-band signaling
			 */
			if (dst > dst_orig)
				break;
		} else {
			/* NOT inside escape sequence */
			if (*src == GS_PKT_ESC)
			{
				pkt->type = 0;
				pkt->esc_len_rem = 1;		/* Unknown at this stage */
				src++;
				continue;
			}
			/* COPY */
			*dst = *src;
			dst++;
			src++;
		}

	}

	*dlen = dst - dst_orig;
	return src - src_orig;
}

/*
 * Return 0 on success.
 */
int
GS_PKT_decode(GS_PKT *pkt, const uint8_t *src, size_t slen, uint8_t *dst, size_t *dlen)
{
	size_t dsz;
	uint8_t *dst_orig = dst;
	ssize_t consumed;
	const uint8_t *s_end = src + slen;
	const uint8_t *s = src;

	while (s < s_end)
	{
		consumed = GS_PKT_decode_single(pkt, s, s_end - s, dst, &dsz);
		// DEBUGF("Consumed: %zd\n", consumed);
		if (consumed < 0)
			return -1;
		dst += dsz;
		s += consumed;
	}

	*dlen = dst - dst_orig;
	return 0;
}

