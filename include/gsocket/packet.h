#ifndef __GS_PACKET_H__
#define __GS_PACKET_H__ 1

#define GS_PKT_MAX_SIZE		(2048)  // content length without pkt-header (2 or 4 bytes)
#define GS_PKT_HDR_MAX_SIZE (4)
#define GS_PKT_MAX_MSG		128  // type = 0..127
#define GS_PKT_MAX_CHN		128  // type = 128..255 
// #define GS_PKT_ESC			'e'  // TESTING ONLY
#ifndef GS_PKT_ESC
# define GS_PKT_ESC			0xFB // escape character
#endif

#define GS_PKT_MSG_HDR_LEN	(2)
#define GS_PKT_CHN_HDR_LEN	(4)

typedef void (*gspkt_cb_t)(uint8_t type, const uint8_t *data, size_t len, void *arg);

/*
 * - msg are fixed length (e.g. window size)
 * - channels are streams (e.g. file transfer)
 */
typedef struct
{
	size_t esc_len_rem;
	uint8_t type;					// type 0..127 is msg's, 128..255 is chn
	uint8_t inband[GS_PKT_MAX_SIZE];// in-band packet/stream chunk
	size_t len;						// length of data in inband buffer
	int is_got_chn_len;				//
	gspkt_cb_t funcs[256];			// Dispatch functions for msg/chn type
	void *args[256];
} GS_PKT;

struct gs_pkt_msg_hdr
{
	uint8_t esc;
	uint8_t type;
} __attribute__((__packed__));

struct gs_pkt_chn_hdr
{
	uint8_t esc;
	uint8_t type;
	uint16_t len;
} __attribute__((__packed__));


#define GS_PKT_IS_CHANNEL(a)		(((a) >> 7) & 0x01)
#define GS_PKT_CHN2TYPE(a)          (GS_PKT_MAX_MSG + a)

int GS_PKT_init(GS_PKT *pkt);
int GS_PKT_close(GS_PKT *pkt);
int GS_PKT_assign_msg(GS_PKT *pkt, uint8_t msg, gspkt_cb_t func, void *arg);
int GS_PKT_assign_chn(GS_PKT *pkt, uint8_t chn, gspkt_cb_t func, void *arg);
void GS_PKT_encode(GS_PKT *pkt, const uint8_t *src, size_t slen, uint8_t *dst, size_t *dlen);
int GS_PKT_decode(GS_PKT *pkt, const uint8_t *src, size_t slen, uint8_t *dst, size_t *dlen);
ssize_t GS_PKT_decode_single(GS_PKT *pkt, const uint8_t *src, size_t slen, uint8_t *dst, size_t *dlen);
int GS_PKT_MSG_size_by_type(int type);

#define GS_PKT_TYPE_NONE		0x00

#endif /* !__GS_PACKET_H__ */
