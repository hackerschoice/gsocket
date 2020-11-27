#ifndef __GS_PKT_MGR_H__
#define __GS_PKT_MGR_H__ 1

#define PKT_MSG_WSIZE		(1)
#define PKT_MSG_IDS			(2)
#define PKT_MSG_PING		(16)
#define PKT_MSG_PONG		(16)
#define PKT_MSG_LOG			(32)

struct _pkt_app_pong
{
	uint16_t load;
	uint16_t idle;
	uint8_t user[12];
} __attribute__((__packed__));

struct _pkt_app_ids
{
	uint8_t conf;
	uint8_t reserved[3];
} __attribute__((__packed__));


void pkt_app_cb_wsize(uint8_t msg, const uint8_t *data, size_t len, void *ptr);
void pkt_app_cb_ping(uint8_t msg, const uint8_t *data, size_t len, void *ptr);
void pkt_app_cb_pong(uint8_t msg, const uint8_t *data, size_t len, void *ptr);
void pkt_app_cb_ids(uint8_t msg, const uint8_t *data, size_t len, void *ptr);
void pkt_app_cb_log(uint8_t msg, const uint8_t *data, size_t len, void *ptr);

int pkt_app_send_wsize(GS_SELECT_CTX *ctx, struct _peer *p, int row);
int pkt_app_send_pong(GS_SELECT_CTX *ctx, struct _peer *p);
int pkt_app_send_ping(GS_SELECT_CTX *ctx, struct _peer *p);

#endif /* !__GS_PKT_MGR_H__ */