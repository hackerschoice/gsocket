#ifndef __GS_PKT_MGR_H__
#define __GS_PKT_MGR_H__ 1

#define PKT_MSG_WSIZE		(1)
#define PKT_MSG_IDS			(2)
#define PKT_MSG_PING		(16)
#define PKT_MSG_PONG		(16)
#define PKT_MSG_LOG			(32)  // max 64 bytes long

struct _pkt_app_pong
{
	uint16_t load;
	uint16_t idle;
	uint8_t user[12];
} __attribute__((__packed__));

struct _pkt_app_ids
{
	uint8_t flags;
	uint8_t reserved[3];
} __attribute__((__packed__));

#define GS_PKT_APP_FL_IDS	(0x01)

struct _pkt_app_log
{
	uint8_t type;
	uint8_t msg[63];
} __attribute__((__packed__));

#define GS_PKT_APP_LOG_TYPE_DEFAULT	(0x00)  // default color
#define GS_PKT_APP_LOG_TYPE_ALERT	(0x01)  // RED
#define GS_PKT_APP_LOG_TYPE_NOTICE	(0x02)  // Yellow
#define GS_PKT_APP_LOG_TYPE_INFO	(0x03)  // green
#define GS_PKT_APP_LOG_TYPE_MAX	    (0x03)  // set to highest color code



void pkt_app_cb_wsize(uint8_t msg, const uint8_t *data, size_t len, void *ptr);
void pkt_app_cb_ping(uint8_t msg, const uint8_t *data, size_t len, void *ptr);
void pkt_app_cb_pong(uint8_t msg, const uint8_t *data, size_t len, void *ptr);
void pkt_app_cb_ids(uint8_t msg, const uint8_t *data, size_t len, void *ptr);
void pkt_app_cb_log(uint8_t msg, const uint8_t *data, size_t len, void *ptr);

int pkt_app_send_wsize(GS_SELECT_CTX *ctx, struct _peer *p, int row);
int pkt_app_send_pong(GS_SELECT_CTX *ctx, struct _peer *p);
int pkt_app_send_ping(GS_SELECT_CTX *ctx, struct _peer *p);
int pkt_app_send_ids(GS_SELECT_CTX *ctx, struct _peer *p);
int pkt_app_send_all_log(GS_SELECT_CTX *ctx, struct _peer *p);


#endif /* !__GS_PKT_MGR_H__ */