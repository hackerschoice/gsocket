#ifndef __GS_FILETRANSFER_H__
#define __GS_FILETRANSFER_H__ 1

#define GS_FT_CHN_PUT       (0)
#define GS_FT_CHN_ACCEPT    (1)
#define GS_FT_CHN_DATA      (3)
#define GS_FT_CHN_ERROR     (4)
#define GS_FT_CHN_SWITCH    (5)

// Number of bytes needed for largest message (could be data)
#define GS_FT_MIN_BUF_SIZE	(64)

struct _gs_ft_file
{
	GS_LIST_ITEM *li;
	char *name;
	char *realname;  // realpath() resolved
	mode_t mode;
	time_t mtime;
	FILE *fp;
	off_t offset; // Offset to read(=client)/write(=server)
	off_t fsize;  // Total file size (from client)

	// statistics
	// Note: xfer might be suspended by 'switch' to another file.
	// Log suspended time in usec_suspend.
	uint64_t usec_start;
	uint64_t usec_end;
	uint64_t usec_suspend_start;
	uint64_t usec_suspend_duration;
	int64_t xfer_amount;  // Actual data on the wire
};

struct _gs_ft_stats
{
	uint32_t id;
	struct _gs_ft_file *f;
	uint64_t xfer_duration; // Actual transfer time (without suspension)
	uint64_t xfer_amount;   // Actual data transfered
	char speed_str[8];     // Speed (bps). Human readable string.
};

typedef void (*gsft_cb_stats_t)(struct _gs_ft_stats *s);

// Updated after each file completion
typedef struct
{
	uint64_t xfer_duration;
	uint64_t xfer_amount;
	char speed_str[8];
	int n_files_success; // transferred or skipped so far
	int n_files_error;
} GS_FT_stats_total;

/*
 * Queue'ed error's that need to be send to peer.
 */
struct _gs_ft_qerr
{
	uint32_t id;
	uint8_t code;
	char *str;
};

struct _gs_ft_status
{
	uint8_t code;
	struct _gs_ft_file *file;
	char err_str[128]; // 0-terminated error string
};
typedef void (*gsft_cb_status_t)(void *ft_ptr, struct _gs_ft_status *s);
 
typedef struct 
{
	GS_LIST fqueue;     // Client List of files to be transfered
	GS_LIST fputs;      // Client list of files we requested transfer (put sent)
	GS_LIST faccepted;  // Client List of accepted files
	GS_LIST fcompleted; // Completed. Waiting for 'ERR_COMPLETED'

	GS_LIST fadded;     // Server Side list of ready files
	GS_LIST freceiving; // Server Side list of receiving files
	int g_id;
	struct _gs_ft_file *active_put_file;  // Current active file
	struct _gs_ft_file *active_receiving; //
	gsft_cb_stats_t func_stats;
	gsft_cb_status_t func_status;

	GS_LIST qerrs;      // queue'd errors

	int n_files_waiting;   // Files waiting for completion or error

	// Statistics total (all files)
	GS_FT_stats_total stats_total;
} GS_FT;

// CLIENT -> Server: put a file to server.
struct _gs_ft_put
{
	uint32_t id;
	uint32_t fperm;
	int64_t fsize;
	uint32_t mtime;
	uint8_t reserved[32 - 4 - 4 - 4 - 8];
	uint8_t name[0];  // 0-terminated file name
} __attribute__((__packed__));

// SERVER -> Client: Accept file. (reply to PUT)
struct _gs_ft_accept
{
	uint32_t id;
	uint8_t res[4];
	int64_t offset_dst; // Server side fsize
	uint8_t crcNOTUSED[4];
	uint8_t res2[4];
} __attribute__((__packed__));

// CLIENT -> Server: Following data is for this file id.
struct _gs_ft_switch
{
	uint32_t id;
	uint8_t res[4];
	// int64_t fsize;  // total file size
	int64_t offset; // offset to start
} __attribute__((__packed__));

struct _gs_ft_error
{
	uint32_t id;
	uint8_t code;
	uint8_t res[3]; // reerved
	uint8_t str[0]; // 0-terminated error string (not used)
} __attribute__((__packed__));

#define GS_FT_ERR_UNKNOWN      (0)
#define GS_FT_ERR_PERM         (1)
#define GS_FT_ERR_NOENT        (2)
#define GS_FT_ERR_BADFSIZE     (3)   // Size on server is larger
#define GS_FT_ERR_BADF         (9)
#define GS_FT_ERR_NODATA       (10)
#define GS_FT_ERR_COMPLETED    (128) // All data written successfully

void GS_FT_init(GS_FT *ft, gsft_cb_stats_t func, gsft_cb_status_t);
void GS_FT_free(GS_FT *ft);
int GS_FT_add_file(GS_FT *ft, uint32_t id, const char *fname, size_t len, int64_t fsize, uint32_t mtime, uint32_t fperm);
int GS_FT_put(GS_FT *ft, const char *fname);
void GS_FT_switch(GS_FT *ft, uint32_t id, /*int64_t fsize, */int64_t offset);
void GS_FT_accept(GS_FT *ft, uint32_t id, int64_t offset);
void GS_FT_data(GS_FT *ft, const void *data, size_t len);
void GS_FT_status(GS_FT *ft, uint32_t id, uint8_t code, const char *err_str, size_t len);
// void GS_FT_del_file(GS_FT *ft, uint32_t id);
size_t GS_FT_packet(GS_FT *ft, void *dst, size_t len, int *pkt_type);
int GS_FT_WANT_WRITE(GS_FT *ft);

// Packet types
#define GS_FT_TYPE_NONE       (0)
#define GS_FT_TYPE_SWITCH     (1)
#define GS_FT_TYPE_DATA       (2)
#define GS_FT_TYPE_ERROR      (3)
#define GS_FT_TYPE_PUT        (4)
#define GS_FT_TYPE_DONE       (5)  // Inform caller that stack is done
#define GS_FT_TYPE_ACCEPT     (6)

// Packet Bulding functions
//uint16_t GS_FT_mk_put(GS_FT *ft, void *dst, size_t len, const char *fname);
//uint16_t GS_FT_mk_error(GS_FT *ft, void *dst, size_t len, uint32_t id, uint8_t code, const char *str);

#endif /* !__GS_FILETRANSFER_H__*/
