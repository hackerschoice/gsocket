#ifndef __GS_FILETRANSFER_H__
#define __GS_FILETRANSFER_H__ 1

#define GS_FT_CHN_PUT           (0)  // 128
#define GS_FT_CHN_ACCEPT        (1)  // 129
#define GS_FT_CHN_LIST_REQUEST  (2)  // 130 0x82
#define GS_FT_CHN_DATA          (3)  // 131 0x83
#define GS_FT_CHN_ERROR         (4)  // 132
#define GS_FT_CHN_SWITCH        (5)  // 133 0x85
#define GS_FT_CHN_LIST_REPLY    (6)  // 134 0x86
#define GS_FT_CHN_DL            (7)  // 135 0x87

// Number of bytes needed for largest message (could be data)
#define GS_FT_MIN_BUF_SIZE	(64)

struct _gs_ft_file
{
	GS_LIST_ITEM *li;
	char *name;
	char *realname;  // local file name (absolute)
	mode_t mode;
	time_t mtime;
	FILE *fp;
	off_t fz_remote; //offset; // Offset to read(=client)/write(=server)
	off_t fz_local;  // Total file size (from client)
	uint32_t globbing_id;

	struct timespec dir_mtime;
	// statistics
	// Note: xfer might be suspended by 'switch' to another file.
	// Log suspended time in usec_suspend.
	uint64_t usec_start;
	uint64_t usec_end;
	uint64_t usec_suspend_start;
	uint64_t usec_suspend_duration;
	int64_t xfer_amount;  // Actual data on the wire
};

// Client structure to keep outstanding 'list' request in a GS-LIST
struct _gs_ft_list_pattern
{
	uint32_t globbing_id;
	char *pattern;
	char *wdir;      // working directory
};

struct _gs_ft_stats
{
	uint32_t id;
	// struct _gs_ft_file *f;
	const char *fname;
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
	// PUT (upload) - Client Side
	GS_LIST fqueue;     // Client List of files to be transfered
	GS_LIST fputs;      // Client list of files we requested transfer (put sent)
	GS_LIST faccepted;  // Client List of accepted files
	GS_LIST fcompleted; // Completed. Waiting for 'ERR_COMPLETED'
	// PUT (upload) - Server Side
	GS_LIST fadded;     // Server Side list of ready files
	GS_LIST freceiving; // Server Side list of receiving files

	// GET (download) - Client Side
	GS_LIST plistreq;         // Client List of files to be requested (globbing)
	GS_LIST plistreq_waiting; // 'list' request sent. awaiting positive reply or error.
	GS_LIST flist;       // List received from server of files (with names)
	GS_LIST fdl_waiting; // List of files to download ('gs_ft_dl' was send for these).
	// GET (download) - Server Side
	GS_LIST flistreply;  // Server list of file to be send to client.
	GS_LIST fdl;         // List of files ready to send (switch to).
	// GS_LIST fdl_completed;  // Waiting for ERR_COMPLETED

	int g_id;           // global request ID (unique) to match error-replies to requests
	int g_globbing_id;  // global globbing id
	struct _gs_ft_file *active_put_file;  // Current active upload file
	struct _gs_ft_file *active_dl_file;  // Current active download file
	gsft_cb_stats_t func_stats;
	gsft_cb_status_t func_status;

	GS_LIST qerrs;      // queue'd errors
	int is_server;
	int is_paused_data;    // write() blocked. Queue control data. Pause sending file data

	int n_files_waiting;   // Files waiting for completion or error FIXME: This should be n_requests_waiting
	// ..and be a counter of all outstanding requests we are awaiting an answer for....
	// int n_listreply_waiting;

	// Statistics total (all files)
	GS_FT_stats_total stats_total;
} GS_FT;

// CLIENT -> Server: upload a file to server.
// Server replies with 'gs_ft_accept'
struct _gs_ft_put
{
	uint32_t id;
	uint32_t fperm;
	int64_t fsize;
	uint32_t mtime;
	uint8_t flags;
	uint8_t reserved[32 - 4 - 4 - 4 - 8 - 1];
	uint8_t name[0];  // 0-terminated file name
} __attribute__((__packed__));

// CLIENT -> Server: request a file from server
struct _gs_ft_list_request
{
	uint32_t globbing_id;        // ID of _this_ LIST request
	uint8_t pattern[0]; // 0-terminated file name (globbing allowed: ~/*.[ch])
} __attribute__((__packed__));

// SERVER -> Client: Push a file to server.
struct _gs_ft_list_reply
{
	uint32_t globbing_id;    // Matching ID of get-request.
	uint32_t file_idNOTUSED;    // NBO: 0..file_max
	uint32_t file_maxNOTUSED;   // NBO: max number of files this globbing resolved into
	uint32_t fperm;
	int64_t fsize;
	uint32_t mtime;
	uint8_t flags;
	uint8_t reserved[32 - 4 - 4 - 4 - 8 - 1];
	uint8_t name[0];  // 0-terminated file name
} __attribute__((__packed__));
#define GS_FT_LISTREPLY_FL_LAST      (1)
#define GS_FT_FL_ISDIR               (2)


// CLIENT -> Server: request file for download
struct _gs_ft_dl
{
	uint32_t id;
	uint8_t res[4];
	int64_t offset; // Offset to start from
	uint8_t res2[8];
	uint8_t name[0]; // 0-terminated file name
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
// SERVER -> Client: Following data is for this file id.
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

void GS_FT_init(GS_FT *ft, gsft_cb_stats_t func_stats, gsft_cb_status_t func_status, int is_server);
void GS_FT_free(GS_FT *ft);
int GS_FT_add_file(GS_FT *ft, uint32_t id, const char *fname, size_t len, int64_t fsize, uint32_t mtime, uint32_t fperm, uint8_t flags);
int GS_FT_dl_add_file(GS_FT *ft, uint32_t id, const char *fname, size_t len, int64_t fsize);
int GS_FT_list_add_files(GS_FT *ft, uint32_t get_id, const char *pattern, size_t len);
int GS_FT_list_add(GS_FT *ft, uint32_t globbing_id, const char *fname, size_t len, int64_t fsize, uint32_t mtime, uint32_t fperm, uint8_t flags);
int GS_FT_put(GS_FT *ft, const char *fname);
int GS_FT_get(GS_FT *ft, const char *pattern);
void GS_FT_switch(GS_FT *ft, uint32_t id, int64_t offset);
void GS_FT_accept(GS_FT *ft, uint32_t id, int64_t offset);
void GS_FT_data(GS_FT *ft, const void *data, size_t len);
void GS_FT_status(GS_FT *ft, uint32_t id, uint8_t code, const char *err_str, size_t len);
size_t GS_FT_packet(GS_FT *ft, void *dst, size_t len, int *pkt_type);
void GS_FT_pause_data(GS_FT *ft);
void GS_FT_unpause_data(GS_FT *ft);
int GS_FT_WANT_WRITE(GS_FT *ft);

// Packet types
#define GS_FT_TYPE_NONE        (0)
#define GS_FT_TYPE_SWITCH      (1)
#define GS_FT_TYPE_DATA        (2)
#define GS_FT_TYPE_ERROR       (3)
#define GS_FT_TYPE_PUT         (4)
#define GS_FT_TYPE_DONE        (5)  // Inform caller that stack is done
#define GS_FT_TYPE_ACCEPT      (6)
#define GS_FT_TYPE_LISTREQUEST (7)  // CLIENT -> Server (globbing pattern)
#define GS_FT_TYPE_LISTREPLY   (8)  // SERVER -> Client
#define GS_FT_TYPE_DL          (9)  // CLIENT -> Server (request file by name)

// Packet Bulding functions
//uint16_t GS_FT_mk_put(GS_FT *ft, void *dst, size_t len, const char *fname);
//uint16_t GS_FT_mk_error(GS_FT *ft, void *dst, size_t len, uint32_t id, uint8_t code, const char *str);

#endif /* !__GS_FILETRANSFER_H__*/
