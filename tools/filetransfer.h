#ifndef __GS_FILETRANSFER_H__
#define __GS_FILETRANSFER_H__ 1

#define GS_FT_CHN_PUT       (0)
#define GS_FT_CHN_ACCEPT    (1)
#define GS_FT_CHN_DATA      (3)
#define GS_FT_CHN_ERROR     (4)
#define GS_FT_CHN_SWITCH    (5)

struct _gs_ft_file
{
	GS_LIST_ITEM *li;
	char *name;
	char *realname;  // realpath() resolved
	uint32_t umask;
	FILE *fp;
	off_t offset; // Offset to start transmitting
	off_t fsize;  // Total file size (from client)
};

typedef struct 
{
	GS_LIST fqueue;     // Client List of files to be transfered
	GS_LIST fputs;      // Client list of files we requested transfer (put sent)
	GS_LIST faccepted;  // Client List of accepted files

	GS_LIST fadded;     // Server Side list of ready files
	GS_LIST freceiving; // Server Side list of receiving files
	int g_id;
	struct _gs_ft_file *active_put_file;  // Current active file
	struct _gs_ft_file *active_receiving; //
	int is_put_done;    // No more files to transmit
} GS_FT;


// CLIENT -> Server: put a file to server.
struct _gs_ft_put
{
	uint32_t umask;
	uint32_t id;
	uint8_t reserved[32 - 4 - 4];
	uint8_t name[0];  // 0-terminated file name
} __attribute__((__packed__));

// SERVER -> Client: Accept file.
struct _gs_ft_accept
{
	uint32_t id;
	uint8_t res[4];
	int64_t offset;
	uint8_t crcNOTUSED[4];
	uint8_t res2[4];
} __attribute__((__packed__));

// CLIENT -> Server: Following data is for this file id.
struct _gs_ft_switch
{
	uint32_t id;
	uint8_t res[4];
	int64_t fsize; // total file size
} __attribute__((__packed__));

struct _gs_ft_error
{
	uint8_t code;
	uint8_t res[3]; // reerved
	uint32_t id;
	uint8_t str[0]; // 0-terminated error string (not used)
} __attribute__((__packed__));

#define GS_FT_ERR_UNKNOWN      (0)
#define GS_FT_ERR_PERM         (1)
#define GS_FT_ERR_NOENT        (2)
#define GS_FT_ERR_BADF         (9)
#define GS_FT_ERR_NODATA       (10)

void GS_FT_init(GS_FT *ft);
void GS_FT_free(GS_FT *ft);
int64_t GS_FT_add_file(GS_FT *ft, uint32_t id, const char *fname, uint32_t umask);
int GS_FT_put(GS_FT *ft, const char *fname);
void GS_FT_switch(GS_FT *ft, uint32_t id, int64_t fsize);
void GS_FT_accept(GS_FT *ft, uint32_t id, int64_t offset);
void GS_FT_data(GS_FT *ft, const void *data, size_t len);
void GS_FT_del_file(GS_FT *ft, uint32_t id);
size_t GS_FT_packet(GS_FT *ft, void *dst, size_t len, int *pkt_type);

#define GS_FT_TYPE_NONE       (0)
#define GS_FT_TYPE_SWITCH     (1)
#define GS_FT_TYPE_DATA       (2)
#define GS_FT_TYPE_ERROR      (3)
#define GS_FT_TYPE_PUT        (4)
#define GS_FT_TYPE_DONE       (5)
#define GS_FT_TYPE_ACCEPT     (6)

// Packet Bulding functions
//uint16_t GS_FT_mk_put(GS_FT *ft, void *dst, size_t len, const char *fname);
//uint16_t GS_FT_mk_error(GS_FT *ft, void *dst, size_t len, uint32_t id, uint8_t code, const char *str);

#endif /* !__GS_FILETRANSFER_H__*/
