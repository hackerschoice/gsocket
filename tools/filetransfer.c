
#include "common.h"
#include "utils.h"
#include "filetransfer.h"

static void ft_del(GS_LIST_ITEM *li);

// FIXME: must make sure that server cant request transfer from client!

void
GS_FT_init(GS_FT *ft)
{
	memset(ft, 0, sizeof *ft);
	GS_LIST_init(&ft->fqueue, 0);
	GS_LIST_init(&ft->fputs, 0);
	GS_LIST_init(&ft->faccepted, 0);

	GS_LIST_init(&ft->fadded, 0);
	GS_LIST_init(&ft->freceiving, 0);
}

#if 0
uint16_t
GS_FT_mk_put(GS_FT *ft, void *dst, size_t len, const char *name)
{
	size_t n;
	struct _gs_ft_put *hdr = (struct _gs_ft_put *)dst;

	if (len < sizeof *hdr + 1)
		return 0;  // protcol error

	hdr->umask = 3133;
	hdr->id = htonl(ft->g_id);
	ft->g_id += 1;

	n = MIN(len - sizeof *hdr, strlen(name) + 1);
	// DEBUGF("name len %zu + hdr %zu\n", n, sizeof *hdr);
	memcpy(hdr->name, name, n - 1);
	hdr->name[n] = '\0';

	return sizeof *hdr + n;
}

uint16_t
GS_FT_mk_error(GS_FT *ft, void *dst, size_t len, uint32_t id, uint8_t code, const char *str)
{
	size_t n;
	struct _gs_ft_error *hdr = (struct _gs_ft_error *)dst;

	if (len < sizeof *hdr + 1)
		return 0;  // protcol error

	hdr->id = htonl(id);
	hdr->code = code;

	n = MIN(len - sizeof *hdr, strlen(str) + 1);
	// DEBUGF("name len %zu + hdr %zu\n", n, sizeof *hdr);
	memcpy(hdr->str, str, n - 1);
	hdr->str[n] = '\0';

	return sizeof *hdr + n;
}
#endif


/*
 * SERVER
 * Return < 0 on error.
 * Return bytes already here.
 */
int64_t
GS_FT_add_file(GS_FT *ft, uint32_t id, const char *fname, uint32_t umask)
{
	// FIXME: get absolute path and save absolute path

	int ret;
	int64_t fz = 0;
	struct stat res;
	ret = stat(fname, &res);
	if (ret != 0)
	{
		if (errno != ENOENT)
			return -GS_FT_ERR_PERM; // Exists but stat() failed 
	} else {
		// FILE exists
		if (!S_ISREG(res.st_mode))
			return -GS_FT_ERR_BADF; // Not a regular file
		// File is a regular file.
		fz = res.st_size;
	}

	struct _gs_ft_file *f;
	f = calloc(1, sizeof *f);
	f->name = strdup(fname);
	f->umask = umask;
	char buf[PATH_MAX];
	snprintf(buf, sizeof buf, "%s/%s", getcwd(buf, sizeof buf), fname);
	f->realname = strdup(buf);
	f->offset = fz;

	f->li = GS_LIST_add(&ft->fadded, NULL, f, id);

	return fz;
}

/*
 * CLIENT: Add this file to queue.
 */
int
GS_FT_put(GS_FT *ft, const char *fname)
{
	int ret;
	struct stat res;

	// Get absolute and real path as CWD may change before
	// upload starts.
	char *realfname;
	realfname = realpath(fname, NULL);
	if (realfname == NULL)
		return -3;

	ret = stat(fname, &res);
	if (ret != 0)
		return -1;

	if (!S_ISREG(res.st_mode))
		return -2;

	struct _gs_ft_file *f;
	f = calloc(1, sizeof *f);
	f->name = strdup(fname);
	f->realname = realfname;
	f->fsize = res.st_size;
	f->umask = 31337; // FIXME

	f->li = GS_LIST_add(&ft->fqueue, NULL, f, ft->g_id);
	ft->g_id += 1;
	ft->is_put_done = 0;

	return 0;
}

// SERVER
void
GS_FT_data(GS_FT *ft, const void *data, size_t len)
{
	struct _gs_ft_file *f = ft->active_receiving;
	size_t sz;

	if (f == NULL)
	{
		DEBUGF_R("Oops. Receivng data but no active receiving file\n");
		return;
	}

	
	XASSERT(f->fp != NULL, "fp is NULL\n");
	if (f->offset + len > f->fsize)
	{
		DEBUGF_R("Oops. More data than we want!\n");
		len = f->fsize - f->offset;
	}

	sz = fwrite(data, 1, len, f->fp);
	f->offset += sz;

	if (sz != len)
	{
		// FIXME: return error to peer that write has failed...
		goto completed;
	}

	if (f->offset < f->fsize)
		return; // still data missing...

completed:
	ft->active_receiving = NULL;
	ft_del(f->li);
}

// CLIENT
void
GS_FT_accept(GS_FT *ft, uint32_t id, int64_t offset)
{
	GS_LIST_ITEM *li;

	li = GS_LIST_by_id(&ft->fputs, id);
	if (li == NULL)
	{
		DEBUGF_R("Unknown file id %u\n", id);
		return; // actually a protocol error....
	}

	GS_LIST_move(&ft->faccepted, li);

	struct _gs_ft_file *f = (struct _gs_ft_file *)li->data;
	f->offset = offset;
}

// SERVER
void
GS_FT_switch(GS_FT *ft, uint32_t id, int64_t fsize)
{
	GS_LIST_ITEM *li;

	li = GS_LIST_by_id(&ft->freceiving, id);
	if (li == NULL)
	{
		DEBUGF_R("Unknown file id %u\n", id);
		return; // actually a protocol error....
	}

	// Switch from active receiving file to new file
	struct _gs_ft_file *new = (struct _gs_ft_file *)li->data;

	DEBUGF_W("Switching to id %u '%s' (got %"PRId64", want %"PRId64")\n", id, new->name, new->offset, fsize); 

	if ((ft->active_receiving != NULL) && (ft->active_receiving != new))
	{
		fclose(ft->active_receiving->fp);
	}

	ft->active_receiving = NULL;

	// Existing file is larger to fsize send by peer.
	if (new->offset > fsize)
		goto err;

	if (fsize == new->offset)
	{
		DEBUGF_G("file already fully received\n");
		ft_del(li);
		return;
	}

	new->fsize = fsize;
	new->fp = fopen(new->realname, "a");
	// new->fp = fopen(new->realname, "r+");
	if (new->fp == NULL)
	{
		DEBUGF("fopen(%s) failed: %s\n", new->realname, strerror(errno));
		goto err;
	}

	ft->active_receiving = new;
	return;

err:
	// FIXME: Transmit error back to peer.
	// Use a List-queue with error messages (or just 1 error message?)
	ft_del(li);
}
#if 0
/*
 * Remote reported error on this file. Remove from active list.
 */
void
GS_FT_error(GS_FT *ft, uint32_t id)
{
	GS_LIST_ITEM *li;

	li = GS_LIST_by_id(&ft->flist, id);
	if (li == NULL)
		return;
	f = (struct _gs_ft_file *)li->data;

	ft_del(li);

	ft->n_denied += 1;
}
#endif

static void
file_free(struct _gs_ft_file *f)
{
	XFREE(f->name);
	XFREE(f->realname);
	XFREE(f);
}
/*
 * Remove file from queue.
 */
static void
ft_del(GS_LIST_ITEM *li)
{
	struct _gs_ft_file *f = (struct _gs_ft_file *)li->data;

	if (f->fp != NULL)
	{
		fclose(f->fp);
		f->fp = NULL;
	}

	file_free(f);
	GS_LIST_del(li);
}

/*
 * Error received from Server or Client.
 * Remove and free item.
 */
void
GS_FT_del_file(GS_FT *ft, uint32_t id)
{
	GS_LIST_ITEM *li;
	struct _gs_ft_file *f;

	li = GS_LIST_by_id(&ft->fqueue, id);
	if (li == NULL)
	{
		li = GS_LIST_by_id(&ft->fputs, id);
		if (li == NULL)
		{
			li = GS_LIST_by_id(&ft->fadded, id);
			if (li == NULL)
			{
				li = GS_LIST_by_id(&ft->freceiving, id);
				if (li == NULL)
				{
					DEBUGF_R("id %u not found\n", id);
					return; // not found
				}
			}
		}
	}

	f = (struct _gs_ft_file *)li->data;
	if (f == ft->active_put_file)
		ft->active_put_file = NULL;

	file_free(f);
	GS_LIST_del(li);
}


/*
 * Create an error package. Return 0 on error or the length of patcket
 * on success..
 */
static int
mk_error(void *dst, size_t len, uint32_t id, uint8_t code)
{
	struct _gs_ft_error err;

	if (len < sizeof (err) + 1)
	{
		DEBUGF_R("Oops, not enough space?\n");
		return 0;
	}

	memset(&err, 0, sizeof err);
	err.id = htonl(id);
	err.code = code;
	memcpy(dst, &err, sizeof err);
	((uint8_t *)dst)[sizeof err] = '\0';

	return sizeof err + 1; // 0-terminate
}


static int
ft_error(GS_FT *ft, void *dst, size_t len, GS_LIST_ITEM *li, uint8_t code, int *pkt_type)
{
	int ret;

	XASSERT(li != NULL, "Oops. li is NULL\n");
	ret = mk_error(dst, len, li->id, code);
	*pkt_type = GS_FT_TYPE_ERROR;

	ft_del(li);
	if ((ft->fputs.n_items == 0) && (ft->faccepted.n_items == 0))
		ft->is_put_done = 1;

	return ret;
}
/*
 * Create a data packet (from job/queue that need attendtion).
 * Return the length.
 * Return 0 if no data needs to be written or an error occured.
 * check pkt_type to determine the error code.
 *
 * Set TYPE to SWITCH or DATA depending on the type of packet created.
 * Set to DONE when done and NONE when nothing is to be done.
 */
size_t
GS_FT_packet(GS_FT *ft, void *dst, size_t len, int *pkt_type)
{
	struct _gs_ft_file *f;
	size_t sz;

	// DEBUGF("puts %d, accepted %d, done %d\n", ft->fputs.n_items, ft->faccepted.n_items, ft->is_put_done);
	if (ft->is_put_done)
	{
		*pkt_type = GS_FT_TYPE_DONE;
		return 0;
	}

	*pkt_type = GS_FT_TYPE_NONE;

	// Check if any files in the queue that need to be 'put'
	// on offer to the remote side (and then awaiting 'accept').
	if (ft->fqueue.n_items > 0)
	{
		GS_LIST_ITEM *li = NULL;

		DEBUGF("%d items in queue (waiting for put to be send)\n", ft->fqueue.n_items);
		li = GS_LIST_next(&ft->fqueue, NULL);
		f = (struct _gs_ft_file *)li->data;

		struct _gs_ft_put put;
		struct _gs_ft_put *p = (struct _gs_ft_put *)dst;
		memset(&put, 0, sizeof put);
		put.umask = htonl(f->umask);
		put.id = htonl(li->id);
		memcpy(dst, &put, sizeof put);

		sz = MIN(len - sizeof put, strlen(f->name) + 1);
		// DEBUGF("name len %zu + hdr %zu\n", n, sizeof *hdr);
		memcpy(p->name, f->name, sz - 1);
		p->name[sz - 1] = '\0';

		GS_LIST_move(&ft->fputs, li);
		*pkt_type = GS_FT_TYPE_PUT;
		return sizeof put + sz;
	}

	if (ft->fadded.n_items > 0)
	{
		GS_LIST_ITEM *li = NULL;
		li = GS_LIST_next(&ft->fadded, NULL);
		f = (struct _gs_ft_file *)li->data;

		struct _gs_ft_accept acc;
		memset(&acc, 0, sizeof acc);
		acc.id = htonl(li->id);
		acc.offset = htonll(f->offset);
		memcpy(dst, &acc, sizeof acc);
		// HERE: Server. Inform client that we accepted.

		GS_LIST_move(&ft->freceiving, li);
		*pkt_type = GS_FT_TYPE_ACCEPT;
		return sizeof acc;
	}

	if (ft->faccepted.n_items > 0)
	{
		// Here: No files waiting to offer ('put') to remote.
		if (ft->active_put_file == NULL)
		{
			GS_LIST_ITEM *li = NULL;
			int ret;

			// FIXME: find file with least amount of outstanding data
			li = GS_LIST_next(&ft->faccepted, NULL);
			f = (struct _gs_ft_file *)li->data;

			// Open file and seek to location
			f->fp = fopen(f->name, "r");
			if (f->fp == NULL)
				return ft_error(ft, dst, len, f->li, GS_FT_ERR_PERM, pkt_type);

			ret = fseek(f->fp, 0, SEEK_END);
			if (ret != 0)
				return ft_error(ft, dst, len, f->li, GS_FT_ERR_BADF, pkt_type);
			f->fsize = ftell(f->fp);
			// Peer already has all data (or more).
			if (f->fsize <= f->offset)
				return ft_error(ft, dst, len, f->li, GS_FT_ERR_NODATA, pkt_type);

			ret = fseek(f->fp, f->offset, SEEK_SET);
			if (ret != 0)
				return ft_error(ft, dst, len, f->li, GS_FT_ERR_BADF, pkt_type);

			struct _gs_ft_switch sw;
			memset(&sw, 0, sizeof sw);
			sw.id = htonl(li->id);
			sw.fsize = htonll(f->fsize);
			memcpy(dst, &sw, sizeof sw);

			ft->active_put_file = f;
			*pkt_type = GS_FT_TYPE_SWITCH;

			return (sizeof sw);
		}

		// HERE: active file 
		*pkt_type = GS_FT_TYPE_DATA;
		f = ft->active_put_file;

		DEBUGF_C("at %ld\n", ftell(f->fp));
		sz = fread(dst, 1, len, f->fp);
		if (sz <= 0)
		{
			// HERE: Read error or file may have shrunk.
			ft->active_put_file = NULL;
			return ft_error(ft, dst, len, f->li, GS_FT_ERR_BADF, pkt_type);
		}
		f->offset += sz;

		// File completed. No more data.
		if (f->offset >= f->fsize)
		{
			ft_del(f->li);
			if ((ft->fputs.n_items == 0) && (ft->faccepted.n_items == 0))
				ft->is_put_done = 1;
			ft->active_put_file = NULL;
		}
		return sz;
	}

	return 0;
}

static void
free_gsl(GS_LIST *gsl)
{
	GS_LIST_ITEM *li = GS_LIST_next(gsl, NULL);

	for (; li != NULL; li = GS_LIST_next(gsl, li))
	{
		struct _gs_ft_file *f = (struct _gs_ft_file *)li->data;

		file_free(f);
		GS_LIST_del(li);
	}
}

void
GS_FT_free(GS_FT *ft)
{
	free_gsl(&ft->fqueue);
	free_gsl(&ft->fputs);
	free_gsl(&ft->faccepted);

	free_gsl(&ft->fadded);
	free_gsl(&ft->freceiving);

	ft->active_put_file = NULL;
}




