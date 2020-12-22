
#include "common.h"
#include "utils.h"
#include "filetransfer.h"

static void ft_del(GS_LIST_ITEM *li);
static void qerr_add(GS_FT *ft, uint32_t id, uint8_t code, const char *str);
static void mk_stats_total(GS_FT *ft);
static mode_t GS_fperm2mode(uint32_t u);
static uint32_t GS_mode2fperm(mode_t m);


#if 0
0 FIXME: must make sure that server cant request transfer from client!
- test when file becomes unavaialble after it was added.
- Sym Link
- max buffer size 64 macro somewhere needed
- queue up all 'put' requests and send as 1 large message or loop around write() while we can.
- What do we do if a pathname/filename does not fit into wbuf? Filename can be rather long (like 4k?)
  and larger than channel buffer
  (add files until it does not fit. Return to caller the ID that failed and let caller decide
  if he likes to remove that ID from our list or just let caller try again until it fits...)
  is there a limt?
- retain fperm/mtime on directories
- empty directories



- implement GS_FT_get()

TEST CASES:
1. pathname + filename 4096 long
#2. dest file not writeable
#3. re-start transmission
4. same file in command line
5. src file can not be opened or read error.
6. write to symlink
#7. zero file size
#8. retain timestamp
#endif

void
GS_FT_init(GS_FT *ft, gsft_cb_stats_t func_stats, gsft_cb_status_t func_status)
{
	memset(ft, 0, sizeof *ft);
	GS_LIST_init(&ft->fqueue, 0);
	GS_LIST_init(&ft->fputs, 0);
	GS_LIST_init(&ft->faccepted, 0);
	GS_LIST_init(&ft->fcompleted, 0);

	GS_LIST_init(&ft->fadded, 0);
	GS_LIST_init(&ft->freceiving, 0);

	GS_LIST_init(&ft->qerrs, 0);

	ft->func_stats = func_stats;
	ft->func_status = func_status;
}

/*
 * SERVER
 * Return < 0 on error.
 * Return 0 otherwise.
 */
int
GS_FT_add_file(GS_FT *ft, uint32_t id, const char *fname, size_t len, int64_t fsize, uint32_t mtime, uint32_t fperm)
{
	int ret;
	int64_t fz = 0;

	if (fname[len] != '\0')
		return -1; // protocol error. Not 0 terminated.

	// FIXME: sanitize file name
	DEBUGF_Y("#%u ADD-FILE - fperm 0%o, '%s'\n", id, fperm, fname);

	struct stat res;
	ret = stat(fname, &res);

	if (ret != 0)
	{
		if (errno != ENOENT)
		{
			qerr_add(ft, id, GS_FT_ERR_PERM, NULL);
			return -GS_FT_ERR_PERM; // Exists but stat() failed 
		}
	} else {
		// FILE exists
		if (!S_ISREG(res.st_mode))
		{
			qerr_add(ft, id, GS_FT_ERR_BADF, NULL);
			return -GS_FT_ERR_BADF; // Not a regular file
		}
		// File is a regular file.
		fz = res.st_size;
	}

	struct _gs_ft_file *f;
	f = calloc(1, sizeof *f);
	f->name = strdup(fname);
	f->mode = GS_fperm2mode(fperm);
	f->mtime = mtime;
	f->fsize = fsize;
	char buf[PATH_MAX];
	snprintf(buf, sizeof buf, "%s/%s", getcwd(buf, sizeof buf), fname);
	f->realname = strdup(buf);
	f->offset = fz;

	f->li = GS_LIST_add(&ft->fadded, NULL, f, id);

	return 0;
}


struct _mperm
{
	mode_t mode;
	uint32_t perm;
};

struct _mperm x_mperm[] = {
	{S_ISUID, 04000},
	{S_ISGID, 02000},
	{S_ISVTX, 01000},

	{S_IRUSR, 00400},
	{S_IWUSR, 00200},
	{S_IXUSR, 00100},

	{S_IRGRP, 00040},
	{S_IWGRP, 00020},
	{S_IXGRP, 00010},

	{S_IROTH, 00004},
	{S_IWOTH, 00002},
	{S_IXOTH, 00001}
};

// Host to network byte order for st_mode file permission
static uint32_t
GS_mode2fperm(mode_t m)
{
	uint32_t u = 0;
	int n;

	m &= ~S_IFMT;
	for (n = 0; n < sizeof x_mperm / sizeof *x_mperm; n++)
	{
		if (m & x_mperm[n].mode)
			u |= x_mperm[n].perm;
	}

	DEBUGF_B("mode2fperm 0%o\n", u);
	return u;
}

// Network to host byte order for st_mode file permission
static mode_t
GS_fperm2mode(uint32_t u)
{
	mode_t m = 0;
	int n;

	DEBUGF_B("fperm2mode 0%o\n", u);

	for (n = 0; n < sizeof x_mperm / sizeof *x_mperm; n++)
	{
		if (u & x_mperm[n].perm)
			m |= x_mperm[n].mode;
	}

	return m;
}
/*
 * CLIENT: Add this file (not directory) to queue.
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

	/*
	 * Consider these possibilities (examples)
	 * /tmp/foo/bar/hosts
	 * /./tmp/foo/bar/hosts
	 * /tmp/foo/./bar/./hosts
	 * /tmp/./foo/bar/hosts
	 * hosts
	 * foo/bar/host
	 */
	// Find token after last occurance of '/./'
	const char *str = fname;
	char *token;
	int found = 0;
	while (1)
	{
		token = strstr(str, "/./");
		if (token == NULL)
			break;
		found = 1;
		str = token + 3; // skip '/./'
	}
	// str contains everything after '/./' or fname if '/./' not found.
	if (found == 0)
	{
		// HERE: No '/./'. Use basename (file only, no directory part)
		char *s = strdup(fname); // basename() might modify str :/
		f->name = strdup(basename(s));
		free(s);
	} else {
		f->name = strdup(str);
	}

	f->realname = realfname;
	f->fsize = res.st_size;
	f->mode = res.st_mode;
	f->mtime = res.st_mtime;

	// DEBUGF_Y("mode = %o\n", res.st_mode & ~S_IFMT);
	DEBUGF_Y("#%u name = %s\n", ft->g_id, f->name);
	f->li = GS_LIST_add(&ft->fqueue, NULL, f, ft->g_id);
	ft->g_id += 1;

	ft->n_files_waiting += 1;

	return 0;
}


static void
qerr_add(GS_FT *ft, uint32_t id, uint8_t code, const char *str)
{
	struct _gs_ft_qerr *qerr;

	qerr = calloc(1, sizeof *qerr);
	qerr->id = id;
	qerr->code = code;
	qerr->str = NULL;
	if (str != NULL)
		qerr->str = strdup(str);

	// Must add in sequence of occurance (add_count)
	GS_LIST_add(&ft->qerrs, NULL, qerr, ft->qerrs.add_count);
}

static void
do_error(GS_FT *ft, GS_LIST_ITEM *li, uint32_t code, const char *str)
{
	qerr_add(ft, li->id, code, str);
	ft_del(li);
}

static void
do_complete(GS_FT *ft, struct _gs_ft_file *f)
{
	if (f->fp != NULL)
	{
		fflush(f->fp);
		fchmod(fileno(f->fp), f->mode & ~S_IFMT);
		if (f->mtime != 0)
		{
			DEBUGF_B("Setting time to %ld\n", f->mtime);
			struct timeval t[] = {{f->mtime, 0}, {f->mtime, 0}};
			futimes(fileno(f->fp), t);
		}
	}
	do_error(ft, f->li, GS_FT_ERR_COMPLETED, NULL);
}

static void
qerr_free(struct _gs_ft_qerr *qerr)
{
	XFREE(qerr->str);
	XFREE(qerr);
}

// SERVER
void
GS_FT_data(GS_FT *ft, const void *data, size_t len)
{
	struct _gs_ft_file *f = ft->active_receiving;
	size_t sz;

	if (f == NULL)
	{
		DEBUGF_R("Receiving data but no active receiving file\n");
		return;
	}
	
	XASSERT(f->fp != NULL, "fp is NULL\n");
	if (f->offset + len > f->fsize)
	{
		DEBUGF_R("More data than we want!\n");
		len = f->fsize - f->offset;
	}

	sz = fwrite(data, 1, len, f->fp);
	f->offset += sz;

	if (sz != len)
	{
		do_error(ft, f->li, GS_FT_ERR_BADF, NULL);
		ft->active_receiving = NULL;
		return;
	}

	if (f->offset < f->fsize)
		return; // still data missing...

	DEBUGF_B("Server: All data received (%"PRIu64" of %"PRIu64")\n", f->offset, f->fsize);
	do_complete(ft, f); 
	ft->active_receiving = NULL;
}

// CLIENT
void
GS_FT_accept(GS_FT *ft, uint32_t id, int64_t offset_dst)
{
	GS_LIST_ITEM *li;

	DEBUGF("#%u acc offset_dst = %"PRId64"\n", id, offset_dst);

	li = GS_LIST_by_id(&ft->fputs, id);
	if (li == NULL)
	{
		DEBUGF_R("Unknown file id %u\n", id);
		return; // actually a protocol error....
	}

	GS_LIST_move(&ft->faccepted, li);

	struct _gs_ft_file *f = (struct _gs_ft_file *)li->data;
	f->offset = offset_dst;
}

/*
 * Create all directories up to file
 * /tmp/foo/bar/test.dat would create /tmp/foo/bar/
 * /tmp/foo/bar/test.dat/ would create /tmp/foo/bar/test.dat/
 */
static void
mkdirp(const char *file)
{
	char *f = strdup(file);

	char *ptr = f;
	while (1)
	{
		ptr = index(ptr, '/');
		if (ptr == NULL)
			break;
		*ptr = '\0';
		if (*f != 0)
		{
			DEBUGF_W("mkdir(%s)\n", f);
			mkdir(f, 0755);
		}
		*ptr = '/';
		ptr += 1;
	}

	free(f);
}

// SERVER
void
GS_FT_switch(GS_FT *ft, uint32_t id, int64_t offset)
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

	DEBUGF_W("Switching to id %u '%s' (got %"PRId64", want %"PRId64")\n", id, new->name, new->offset, new->fsize); 

	if ((ft->active_receiving != NULL) && (ft->active_receiving != new))
	{
		fclose(ft->active_receiving->fp);
	}

	ft->active_receiving = NULL;

	// Server: Existing file is larger. Overwrite.
	if (new->offset > new->fsize)
	{
		DEBUGF_W("File larger. Overwritting...\n");
		XASSERT(offset == 0, "OFFSET not 0 but server's file is larger\n");
		new->offset = 0;
		offset = 0;
	}

	if ((new->offset == new->fsize) && (new->fsize != 0))
	{
		// FIXME: currently _not_ updating mtime/fperm if file is already on peer side.
		// Do we want this? (if so then move this code block after fopen().)
		do_complete(ft, new);
		return;
	}

	// new->fsize = fsize;
	if (offset == 0)
	{
		DEBUGF_G("New file (%s)\n", new->name);
		mkdirp(new->name);
		new->fp = fopen(new->realname, "w");
	} else {
		// Check fsize of local file.
		DEBUGF_G("Appending file\n");
		struct stat res;
		if (stat(new->realname, &res) != 0)
			goto err;
		if (res.st_size != offset)
		{
			// Size changed
			do_error(ft, new->li, GS_FT_ERR_BADFSIZE, NULL);
			return;
		}
		new->fp = fopen(new->realname, "a");
	}

	if (new->fp == NULL)
	{
		DEBUGF("fopen(%s) failed: %s\n", new->realname, strerror(errno));
		goto err;
	}

	if (new->fsize == 0)
	{
		// Zero sized file. Completed.
		do_complete(ft, new);
		return;
	}

	ft->active_receiving = new;
	return;

err:
	do_error(ft, new->li, GS_FT_ERR_PERM, NULL);
}

static void
file_free(struct _gs_ft_file *f)
{
	XFREE(f->name);
	XFREE(f->realname);
	XFREE(f);
}

// Reduce counter of outstanding files/errors.
static void
ft_done(GS_FT *ft)
{
	if (ft->n_files_waiting > 0)
		ft->n_files_waiting -= 1;
	else
		DEBUGF_R("Oops, n_files_waiting == %d\n", ft->n_files_waiting);
}

/*
 * Remove file from queue.
 */
static void
ft_del(GS_LIST_ITEM *li)
{
	struct _gs_ft_file *f = (struct _gs_ft_file *)li->data;

	XFCLOSE(f->fp);

	file_free(f);
	GS_LIST_del(li);
}

// Human readable bps string
static void
mk_bps(char *str, size_t sz, uint64_t duration, uint64_t amount, int err)
{
	if (err != 0)
	{
		snprintf(str, sz, "ERROR");
		return;
	}
	if (duration > 0)
		GS_format_bps(str, sz, (amount * 1000000 / duration));
	else
		snprintf(str, sz, "SKIPPED");
}

// Generate stats per file and call call-back.
static void
mk_stats(GS_FT *ft, uint32_t id, struct _gs_ft_file *f, int err)
{
	struct _gs_ft_stats s;

	memset(&s, 0, sizeof s);
	s.id = id;
	s.f = f;
	s.xfer_amount = f->xfer_amount;
	if (f->usec_start > f->usec_end)
		f->usec_end = GS_usec();

	if (f->usec_suspend_start != 0)
	{
		DEBUGF_R("Oops, Reporting stats on a suspended file\n");
		f->usec_suspend_duration += (GS_usec() - f->usec_suspend_start);
	}

	s.xfer_duration = (f->usec_end - f->usec_start) - f->usec_suspend_duration;
	mk_bps(s.speed_str, sizeof s.speed_str, s.xfer_duration, f->xfer_amount, err);

	// Global stats for all files
	ft->stats_total.xfer_duration += s.xfer_duration;
	ft->stats_total.xfer_amount += f->xfer_amount;
	if (err == 0)
		ft->stats_total.n_files_success += 1;
	else 
		ft->stats_total.n_files_error += 1;
	mk_stats_total(ft);

	// Call call-back
	if (ft->func_stats != NULL)
		(*ft->func_stats)(&s);
}

// Generate total stats
static void
mk_stats_total(GS_FT *ft)
{
	GS_FT_stats_total *st = &ft->stats_total;

	mk_bps(st->speed_str, sizeof st->speed_str, st->xfer_duration, st->xfer_amount, st->n_files_success==0?1:0);
}

/*
 * Error received from Server or Client.
 * Remove and free item.
 */
void
GS_FT_status(GS_FT *ft, uint32_t id, uint8_t code, const char *err_str, size_t len)
{
	GS_LIST_ITEM *li;
	int err = 1;

	if (err_str[len] != '\0')
		return; // protocol error. Not 0 terminated.
	DEBUGF_R("#%u STATUS: %u (%s)\n", id, code, err_str);

	li = GS_LIST_by_id(&ft->fcompleted, id);
	if (li == NULL)
	{
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
	} else {
		// Was waiting for 'complete' signal. No error if 'complete' is a success.
		if (code == GS_FT_ERR_COMPLETED)
			err = 0;
	}

	// Make status
	struct _gs_ft_status s;
	memset(&s, 0, sizeof s);
	s.code = code;
	s.file = li->data;
	// FIXME: sanitize error string
	snprintf(s.err_str, sizeof s.err_str, "%s", err_str);
	if (ft->func_stats != NULL)
		(*ft->func_status)(ft, &s);

	// Report stats to caller
	mk_stats(ft, id, li->data, err);

	if (li->data == ft->active_put_file)
		ft->active_put_file = NULL;

	ft_done(ft);
	ft_del(li);
}

/*
 * Make an error packet. Return length.
 */
static size_t
mk_error(void *dst, size_t len, uint32_t id, uint8_t code, const char *str)
{
	size_t sz;
	struct _gs_ft_error err;

	memset(&err, 0, sizeof err);
	err.id = htonl(id);
	err.code = code;
	memcpy(dst, &err, sizeof err);

	sz = 1;
	struct _gs_ft_error *p = (struct _gs_ft_error *)dst;
	if ((str != NULL) && (strlen(str) > 0))
	{
		sz = MIN(len - sizeof err, strlen(str) + 1);
		memcpy(p->str, str, sz - 1);
	}
	p->str[sz - 1] = '\0';

	return sizeof err + sz;
}

/*
 * Make an error packet. Remove errornous file from queue
 */
static size_t
ft_mk_error(GS_FT *ft, void *dst, size_t len, int *pkt_type, GS_LIST_ITEM *li, uint8_t code, const char *str)
{
	size_t sz;

	*pkt_type = GS_FT_TYPE_ERROR;
	sz = mk_error(dst, len, li->id, code, str);

	ft_done(ft);
	ft_del(li);

	return sz;
}

/*
 * Create a data packet (from job/queue that need attention).
 * Return the length.
 * Return 0 if no data needs to be written or an error occured.
 * check pkt_type to for packet code that needs to be written.
 *
 * Set TYPE to SWITCH or DATA depending on the type of packet created.
 * Set to DONE when done and NONE when nothing is to be done.
 */
size_t
GS_FT_packet(GS_FT *ft, void *dst, size_t len, int *pkt_type)
{
	struct _gs_ft_file *f;
	size_t sz;

	DEBUGF("GS_FT_packet() %d, accepted %d, len %zu\n", ft->fputs.n_items, ft->faccepted.n_items, len);

	*pkt_type = GS_FT_TYPE_NONE;
	if (len < GS_FT_MIN_BUF_SIZE)
	{
		return 0;
	}
	// XASSERT(len >= GS_FT_MIN_BUF_SIZE, "len to small\n");

	// Check if any queue'd errors needs sending.
	// Server & Client
	if (ft->qerrs.n_items > 0)
	{
		GS_LIST_ITEM *li = NULL;
		li = GS_LIST_next(&ft->qerrs, NULL);
		struct _gs_ft_qerr *qerr = (struct _gs_ft_qerr *)li->data;

		sz = mk_error(dst, len, qerr->id, qerr->code, qerr->str);

		*pkt_type = GS_FT_TYPE_ERROR;
		GS_LIST_del(li);
		return sz;
		// return sizeof err + sz;
	}

	// Check if any files in the queue that need to be 'put'
	// on offer to the remote side (and then awaiting 'accept').
	// Client
	if (ft->fqueue.n_items > 0)
	{
		DEBUGF("%d items in queue (waiting for put to be send)\n", ft->fqueue.n_items);
		GS_LIST_ITEM *li = NULL;
		li = GS_LIST_next(&ft->fqueue, NULL);
		f = (struct _gs_ft_file *)li->data;

		struct _gs_ft_put put;
		struct _gs_ft_put *p = (struct _gs_ft_put *)dst;
		memset(&put, 0, sizeof put);
		put.fperm = htonl(GS_mode2fperm(f->mode));
		put.id = htonl(li->id);
		put.fsize = htonll(f->fsize);
		put.mtime = htonl(f->mtime);
		memcpy(dst, &put, sizeof put);

		sz = MIN(len - sizeof put, strlen(f->name) + 1);
		// DEBUGF("name len %zu + hdr %zu\n", n, sizeof *hdr);
		memcpy(p->name, f->name, sz - 1);
		p->name[sz - 1] = '\0';

		GS_LIST_move(&ft->fputs, li);
		*pkt_type = GS_FT_TYPE_PUT;
		return sizeof put + sz;
	}

	// Server
	if (ft->fadded.n_items > 0)
	{
		GS_LIST_ITEM *li = NULL;
		li = GS_LIST_next(&ft->fadded, NULL);
		f = (struct _gs_ft_file *)li->data;

		struct _gs_ft_accept acc;
		memset(&acc, 0, sizeof acc);
		acc.id = htonl(li->id);
		acc.offset_dst = htonll(f->offset);
		memcpy(dst, &acc, sizeof acc);
		// HERE: Server. Inform client that we accepted.

		GS_LIST_move(&ft->freceiving, li);
		*pkt_type = GS_FT_TYPE_ACCEPT;
		return sizeof acc;
	}

	// Client
	if (ft->faccepted.n_items > 0)
	{
		if (ft->active_put_file == NULL)
		{
			// HERE: Currently not transmitting any file data => Select new file.
			GS_LIST_ITEM *li = NULL;
			int ret;

			// FIXME: find file with least amount of outstanding data
			li = GS_LIST_next(&ft->faccepted, NULL);
			f = (struct _gs_ft_file *)li->data;

			// Open file and seek to location
			f->fp = fopen(f->realname, "r");
			if (f->fp == NULL)
				return ft_mk_error(ft, dst, len, pkt_type, li, GS_FT_ERR_PERM, NULL);

			ret = fseek(f->fp, 0, SEEK_END);
			if (ret != 0)
				return ft_mk_error(ft, dst, len, pkt_type, li, GS_FT_ERR_BADF, NULL);
			f->fsize = ftell(f->fp);

			// Peer already has this file.
			// Overwrite if remote size is smaller _or_ larger.
			// f->fsize == local size, f->offset == remote size
			if ((f->fsize == f->offset) && (f->fsize != 0))
			{
				DEBUGF("#%u Skipping %s (already on peer)\n", (unsigned int)f->li->id, f->name);
				mk_stats(ft, li->id, f, 0 /*success*/);
				return ft_mk_error(ft, dst, len, pkt_type, li, GS_FT_ERR_NODATA, NULL);
			}

			// Remote size is larger. Overwrite from beginning.
			if (f->fsize < f->offset)
				f->offset = 0;

			// Remote size is smaller. Restart transmission.
			ret = fseek(f->fp, f->offset, SEEK_SET);
			if (ret != 0)
				return ft_mk_error(ft, dst, len, pkt_type, li, GS_FT_ERR_BADF, NULL);

			struct _gs_ft_switch sw;
			memset(&sw, 0, sizeof sw);
			sw.id = htonl(li->id);
			sw.offset = htonll(f->offset);
			memcpy(dst, &sw, sizeof sw);

			// Handle zero size files
			if (f->fsize == 0)
			{
				GS_LIST_move(&ft->fcompleted, f->li);
				ft->active_put_file = NULL;
			} else {
				// HERE: fsize is not zero.
				ft->active_put_file = f;
			}

			*pkt_type = GS_FT_TYPE_SWITCH;

			return (sizeof sw);
		}

		// HERE: active file 
		*pkt_type = GS_FT_TYPE_DATA;
		f = ft->active_put_file;

		sz = fread(dst, 1, len, f->fp);

		if (sz <= 0)
		{
			// HERE: Read error or file may have shrunk.
			ft->active_put_file = NULL;
			return ft_mk_error(ft, dst, len, pkt_type, f->li, GS_FT_ERR_BADF, NULL);
		}
		f->offset += sz;

		// -----BEGIN Log statistics-----
		if (f->usec_start == 0)
		{
			f->usec_start = GS_usec();
		}

		if (f->usec_suspend_start != 0)
		{
			f->usec_suspend_duration += (GS_usec() - f->usec_suspend_start);
			f->usec_suspend_start = 0;
		}
		f->xfer_amount += sz;
		// -----END Log statistics-----

		// File completed. No more data.
		if (f->offset >= f->fsize)
		{
			GS_LIST_move(&ft->fcompleted, f->li);
			ft->active_put_file = NULL;
		}
		return sz;
	}

	if (ft->n_files_waiting == 0)
	{
		*pkt_type = GS_FT_TYPE_DONE;
		return 0;
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
	free_gsl(&ft->fcompleted);

	free_gsl(&ft->fadded);
	free_gsl(&ft->freceiving);

	GS_LIST_ITEM *li;
	for (li = GS_LIST_next(&ft->qerrs, NULL); li != NULL; li = GS_LIST_next(&ft->qerrs, li))
	{
		qerr_free((struct _gs_ft_qerr *)li->data);

		GS_LIST_del(li);
	}

	ft->active_put_file = NULL;
}




