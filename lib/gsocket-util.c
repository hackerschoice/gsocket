
#include "gs-common.h"
#include <gsocket/gsocket.h>
#include "gsocket-engine.h"
#include "gs-externs.h"

static const char       b58digits_ordered[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
// static const int8_t b58digits_map[] = {
// 	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
// 	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
// 	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
// 	-1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
// 	-1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
// 	22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
// 	-1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
// 	47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
// };

#ifndef HAVE_GETLINE
static int
getline(char **lineptr, size_t *n, FILE *stream)
{
	static char line[256];
	char *ptr;
	unsigned int len;

   if (lineptr == NULL || n == NULL)
   {
      errno = EINVAL;
      return -1;
   }

   if (ferror (stream))
      return -1;

   if (feof(stream))
      return -1;
     
   fgets(line,256,stream);

   ptr = strchr(line,'\n');   
   if (ptr)
      *ptr = '\0';

   len = strlen(line);
   
   if ((len+1) < 256)
   {
      ptr = realloc(*lineptr, 256);
      if (ptr == NULL)
         return(-1);
      *lineptr = ptr;
      *n = 256;
   }

   strcpy(*lineptr,line); 
   return(len);
}
#endif	/* HAVE_GETLINE */

static char *
user_secret_from_stdin(GS_CTX *ctx)
{
	size_t n = 0;
	char *ptr = NULL;
	ssize_t len;

	while (1)
	{
		fprintf(stderr, "Enter Secret (or press Enter to generate): ");
		len = getline(&ptr, &n, stdin);
		XASSERT(len > 0, "getline()\n");
		if (ptr[len - 1] == '\n')
			ptr[len - 1] = 0;	// Remove '\n' 
		if (strlen(ptr) == 0)
			return NULL;
		if (strlen(ptr) >= 8)
			break;
		fprintf(stderr, "Too short.\n");
	}

	return strdup(ptr);
}


static char *
user_secret_from_file(GS_CTX *ctx, const char *file)
{
	FILE *fp;
	char buf[256];
	int ret;

	if (file == NULL)
		return NULL;

	memset(buf, 0, sizeof buf);
	fp = fopen(file, "r");
	if (fp == NULL)
	{
		gs_ctx_set_errorf(ctx, "'%s'", file);
		return NULL;
	}

	ret = fread(buf, 1, sizeof buf - 1, fp);
	fclose(fp);

	if (ret <= 0)
		return NULL;
	if (buf[ret-1] == '\n')
		buf[ret-1] = 0;

	return strdup(buf);
}

char *
GS_getenv(const char *name)
{
	char *ptr = getenv(name);
	if (ptr == NULL)
		return NULL;
	if (*ptr == '\0')
		return NULL;

	return ptr;
}

uint32_t
GS_hton(const char *hostname)
{
	struct hostent *he;
	struct in_addr **addr_list;

	uint32_t ip;
	/* Check if the string is an IP addres "1.2.3.4" */
	ip = inet_addr(hostname);
	if (ip != 0xFFFFFFFF)
		return ip;

	he = gethostbyname(hostname);
	if (he == NULL)
		return 0xFFFFFFFF;

	addr_list = (struct in_addr **)he->h_addr_list;
	if (addr_list == NULL)
		return 0xFFFFFFFF;
	if (addr_list[0] == NULL)
		return 0xFFFFFFFF;

	return addr_list[0][0].s_addr;
}

const char *
GS_gen_secret(void)
{
	int ret;

	GS_library_init(stderr, stderr, NULL);

	// Generate random numbers
	uint8_t buf[GS_SECRET_MAX_LEN];
	ret = RAND_bytes(buf, sizeof buf);
	XASSERT(ret == 1, "RAND_bytes() failed.\n");

	char b58[sizeof buf * 2];
	size_t b58sz = sizeof (b58);
	GS_bin2b58(b58, &b58sz, buf, sizeof buf);
	b58[22] = '\0'; // shorten secret to 21 characters

	return strdup(b58);
}

const char *
GS_user_secret(GS_CTX *ctx, const char *sec_file, const char *sec_str)
{
	const char *ptr;

	/* Secret from file has priority of sec_str value */
	if (sec_file != NULL)
	{
		ptr = user_secret_from_file(ctx, sec_file);
		if (ptr != NULL)
			return ptr;
		return NULL;
	}

	/* If sec_str is set by command line parameters then use it */
	if (sec_str != NULL)
		return sec_str;

	/* Ask user to enter a secret or if empty generate one */
	ptr = user_secret_from_stdin(ctx);
	if (ptr != NULL)
		return ptr;

	/* Genexrate a new secret */
	ptr = GS_gen_secret();

	return ptr;
}


/* Convert 128 bit binary into base58 + CRC
 */
static int
b58enc(char *b58, size_t *b58sz, uint8_t *src, size_t binsz)
{
    const uint8_t *bin = src;
    int carry;
    size_t i, j, high, zcount = 0;
    size_t size;

    /* Find out the length. Count leading 0's. */
    while (zcount < binsz && !bin[zcount])
            ++zcount;

    size = (binsz - zcount) * 138 / 100 + 1;
    uint8_t buf[size];
    memset(buf, 0, size);

    for (i = zcount, high = size - 1; i < binsz; ++i, high = j)
    {
            for (carry = bin[i], j = size - 1; (j > high) || carry; --j)
            {
                    carry += 256 * buf[j];
                    buf[j] = carry % 58;
                    carry /= 58;
                    if (!j)
                    {
                            break;
                    }
            }
    }

    for (j = 0; j < size && !buf[j]; ++j);

    if (*b58sz <= zcount + size - j)
    {
            ERREXIT("Wrong size...%zu\n", zcount + size - j + 1);
            *b58sz = zcount + size - j + 1;
            return -1;
    }
    if (zcount)
    	memset(b58, '1', zcount);

    for (i = zcount; j < size; ++i, ++j)
    {
            b58[i] = b58digits_ordered[buf[j]];
    }
    b58[i] = '\0';
    *b58sz = i + 1;

	return 0;
}

char *
GS_bin2b58(char *b58, size_t *b58sz, uint8_t *src, size_t binsz)
{
	b58enc(b58, b58sz, src, binsz);

	return b58;
}

// 0-Terminate 'dst'.
static char *
bin2hex(char *dst, size_t dsz, const void *src, size_t sz, char *hexset)
{
	char *end = dst + dsz;
	char *dst_orig = dst;
	uint8_t *s = (uint8_t *)src;
	uint8_t *e = s + sz;

	while ((dst + 1 < end) && (s < e))
	{
		*dst = hexset[*s >> 4];
		dst += 1;
		if (dst + 1 >= end)
			break;
		*dst = hexset[*s & 0x0f];
		dst += 1;
		s++;
	}
	*dst = '\0';

	return dst_orig;
}

char *
GS_bin2hex(char *dst, size_t dsz, const void *src, size_t sz)
{
	return bin2hex(dst, dsz, src, sz, "0123456789abcdef");
}

char *
GS_bin2HEX(char *dst, size_t dsz, const void *src, size_t sz)
{
	return bin2hex(dst, dsz, src, sz, "0123456789ABCDEF");
}

char *
GS_addr2hex(char *dst, const void *src)
{
	if (dst == NULL)
	{
		static char dst_local[GS_ADDR_SIZE * 2 + 1];
		dst = dst_local;
	}

	return GS_bin2hex(dst, GS_ADDR_SIZE * 2 + 1, src, GS_ADDR_SIZE);
}

char *
GS_token2hex(char *dst, const void *src)
{
	if (dst == NULL)
	{
		static char dst_local[GS_TOKEN_SIZE * 2 + 1];
		dst = dst_local;
	}

	return GS_bin2hex(dst, GS_TOKEN_SIZE * 2 + 1, src, GS_TOKEN_SIZE);
}

#define GS_SRP_KD1   "/kd/srp/1"
#define GS_ADDR_KD2  "/kd/addr/2"

// Convert a secret to a SRP secret and address.
GS_ADDR *
GS_ADDR_sec2addr(GS_ADDR *addr, const char *gs_secret)
{
	unsigned char md[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha;

	// Derive a SRP Secret (from gs_secret)
	SHA256_Init(&sha);
	SHA256_Update(&sha, GS_SRP_KD1, strlen(GS_SRP_KD1));
	SHA256_Update(&sha, gs_secret, strlen(gs_secret));
	SHA256_Final(md, &sha);
	// Convert to hex string
	GS_bin2hex(addr->srp_password, sizeof addr->srp_password, md, sizeof md);

	// Derive the GS address
	SHA256_Init(&sha);
	SHA256_Update(&sha, GS_ADDR_KD2, strlen(GS_ADDR_KD2));
	SHA256_Update(&sha, gs_secret, strlen(gs_secret));
	SHA256_Final(md, &sha);

	memcpy(addr->addr, md, sizeof addr->addr);

	return addr;
}

// Return 0..25 to connect to [a-z].gsocket.org
uint8_t
GS_ADDR_get_hostname_id(uint8_t *addr)
{
	int i;
	int num = 0;
	for (i = 0; i < GS_ADDR_SIZE; i++)
		num += addr[i];

	return num % 26;
}

uint64_t
GS_usec(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return GS_TV_TO_USEC(&tv);
}

// 7 readable characters + suffix + 0
static const char unit[] = "BKMGT";
void
GS_format_bps(char *dst, size_t size, int64_t bytes, const char *suffix)
{
	int i;

	if (suffix == NULL)
		suffix = "";

	if (bytes < 1000)
	{
		snprintf(dst, size, "%3d.0 B%s", (int)bytes, suffix);
		return;
	}
	bytes *= 100;

	for (i = 0; bytes >= 100*1000 && unit[i] != 'T'; i++)
		bytes = (bytes + 512) / 1024;
	snprintf(dst, size, "%3lld.%1lld%c%s%s",
            (long long) (bytes + 5) / 100,
            (long long) (bytes + 5) / 10 % 10,
            unit[i],
            i ? "B" : " ", suffix);
}

// Convert 'sec' to human readable string
// 99s
// 1m40   100
// 99m59  5999
// 1h40   6000
// 99h59  359940
// 4d04   360000
// 99d23  8636400
// 100d   8640000
// MAX LENGTH IS 7 chars including 0-termination.
char *
GS_format_since(char *dst, size_t dst_sz, int32_t sec)
{
	if (sec >= 100 * 24 * 60 * 60) // 100 days or more 
		snprintf(dst, dst_sz, "%ud", sec / (24 * 60 * 60));
	else if (sec >= 100 * 60 * 60) // 100 hours or more => 4d00
		snprintf(dst, dst_sz, "%ud%02uh", sec / (24 * 60 * 60) /*days*/, (sec / (60 * 60)) % 24);
	else if (sec >= 100 * 60) // 100 minutes or more => 1h40
		snprintf(dst, dst_sz, "%uh%02um", sec / (60 * 60), (sec / 60) % 60);
	else if (sec >= 100) // 100 seconts or more => 1m40
		snprintf(dst, dst_sz, "%um%02us", sec / 60, sec % 60);
	else
		snprintf(dst, dst_sz, "%us", MAX(0, sec));

	return dst;
}

// Get Working Directory of process with id pid or if this fails then current cwd
// of this process.
char *
GS_getpidwd(pid_t pid)
{
	char *wd = NULL;

	if (pid <= 0)
		goto err;

#if defined(__APPLE__) && defined(HAVE_LIBPROC_H)
	// OSX (and others?)
	int ret;
	struct proc_vnodepathinfo vpi;
	ret = proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &vpi, sizeof vpi);
	if (ret <= 0)
		goto err;

	wd = strdup(vpi.pvi_cdir.vip_path);
#elif __FREEBSD__
	struct procstat *procstat;
	struct kinfo_proc *kipp;
	struct filestat_list *head;
	struct filestat *fst;
	unsigned int cnt;

	procstat = procstat_open_sysctl();
	if (procstat == NULL)
		goto err;

	kipp = procstat_getprocs(procstat, KERN_PROC_PID, pid, &cnt);
	if ((kipp == NULL) || (cnt <= 0))
		goto err;

	head = procstat_getfiles(procstat, kipp, 0);
	if (head == NULL)
		goto err;

	STAILQ_FOREACH(fst, head, next)
	{
		if (!(fst->fs_uflags & PS_FST_UFLAG_CDIR))
			continue;
		if (fst->fs_path == NULL)
			continue;
		wd = strdup(fst->fs_path);
		break;
	}

	procstat_freefiles(procstat, head);
#else
	// Linux & other unix (solaris etc)
	char buf[1024];
	char res[GS_PATH_MAX + 1];
	ssize_t sz;
	
	snprintf(buf, sizeof buf, "/proc/%d/cwd", (int)pid);
	sz = readlink(buf, res, sizeof res - 1);
	if (sz < 0)
		goto err;
	res[sz] = '\0';
	wd = strdup(res); 
#endif
err:
	if (wd == NULL)
	{
		#if defined(__sun) && defined(HAVE_OPEN64)
		// This is solaris 10
		wd = getcwd(NULL, GS_PATH_MAX + 1); // solaris10 segfaults if size is 0...
		#else
		wd = getcwd(NULL, 0);
		#endif
		XASSERT(wd != NULL, "getcwd(): %s\n", strerror(errno)); // hard fail
	}
	DEBUGF_W("PID %d CWD=%s\n", pid, wd);
	return wd;
}

/*
 * Duplicate the process. Child returns. Parent monitors child
 * and re-spwans child if it dies.
 * Disconnect from process group and do all the things to become
 * a daemon.
 * Terminate the daemon if code_force_exit matches _TWICE_ the error code of
 * the child. This is used to detect BAD-AUTH from the GSRN.
 * Set to -1 to ignore.
 */
void
GS_daemonize(FILE *logfp, int code_force_exit)
{
	pid_t pid;
	struct timeval last;
	struct timeval now;
	int n_force_exit = 0;

	memset(&last, 0, sizeof last);
	memset(&now, 0, sizeof now);

	gs_errfp = logfp;
#ifdef DEBUG
	gs_dout = logfp;
#endif

	pid = fork();
	XASSERT(pid >= 0, "fork(): %s\n", strerror(errno));

	if (pid > 0)
		exit(0);	// Parent exits

	/* HERE: Child. */
	setsid();
	// if (chdir("/") != 0)
	// 	ERREXIT("chdir(): %s\n", strerror(errno));
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	/* HERE: We are now a daemon. Next: Become a watchdog. */
	while (1)
	{
		signal(SIGCHLD, SIG_DFL);	// make wait() work...
		pid = fork();
		XASSERT(pid >= 0, "fork(): %s\n", strerror(errno));

		if (pid == 0)
		{
			signal(SIGCHLD, SIG_IGN);
			return;
		}
		/* HERE: Parent. We are the watchdog. */
		int wstatus;
		wait(&wstatus);	// Wait for child to termiante and then restart child
		if (WIFEXITED(wstatus) && (WEXITSTATUS(wstatus) == code_force_exit))
		{
			// Admin behavior is to test gs-netcat without -D and then
			// with -D immediatly after. The 2nd gs-netcat will use a different
			// AUTH-TOKEN and thus will receive a BAD-AUTH immediately.
			// => Wait 10 seconds before re-conncting to give the GSRN time
			// to expire the AUTH-TOKEN. If we get a 2nd BAD-AUTH thereafter
			// then it is clear that another server using the same SECRET
			// is already listening and we should exit the daemon/watchdog.
			n_force_exit += 1;

			// Kill the daemon / watchdog.
			if (n_force_exit >= 2)
				exit(0);
		} else {
			n_force_exit = 0;
		}
		/* No not spawn to often. */
		gettimeofday(&now, NULL);
		int diff = now.tv_sec - last.tv_sec;
		int n = 60;
		if (diff > 60)
		{
			n_force_exit = 0;
			n = 1;	// Immediately restart if this is first restart or child ran for >60sec
		}
		if (n_force_exit == 1)
			n = GSRN_TOKEN_LINGER_SEC + 3; // If BAD-AUTH then only wait long enough for GSRN to drop auth token (7 seconds)

		xfprintf(gs_errfp, "%s ***DIED*** (wstatus=%d/). Restarting in %d second%s.\n", GS_logtime(), wstatus, n, n>1?"s":"");
		sleep(n);

		gettimeofday(&last, NULL);	// When last restarted.
	}

	exit(255);	// NOT REACHED
}

// Sanitize a string
const char *
GS_sanitize(char *dst, size_t dsz, char *src, size_t sz, const char *set, size_t setsz, short option)
{
	char *dst_orig = dst;
	if (dsz <= 0)
		return NULL;

	char *dst_end = dst + dsz;
	char *src_end = src + sz;

	uint8_t c;
	uint8_t n;

	while ((dst < dst_end) && (src < src_end))
	{
		c = *src;
		if (c == '\0')
			break;

		if (c < setsz)
		{
			n = set[c];
		} else {
			n = '#';
		}

		*dst = n;
		dst++;
		src++;
	}

	*dst = '\0';

	return dst_orig;
}

static const char fname_valid_char[] = ""
"................"
"................"
" !.#$%&.()#+,-.."	/* Dont allow " or / or ' or * */
"0123456789:;.=.."	/* Dont allow < or > or ? */
"@ABCDEFGHIJKLMNO"
"PQRSTUVWXYZ[.]^_"	/* Dont allow \ */
".abcdefghijklmno"	/* Dont allow ` */
"pqrstuvwxyz{.}.." 	/* Dont allow | or ~ */
"";

// Sanitize a filename
const char *
GS_sanitize_fname_str(char *str, size_t len)
{
	return GS_sanitize(str, len, str, len, fname_valid_char, sizeof fname_valid_char, 0);
}

const char *
GS_sanitize_fname(char *dst, size_t dlen, char *src, size_t slen)
{
	return GS_sanitize(dst, dlen, src, slen, fname_valid_char, sizeof fname_valid_char, 0);
}

static const char logmsg_valid_char[] = ""
"................"
"................"
" !\"#$%#'()#+,-./" // dont allow &, *
"0123456789:#<=>?"  // dont allow ;
"@ABCDEFGHIJKLMNO"
"PQRSTUVWXYZ[\\]^_"
"#abcdefghijklmno"  // dont allow `
"pqrstuvwxyz{#}~."  // dont allow |
"";

// Sanitize a log message
const char *
GS_sanitize_logmsg_str(char *str, size_t len)
{
	return GS_sanitize(str, len, str, len, logmsg_valid_char, sizeof logmsg_valid_char, 0);
}

const char *
GS_sanitize_logmsg(char *dst, size_t dlen, char *src, size_t slen)
{
	return GS_sanitize(dst, dlen, src, slen, logmsg_valid_char, sizeof logmsg_valid_char, 0);
}
