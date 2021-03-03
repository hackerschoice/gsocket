
#include "gs-common.h"
#include <gsocket/gsocket.h>
#include "gsocket-engine.h"
#include "gs-externs.h"

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
		xfprintf(gs_errfp, "Enter Secret (or press Enter to generate): ");
		len = getline(&ptr, &n, stdin);
		XASSERT(len > 0, "getline()\n");
		if (ptr[len - 1] == '\n')
			ptr[len - 1] = 0;	// Remove '\n' 
		if (strlen(ptr) == 0)
			return NULL;
		if (strlen(ptr) >= 8)
			break;
		xfprintf(gs_errfp, "Too short.\n");
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

	GS_library_init(stderr, stderr);

	/* Generate a new secret */
	uint8_t buf[GS_SECRET_MAX_LEN + 1];
	ret = RAND_bytes(buf, GS_SECRET_MAX_LEN);
	XASSERT(ret == 1, "RAND_bytes() failed.\n");

	GS_ADDR addr;
	GS_ADDR_bin2addr(&addr, buf, GS_SECRET_MAX_LEN);

	return strdup(addr.b58str);
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
	char res[PATH_MAX + 1];
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
		wd = getcwd(NULL, PATH_MAX + 1); // solaris10 segfaults if size is 0...
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
 */
void
GS_daemonize(FILE *logfp)
{
	pid_t pid;
	struct timeval last;
	struct timeval now;

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
		int status;
		wait(&status);	// Wait for child to termiante and then restart child
		/* No not spawn to often. */
		gettimeofday(&now, NULL);
		int diff = now.tv_sec - last.tv_sec;
		int n = 60;
		if (diff > 60)
			n = 1;	// Immediately restart if this is first restart or child ran for >60sec
		xfprintf(gs_errfp, "%s ***DIED*** (status=%d). Restarting in %d second%s.\n", GS_logtime(), status, n, n>1?"s":"");
		sleep(n);

		gettimeofday(&last, NULL);	// When last restarted.
	}

	exit(255);	// NOT REACHED
}

