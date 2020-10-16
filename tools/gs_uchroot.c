/*
 * gcc -shared -fPIC -O2 uchroot.c -o uchroot.so -ldl
 * LD_PRELOAD=$PWD/uchroot.so <executeable>
 *
 * OSX
 * gcc -shared -fPIC -o uchroot.dylib uchroot.c
 * DYLD_INSERT_LIBRARIES=$PWD/uchroot.dylib DYLD_FORCE_FLAT_NAMESPACE=1 <executeable>
 */
#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <libgen.h>

static size_t clen;
static char *cwd;
static int is_init;
static char rp_buf[PATH_MAX + 1];
static int is_debug;

#define DEBUGF(a...) do { if (is_debug == 0){break;} fprintf(stderr, "LDP %d:", __LINE__); fprintf(stderr, a); }while(0)

static void
thc_init(void)
{
	if (is_init)
		return;

	if (getenv("GSOCKET_DEBUG"))
		is_debug = 1;

	cwd = getcwd(NULL, 0);
	if (cwd == NULL)
		exit(213);

	clen = strlen(cwd);
	is_init = 1;
}

/*
 * 'name' must be the absolute and resolved path.
 * Return 0 if access is allowed
 */
static int
thc_access(const char *name, const char *fname)
{
	int len;

	// Access to /dev/null always allowed...
	if (strcmp(name, "/dev/null") == 0)
		return 0;
	if (strcmp(name, "/AppleInternal") == 0)
		return 0;
	if (strcmp(name, ".") == 0)
		return 0;

	/* Check if name starts with cwd */
	len = strlen(name);
	if ((len >= clen) && memcmp(name, cwd, clen) == 0)
	{
		return 0;
	}

	DEBUGF("DENIED %s(%s)\n", fname, name);	
	errno = EACCES;
	return -1;
}

/*
 * if 'path' is relative then it has to be concatenated with CWD
 * and checked by realpath().
 * path == "./dir"
 * realpath($CWD + path)
 */
static char *
thc_realpath(const char *fname, const char *path, char *rp)
{
	char abpath[PATH_MAX + 1];
	const char *ptr;
	char *res;

	DEBUGF("Checking %s\n", path);
	ptr = path;
	if (path[0] == '.')
	{
		ptr = abpath;
		snprintf(abpath, sizeof abpath, "%s/%s", cwd, path);
	}

	DEBUGF("Checking %s\n", ptr);

	res = realpath(ptr, rp);
	if (res == NULL)
		DEBUGF("%s-realpath(%s [from %s]) FAILED\n", fname, ptr, path);

	return res;
}

static int
realfile(const char *fname, const char *file, char *dst)
{
	char dirn[PATH_MAX + 1];
	char *ptr;

	if (strcmp(file, "/dev/null") == 0)
	{
		memcpy(dst, "/dev/null", strlen("/dev/null") + 1);
		return 0;
	}

	if (strlen(file) >= sizeof dirn)
		return -1;
	snprintf(dirn, sizeof dirn, "%s", file);
	ptr = dirname(dirn);

	if (thc_realpath(fname, ptr, dst) == NULL)
		return -1;

	return 0;
}

typedef int (*real_stat_t)(const char *path, struct stat *buf);
int real_stat(const char *path, struct stat *buf) {return ((real_stat_t)dlsym(RTLD_NEXT, "stat$INODE64"))(path, buf);}
int
stat$INODE64(const char *path, struct stat *buf)
{
	/* on OSX getcwd() calls stat()...*/
	if (is_init == 0)
		return real_stat(path, buf);

	thc_init();

	if (thc_realpath(__func__, path, rp_buf) == NULL)
		return -1;
	if (thc_access(rp_buf, __func__) != 0)
		return -1;

  	return real_stat(rp_buf, buf);
}

typedef int (*real_xstat_t)(int ver, const char *path, struct stat *buf);
int real_xstat(const char *fname, int ver, const char *path, struct stat *buf) {return ((real_xstat_t)dlsym(RTLD_NEXT, fname))(ver, path, buf);}
int
thc_xstat(const char *fname, int ver, const char *path, struct stat *buf)
{
	DEBUGF("%s(%s)\n", fname, path);
	thc_init();

	if (thc_realpath(fname, path, rp_buf) == NULL)
		return -1;
	if (thc_access(rp_buf, fname) != 0)
		return -1;

	return real_xstat(fname, ver, path, buf);
}

int
__xstat(int ver, const char *path, struct stat *buf)
{
	return thc_xstat(__func__, ver, path, buf);
}

#if 0
// Can not hijack lxstat() because sftp-server traverses the directory.
// E.g. we are in /home/user and do 'mkdir dir' then sftp-server will:
// lxstat("/home") -> lxstat("/home/user") -> lxstat("/home/user/dir")
int
__lxstat(int ver, const char *path, struct stat *buf)
{
	return thc_xstat(__func__, ver, path, buf);
}
#endif


typedef int (*real_mkdir_t)(const char *path, mode_t mode);
int real_mkdir(const char *path, mode_t mode) {return ((real_mkdir_t)dlsym(RTLD_NEXT, "mkdir"))(path, mode);}
int
mkdir(const char *path, mode_t mode)
{
	DEBUGF("mkdir(%s)\n", path);
	thc_init();
	errno = EACCES;

	/*
	 * path could be absolute or relative (2x):
	 * "./test"
	 * "test"
	 * "/tmp/test"
	 */
	if (realfile(__func__, path, rp_buf) != 0)
		return -1;

	if (thc_access(rp_buf, __func__) != 0)
		return -1;

	return real_mkdir(path, mode);
}


typedef int (*real_open_t)(const char *file, int flags, mode_t mode);
int real_open(const char *file, int flags, mode_t mode) {return ((real_open_t)dlsym(RTLD_NEXT, "open"))(file, flags, mode); }
int
open(const char *file, int flags, mode_t mode)
{
	DEBUGF("open(%s)\n", file);
	thc_init();

	/*
	 * /dev/null -> allowed
	 * ./x.txt -> allowed
	 */
	if (realfile(__func__, file, rp_buf) != 0)
		return -1;

	if (thc_access(rp_buf, __func__) != 0)
		return -1;

	return real_open(file, flags, mode);
}

/*
 * Redirect unlink().
 */
typedef int (*real_func1_t)(const char *file);
int real_func1(const char *fname, const char *file) {return ((real_func1_t)dlsym(RTLD_NEXT, fname))(file); }
int
thc_func1(const char *fname, const char *file)
{
	DEBUGF("%s(%s)\n", fname, file);
	thc_init();

	if (thc_realpath(fname, file, rp_buf) == NULL)
		return -1;
	if (thc_access(rp_buf, fname) != 0)
		return -1;

	return real_func1(fname, rp_buf);
}

int
unlink(const char *file)
{
	return thc_func1(__func__, file);
}

typedef void *(*real_opendir_t)(const char *file);
void *real_opendir(const char *fname, const char *file) {return ((real_opendir_t)dlsym(RTLD_NEXT, fname))(file); }
void *
opendir( const char *file)
{
	DEBUGF("%s(%s)\n", __func__, file);
	thc_init();

	if (thc_realpath(__func__, file, rp_buf) == NULL)
		return NULL;

	if (thc_access(rp_buf, __func__) != 0)
		return NULL;

	return real_opendir(__func__, rp_buf);
}

