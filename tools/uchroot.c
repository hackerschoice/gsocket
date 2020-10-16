/*
 * gcc -shared -fPIC -O2 uchroot.c -o uchroot.so -ldl
 * LD_PRELOAD=$PWD/uchroot.so <executeable>
 *
 * OSX
 * gcc -shared -fPIC -o uchroot.dylib uchroot.c
 * DYLD_INSERT_LIBRARIES=$PWD/uchroot.dylib DYLD_FORCE_FLAT_NAMESPACE=1 <executeable>
 */
#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <string.h>

static size_t clen;
static char *cwd;
static int is_init;
static char rp_buf[PATH_MAX + 1];

static void
thc_init(void)
{
	if (is_init)
		return;

	cwd = getcwd(NULL, 0);
	if (cwd == NULL)
		exit(213);

	clen = strlen(cwd);
	is_init = 1;
}

/* Return 0 if access is allowed */
static int
thc_access(const char *name)
{
	int len;

	// Access to /dev/null always allowed...
	if (memcmp(name, "/dev/null", strlen("/dev/null")) == 0)
		return 0;
	if (memcmp(name, "/AppleInternal", strlen("/AppleInternal")) == 0)
		return 0;

	len = strlen(name);
	if (len >= clen)
	{
		if (memcmp(name, cwd, clen) == 0)
		{
			return 0;
		}
	}

	fprintf(stderr, "DENIED %s\n", name);	
	errno = EACCES;
	return -1;
}

typedef int (*real_stat_t)(const char *path, struct stat *buf);
int real_stat(const char *path, struct stat *buf) {return ((real_stat_t)dlsym(RTLD_NEXT, "stat$INODE64"))(path, buf);}
int
stat$INODE64(const char *path, struct stat *buf)
{
	int ret;
	/* on OSX getcwd() calls stat()...*/
	if (is_init == 0)
		return real_stat(path, buf);

	thc_init();
	errno = EACCES;
	if (realpath(path, rp_buf) == NULL)
		return -1;
	if (thc_access(rp_buf) != 0)
		return -1;

  	ret = real_stat(rp_buf, buf);

	return ret;
}


typedef int (*real_xstat_t)(int ver, const char *path, struct stat *buf);
int real_xstat(int ver, const char *path, struct stat *buf) {return ((real_xstat_t)dlsym(RTLD_NEXT, "__xstat"))(ver, path, buf);}
int
__xstat(int ver, const char *path, struct stat *buf)
{
	int ret;
	fprintf(stderr, "stat(%s)\n", path);
	thc_init();

	errno = EACCES;
	if (realpath(path, rp_buf) == NULL)
	{
		fprintf(stderr, "stat-realpath(%s) failed\n", path);
		return -1;
	}

	if (thc_access(rp_buf) != 0)
		return -1;

  	ret = real_xstat(ver, rp_buf, buf);

	return ret;
}

typedef int (*real_mkdir_t)(const char *path, mode_t mode);
int real_mkdir(const char *path, mode_t mode) {return ((real_mkdir_t)dlsym(RTLD_NEXT, "mkdir"))(path, mode);}
int
mkdir(const char *path, mode_t mode)
{
	int ret;
	
	fprintf(stderr, "mkdir(%s)\n", path);
	thc_init();

	stop here: must check each part of path from left to right until realpath() fails and
	then to thc_access against last successful realpath() result
	for ld-preload check with nm -D for symbols? or compiler time tricks?

	errno = EACCES;
	if (realpath(path, rp_buf) == NULL)
	{
		fprintf(stderr, "mkdir-realpath(%s) failed\n", path);
		return -1;
	}

	if (thc_access(rp_buf) != 0)
		return -1;

	ret = real_mkdir(rp_buf, mode);
	return ret;	
#if 0
	// realpath() expects dir to exist. Create -> check -> rmdir
	ret = real_mkdir(path, mode);
	if (ret != 0)
		return ret;

	if (realpath(path, rp_buf) != NULL)
	{
		if (thc_access(rp_buf) == 0)
		{
			return 0;
		}
	}

	/* Not allowed. Delete directory */
	rmdir(path);	
	errno = EACCES;
	return -1;
#endif
}


typedef int (*real_open_t)(const char *file, int flags, mode_t mode);
int
real_open(const char *file, int flags, mode_t mode)
{
  return ((real_open_t)dlsym(RTLD_NEXT, "open"))(file, flags, mode);
}

int
open(const char *file, int flags, mode_t mode)
{
	int ret;

	fprintf(stderr, "open(%s)\n", file);
	thc_init();

	errno = EACCES;
	if (realpath(file, rp_buf) == NULL)
		return -1;

	if (thc_access(rp_buf) != 0)
		return -1;

	ret = real_open(rp_buf, flags, mode);

	return ret;
}

