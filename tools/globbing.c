/*
 * Create a file list. Used by filetransfer.c (which is used by
 * gs-netcat.c)
 *
 * Used 'wordexp(3)' where available. Alernatively use 'sh -c echo $str'
 * (not implemented)
 */

#include "common.h"
#include <wordexp.h>
#include <dirent.h>
#include "utils.h"
#include "globbing.h"

static void
gl_add_file(gsglobbing_cb_t func, GS_GL *res)
{
	(*func)(res);
}

static void
gl_add_dir(gsglobbing_cb_t func, GS_GL *res)
{
	(*func)(res);
}

static void
gl_dir(gsglobbing_cb_t func, const char *path, GS_GL *res)
{
	DIR *d;

	d = opendir(path);
	if (d == NULL)
		return;

	struct dirent *entry;
	for (entry = readdir(d); entry != NULL; entry = readdir(d))
	{
		char fullname[4096];
		int is_dir = 0;
		int is_reg = 0;
		res->name = fullname;
		snprintf(fullname, sizeof fullname, "%s/%s", path, entry->d_name);
#ifdef __sun
		// Solaris does not support d_type. Use stat()
		struct stat sr;
		
		if (stat(fullname, &sr) == 0)
		{
			if (S_ISDIR(sr.st_mode))
				is_dir = 1;
			else if (S_ISREG(sr.st_mode))
				is_reg = 1;
		} else {
			DEBUGF_R("FAIL %s\n", entry->d_name);
			continue;
		}
#else
		if (entry->d_type == DT_DIR)
			is_dir = 1;
		else if (entry->d_type == DT_REG)
			is_reg = 1;
#endif

		if (is_dir)
		{
			if ((strlen(entry->d_name) == 1) && (entry->d_name[0] == '.'))
				continue;
			if ((strlen(entry->d_name) == 2) && (memcmp(entry->d_name, "..", 2) == 0))
				continue;
			gl_add_dir(func, res);
			gl_dir(func, fullname, res); // recursive call
		} else if (is_reg) {
			gl_add_file(func, res);
		} else {
			DEBUGF_R("FAIL (is_reg=%d, is_dir=%d) %s\n", is_reg, is_dir, entry->d_name);
		}
	}

	closedir(d);	
}

static void
gs_gl(gsglobbing_cb_t func, const char *path, GS_GL *res)
{
	DEBUGF("Glob(%s)\n", path);

	int rv;
	struct stat s;
	rv = stat(path, &s);
	// if stat() fails then still send this result back to caller.
	// This can happen when caller requests "notexist.dat".

	res->name = path;
	// If file then call callback.
	if ((rv != 0) || S_ISREG(s.st_mode))
	{
		gl_add_file(func, res);
		return;
	}

	// If directory then call callback, enter directory and traverse
	if (S_ISDIR(s.st_mode))
	{
		gl_add_dir(func, res);
		gl_dir(func, path, res);
		return;
	}

	return;
}


// GET (download)
// assume CWD==/tmp
// get /tmp/f* should create foo/bar/test4k.dat [file /tmp/./foo/bar/test4k.dat]
// get foo/*.dat should create test1k.dat [file /tmp/foo/./test1k.dat]
// get foo/./bar/test4k.dat should create bar/test4k.dat [file /tmp/foo/bar/test4k.dat]
// get $(find /tmp/ -name *.dat) should create bar/test4k.dat and test1k.dat by using
//     smallest common base (/tmp/foo)
//     [file /tmp/foo/./bar/test4k.dat /tmp/foo/./test1k.dat]

// The CWD might change between the LIST-request and actual file request. Thus any file-list returned
// to the downloading client must contain the _absolute_ path to the file (rather than relative).
// - If file is a relative request then prefix with '${CWD}/./'.
// - If file is absolute request then add '/./' (see below how to add this).

// => Add '/./' last.

// PUT (upload)

// Test Cases:
// ./filetransfer-test G '$(echo dir1/foo.txt  dir2)'

// How to insert '/./'
// Wordexp() might do command substituion (replacing $(command) by the output of command). This
// needs consideration of where to add the '/./'.
// - If fname already contains '/./' then do nothing.

int
GS_GLOBBING(gsglobbing_cb_t func, const char *exp, uint32_t glob_id, void *arg_ptr, uint32_t arg_val)
{
	// wordexp(3) to expand expressions like '*.[ch]'.
	wordexp_t p;
	int i;
	char **w;
	char buf[4096];
	int n_found;
	char *wdir;

	GS_GL res;
	res.globbing_id = glob_id;
	res.arg_ptr = arg_ptr;
	res.arg_val = arg_val;

	wdir = getcwdx();
	if (wdir == NULL)
	{
		DEBUGF_R("getcwd(): %s\n", strerror(errno));
		return 0;
	}


	DEBUGF("G#%u GS_GLOBBING('%s') [wdir='%s']\n", glob_id, exp, wdir);

	// Special case: Globbing loop below discards '.' from globbing results
	if (strcmp(exp, ".") == 0)
		exp = "./";

	// Test Setup:
	// mkdir -p /tmp/foo/dir_empty /tmp/foo/dir1
	// cp /etc/hosts /tmp/foo/dir1/
	// cp /etc/passwd /tmp/foo/.rcfile

	// CASES for globbing and what file structure to create at _destination_:
	// put /tmp/f* should create foo/bar/test4k.dat but not /tmp/foo/bar/test4k.dat
	// put /tmp/foo should create foo/* (and .rcfile)
	// put /tmp/foo/*  should create ./* (but not foo/* and not .rcfile)
	// put /tmp/foo/   should create ./* (and .rcfile) [[** SPECIAL CASE**]]
	// put /tmp/foo/.  should create ./* (and .rcfile)
	// put /tmp/foo/bar/test4k.dat should create test4k.dat
	// put /tmp/./foo/* should create foo/* (but not .rcfile)
	// put /tmp/./foo/  should create foo/* (and .rcfile)
	// put /tmp/./foo   should create foo/* (and .rcfile)
	// put /./tmp/foo should create ./tmp/foo/* (and .rcfile)
	// cd /tmp/foo; put . should create ./* (and .rcfile)
	// put $(find /tmp/ -name *.dat) should based on smallest common directory structure (base).
	// -> /tmp/foo/bar/test1k.dat /tmp/foo/test4k.dat then base => /tmp/foo
	// -> /tmp/test1k.dat /tmp/foo/bar/test1k.dat then base => /tmp 
	int ret;
	signal(SIGCHLD, SIG_DFL);
	ret = wordexp(exp, &p, 0);
	signal(SIGCHLD, SIG_IGN);
	if (ret != 0)
		return 0; // error (0 found)

	w = p.we_wordv;
	n_found = p.we_wordc;

	if (n_found <= 0)
		goto done;

	char base_buf[4096];
	char *base = base_buf;


	// Find the smallest common name of directory. This is needed
	// when wordexp(3) does command subs such as '$(find /tmp -name \*.dat)'
	//
	// /tmp/foo/test1k.dat /tmp/foo/bar/test4k.dat
	// base => /tmp/foo
	// 
	// foo/bar/test4k.dat foo/test1k.dat
	// base => foo
	//
	// foo/bar/test4k.dat foo/test1k.dat test8k.dat
	// base => "" (empty)
	snprintf(base_buf, sizeof base_buf, "%s", w[0]);
	char *ptr;
	ptr = rindex(base, '/');
	if (ptr != NULL)
	{
		*ptr = '\0';
		for (i = 1; i < p.we_wordc; i++)
		{
			int ii;
			for (ii = 0; base[ii] == w[i][ii]; ii++)
			{
				continue;
			}

			// DEBUGF("last identical at %d [%s]\n", ii, w[i]);
			// if it was "/tmp/dir1" and "/tmp/dir2" then make base => /tmp
			// if it was /tmp/foo/bar.txt and /tmp/foo/dir2 then make base => /tmp/foo
			for (; ii > 0 && w[i][ii] != '/'; ii--)
			{
				continue;
			}
			// DEBUGF("/ at %d\n", ii);
			base[ii] = '\0'; // trailing '/' or empty string (ii==0)
			if (ii <= 0)
				break;
		}
	} else {
		base[0] = '\0';
	}
	DEBUGF_C("base = '%s'\n", base);

	for (i = 0; i < p.we_wordc; i++)
	{
		// Check if '/tmp/foo/.*' was specified and ignore expansion for those cases:
		// 1. /tmp/foo/.* shall not glob /tmp/foo/.. or /tmp/foo/. but only /tmp/foo/.rcfile
		// 2. '.*' shall not glob '..' or '.' but only '.rcfile'
		// 3. 'testfile.' shall still glob 'testfile.' [note the '.' at the end of the filename]
		size_t sz = strlen(w[i]);
		if (sz >= 3)
		{
			// Special case: put /tmp/foo/.* shall not glob /tmp/foo/.. [/tmp/]
			if (memcmp(w[i] + sz - 3, "/..", 3) == 0)
				continue;
		}
		if (sz >= 2)
		{
			// Special case: put /tmp/foo/.* shall not glob /tmp/foo/. but only /tmp/foo/.rcfile
			if (memcmp(w[i] + sz - 2, "/.", 2) == 0)
				continue;
			if ((sz == 2) && memcmp(w[i], "..", 2) == 0)
				continue;
		}
		if ((sz == 1) && (memcmp(w[i], ".", 1) == 0))
			continue;

		// Add '/./' 
		char *fname = w[i];
		DEBUGF_C("fname = '%s'\n", fname);

		// GET request of  "./foo/bar/test1k.dat" should be treated as "foo/bar/test1k.dat"
		// and create file 'foo/bar/./test1k.dat'.
		
		// PUT request of  "././foo/bar/test1k.dat" should 
		// and create file '././foo/bar/test1k.dat'
		while (1)
		{
			if ((base[0] == 0) || (base[1] == 0))
				break;
			if ((base[0] == '.') && (base[1] == '/'))
				base += 2;
			break;
		}
		DEBUGF_C("BASE = %s\n", base);

		int is_absolute = 0;
		ptr = fname;
		while (*ptr == '/')
		{
			ptr++;
			is_absolute = 1; // Starts with '/'
		}

		if (strstr(fname, "/./") == NULL)
		{
			// Does NOT contain '/./'.
			// $ get 'foo/*'
			// wdir=/tmp, base=foo => /tmp/foo/bar/test4k.dat & /tmp/foo/test1k.dat
			// base = foo
			// $ get '$(find //tmp/foo -name \*.dat)'
			ptr = rindex(ptr, '/');
			if (ptr == NULL)
			{
				// single file without directory structure
				if (is_absolute)
				{
					// "/test[14]k.dat"
					DEBUGF_Y("1\n");
					snprintf(buf, sizeof buf, "/./%s", fname);
				} else {
					// "test[14]k.dat"
					DEBUGF_Y("2\n");
					snprintf(buf, sizeof buf, "%s/./%s", wdir, fname);
				}
			} else {
				// HERE: fname contains '/' (e.g tmp/foo or foo/bar/test1k.dat)
				if (is_absolute)
				{
					// "/tmp/foo/" or "/tmp/foo/*" or "/tmp/fo*"
					sz = strlen(base_buf);
					XASSERT(sz <= strlen(fname), "fname to short\n");
					DEBUGF_Y("3\n");
					SNPRINTF_ABORT(buf, sizeof buf, "%s/.%s", base, fname + sz);
				} else {
					if (base[0] == '\0')
					{
						// $(echo dir1/ dir2/)
						DEBUGF_Y("4\n");
						snprintf(buf, sizeof buf, "%s/./%s", wdir, fname);
					} else {
						// "foo/*"
						sz = strlen(base_buf);
						XASSERT(sz <= strlen(fname), "fname to short.\n");
						DEBUGF_Y("5\n");
						SNPRINTF_ABORT(buf, sizeof buf, "%s/%s/.%s", wdir, base, fname + sz);
					}
				}
			}
			fname = buf;
		} else {
			// HERE: Contains '/./'
			if (is_absolute)
			{
				// '/etc/./ssh/ssh_config'
				snprintf(buf, sizeof buf, "%s", fname); // as is
			} else {
				// foo/./bar/test1k.dat
				sz = strlen(base_buf);
				XASSERT(sz <= strlen(fname), "fname to short.\n");
				DEBUGF_Y("6\n");
				SNPRINTF_ABORT(buf, sizeof buf, "%s/%s%s", wdir, base, fname + sz);
			}
			fname = buf;
		}

		DEBUGF_C("Globb result '%s' -> '%s'\n", w[i], fname);
		gs_gl(func, fname, &res);
	}

done:
	wordfree(&p);
	XFREE(wdir);
	return n_found;
}

static uint32_t glob_id = 0xFFFFFFFF;

int
GS_GLOBBING_argv(gsglobbing_cb_t func, const char *argv[], void *arg_ptr, uint32_t arg_val)
{
	const char *ptr;

	if (argv == NULL)
		return -1; // Bad parameter

	for (ptr = *argv; ptr != NULL; argv++)
	{
		GS_GLOBBING(func, ptr, glob_id, arg_ptr, arg_val);
		glob_id--;
		ptr = *argv;
	}

	return 0;
}

#if 0
int
GS_GLOBBING_free(GS_GL *ctx)
{
	return 0;
}
#endif