

#ifndef __GSNC_UTILS_H__
#define __GSNC_UTILS_H__ 1

void init_defaults(int *argcptr, char **argvptr[]);
void init_vars(void);
GS *gs_create(void);
void do_getopt(int argc, char *argv[]);
void usage(const char *params);
int fd_cmd(const char *cmd, pid_t *pidptr, int *err);
#define GS_FD_CMD_ERR_NOPTY     (0x01)
int fd_new_socket(int type);
int fd_net_listen(int fd, uint16_t *port, int type);
int fd_net_accept(int listen_fd);
int fd_net_connect(GS_SELECT_CTX *ctx, int fd, uint32_t ip, uint16_t port);
void fd_kernel_flush(int fd);
void stty_set_raw(void);
void stty_switch_nopty(void);
void stty_reset(void);
void stty_check_esc(GS *gs, char c);
void ctrl_c_child(pid_t pid);
// char **mk_env(char **blacklist, char **addlist);
void get_winsize(void);
void cmd_ping(struct _peer *p);
void cmd_pwd(struct _peer *p);
// void sanitze_name_to_string(uint8_t *str, size_t len);
void sanitize_fname_to_str(uint8_t *str, size_t len);
void format_bps(char *buf, size_t size, int64_t bytes);
char *getcwdx(void);
void gs_watchdog(void);


// #define VLOG(a...)	do{if (gopt.log_fp != NULL){ fprintf(gopt.log_fp, a); fflush(gopt.log_fp); } }while(0)

// Log with Timestamp + Peer-ID
#define GS_LOG_TSP(_p, _a...)	do{ \
	GS_LOG("%s [ID=%d] ", GS_logtime(), _p->id); \
	GS_LOG(_a);  \
}while(0)

/* hack to set rows/columns */
#define GS_STTY_INIT_HACK	"stty rows %d columns %d\r"

#define UTILS_GETOPT_STR	"3:vigqwACTrlSDL:a:s:k:p:d:e:"

#endif /* !__GSNC_UTILS_H__ */