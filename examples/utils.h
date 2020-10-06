

#ifndef __GSNC_UTILS_H__
#define __GSNC_UTILS_H__ 1

void init_defaults(int *argcptr, char **argvptr[]);
void init_vars(void);
GS *gs_create(void);
void do_getopt(int argc, char *argv[]);
void usage(const char *params);
int fd_cmd(const char *cmd);
int fd_new_socket(void);
int fd_net_listen(int fd, uint16_t port);
int fd_net_accept(int listen_fd);
int fd_net_connect(GS_SELECT_CTX *ctx, int fd, uint32_t ip, uint16_t port);
void stty_set_raw(void);
void stty_reset(void);
void stty_check_esc(GS *gs, char c);
char **mk_env(char **blacklist);

#define VLOG(a...)	do{if (gopt.log_fp == NULL){break;} fprintf(gopt.log_fp, a); fflush(gopt.log_fp); }while(0)

/* hack to set rows/columns */
#define GS_STTY_INIT_HACK	"stty rows %d columns %d\r"

#define UTILS_GETOPT_STR	"igqwACTrlSDL:a:s:k:p:d:e:"

#endif /* !__GSNC_UTILS_H__ */