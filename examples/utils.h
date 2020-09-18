
void init_defaults(void);
void init_vars(void);
GS *gs_create(void);
void do_getopt(int argc, char *argv[]);
void usage(const char *params);
int fd_cmd(const char *cmd);
int fd_new_socket(void);
int fd_net_listen(GS_SELECT_CTX *ctx, int fd, uint16_t port);
int fd_net_accept(GS_SELECT_CTX *ctx, int listen_fd);
int fd_net_connect(GS_SELECT_CTX *ctx, int fd, uint32_t ip, uint16_t port);
void stty_set_raw(void);
void stty_reset(void);
void stty_check_esc(GS *gs, char c);

/* hack to set rows/columns and allow screen in a screen */
#define GS_STTY_INIT_HACK	"stty rows %d columns %d;unset STY\r"

#define UTILS_GETOPT_STR	"igwACrla:s:k:"