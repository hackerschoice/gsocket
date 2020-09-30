
#ifndef __LIBGSOCKET_ENGINE_H__
#define __LIBGSOCKET_ENGINE_H__ 1


void gs_ssl_want_io_finished(GS *gs);
int gs_ssl_continue(GS *gsocket);
int gs_ssl_want_io_rw(GS_SELECT_CTX *ctx, int fd, int err);
int gs_ssl_shutdown(GS *gsocket);
int gs_srp_init(GS *gsocket);
void gs_select_rw_save_state(GS_SELECT_CTX *ctx, int fd, char *idstr);
void gs_select_rw_restore_state(GS_SELECT_CTX *ctx, int fd, char *idstr);
void gs_select_set_rdata_pending(GS_SELECT_CTX *ctx, int fd);

void gs_fds_out(fd_set *fdset, int max, char id);
void gs_fds_out_rwfd(GS_SELECT_CTX *ctx);
void gs_fds_out_fd(fd_set *fdset, char id, int fd);

#define gs_set_errorf(gs, a...)	do{snprintf((gs)->ctx->err_buf, sizeof (gs)->ctx->err_buf, a);} while(0)

#endif /* !__LIBGSOCKET_ENGINE_H__ */
