#ifndef __GS_NETCAT_H__
#define __GS_NETCAT_H__ 1

int write_gs(GS_SELECT_CTX *ctx, struct _peer *p, int *killed);
int write_gs_atomic(GS_SELECT_CTX *ctx, struct _peer *p);

#endif /* !__GS_NETCAT_H__ */
