

#ifndef __LIBGSOCKET_GS_EXTERNS_H__
#define __LIBGSOCKET_GS_EXTERNS_H__ 1

#ifdef DEBUG
extern FILE *gs_dout;
extern int gs_did;
extern int gs_debug_level;
#endif
extern FILE *gs_errfp;

void gs_log(int type, int level, char *fmt, ...);

#endif /* !__LIBGSOCKET_GS_EXTERNS_H__ */
