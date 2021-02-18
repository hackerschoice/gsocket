#ifndef __GS_FILETRANSFER_MGR_H__
#define __GS_FILETRANSFER_MGR_H__ 1

void GS_FTM_init(struct _peer *p, int is_server);
void GS_FTM_free(struct _peer *p);
ssize_t GS_FTM_mk_packet(GS_FT *ft, uint8_t *dst, size_t dlen);

#endif // __GS_FILETRANSFER_MGR_H__ 