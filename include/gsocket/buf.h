#ifndef __GS_BUF_H__
#define __GS_BUF_H__ 1


typedef struct
{
	void *data;
	size_t sz_total;
	size_t sz_used;

	size_t sz_max_add;
} GS_BUF;

void GS_BUF_init(GS_BUF *gsb, size_t sz_min_free);
void GS_BUF_free(GS_BUF *gsb);
int GS_BUF_resize(GS_BUF *gsb, size_t sz_new);
int GS_BUF_add_length(GS_BUF *gsb, size_t len);
int GS_BUF_add_data(GS_BUF *gsb, void *data, size_t len);
int GS_BUF_printf(GS_BUF *gsb, const char *fmt, ...);
int GS_BUF_del(GS_BUF *gsb, size_t len);
int GS_BUF_memmove(GS_BUF *gsb, void *data, size_t len);

#define GS_BUF_empty(gsb)   (gsb)->sz_used = 0;
#define GS_BUF_DATA(gsb)    (gsb)->data
#define GS_BUF_IS_INIT(gsb)	((gsb)->sz_max_add!=0)
#define GS_BUF_UNUSED(gsb)	((gsb)->sz_total - (gsb)->sz_used)
#define GS_BUF_RSRC(gsb)	(gsb)->data
#define GS_BUF_WDST(gsb)	((uint8_t *)(gsb)->data + (gsb)->sz_used)
#define GS_BUF_USED(gsb)	(gsb)->sz_used

#endif /* !__GS_BUF_H__ */
