
#ifndef __GS_SO_UTILS_H__
#define __GS_SO_UTILS_H__ 1

#define GS_AUTHCOOKIE_LEN     (SHA256_DIGEST_LENGTH)  // 32

struct _gs_portrange
{
	uint16_t low;
	uint16_t high;
};

struct _gs_portrange_list
{
	int n_entries;
	int n_max;
	struct _gs_portrange *list;
};

void authcookie_gen(uint8_t *cookie, const char *secret, uint16_t port);
int GS_portrange_new(struct _gs_portrange_list *l, const char *range_orig);
int GS_portrange_is_match(struct _gs_portrange_list *l, uint16_t port);
void GS_portrange_free(struct _gs_portrange_list *l);

#endif /* !__GS_SO_UTILS_H__ */