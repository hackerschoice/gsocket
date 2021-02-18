#ifndef __GS_GLOBBING_H__
#define __GS_GLOBBING_H__ 1

typedef struct
{
	const char *name;
	mode_t mode;
	uint32_t globbing_id;
	void *arg_ptr;
	uint32_t arg_val;
} GS_GL;

struct _gs_gl
{
	int res;
	void *func;
};

typedef void (gsglobbing_cb_t)(GS_GL *res);

int GS_GLOBBING(gsglobbing_cb_t func, const char *path, uint32_t glob_id, void *arg_ptr, uint32_t arg_val);
int GS_GLOBBING_argv(gsglobbing_cb_t func, const char *argv[], void *arg_ptr, uint32_t arg_val);

#endif /* !__GS_GLOBBING_H__ */