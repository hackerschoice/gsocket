#ifndef __GS_EVENT_H__
#define __GS_EVENT_H__ 1


typedef int (*gsevent_cb_t)(void *event);


typedef struct
{
	void *mgr;
	uint64_t interval;
	uint64_t start;
	uint64_t due;
	GS_LIST_ITEM li;

	void *data;
	size_t len;
	gsevent_cb_t func;
	int is_calloc;
	int id;
} GS_EVENT;

/*
 * Keep track of all events under a context
 */
typedef struct
{
	GS_LIST list_ts;  // events by timestamp (usec)
	int id_counter;
	int is_return_to_caller;
} GS_EVENT_MGR;

int GS_EVENT_MGR_init(GS_EVENT_MGR *mgr);
GS_EVENT *GS_EVENT_add_by_ts(GS_EVENT_MGR *mgr, GS_EVENT *gsevent, uint64_t start, uint64_t interval, gsevent_cb_t func, void *data, size_t len);
int GS_EVENT_del(GS_EVENT *gsevent);
uint64_t GS_EVENT_usec_until_event(GS_EVENT_MGR *mgr);
uint64_t GS_EVENT_execute(GS_EVENT_MGR *mgr);
uint64_t GS_EVENT_execute_all(GS_EVENT_MGR *mgr);

#endif /* !__GS_EVENT_H__ */