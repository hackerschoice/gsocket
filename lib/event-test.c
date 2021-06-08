#include "gs-common.h"
#include <gsocket/gsocket.h>
#include "gs-externs.h"

static int
cb_event(void *ptr)
{
#ifdef DEBUG
	GS_EVENT *event = (GS_EVENT *)ptr;
#endif

	DEBUGF("Event callback...(data = '%s', len = %zd)\n", (char *)event->data, event->len);

	return 0;
}


int
main(int argc, char *argv[])
{
	GS_EVENT_MGR mgr;
	GS_EVENT my_e;
	GS_EVENT *my_e_ptr;

	GS_library_init(stderr, stderr, NULL);
	srand(time(NULL));

	GS_EVENT_MGR_init(&mgr);

	my_e_ptr = GS_EVENT_add_by_ts(&mgr, NULL, 0, GS_SEC_TO_USEC(1), cb_event, "foobar", 7);
	// Every 2 seconds return to caller
	my_e_ptr = GS_EVENT_add_by_ts(&mgr, NULL, 0, GS_SEC_TO_USEC(2), NULL, "caller-action", 7);
	GS_EVENT_add_by_ts(&mgr, &my_e, 0, GS_MSEC_TO_USEC(437), cb_event, "foobar500", 31337);

	if (my_e_ptr == NULL)
		ERREXIT("add_by_ts()\n");
	uint64_t wait;
	while (1)
	{
		wait = GS_EVENT_execute(&mgr);
		DEBUGF_G("Next event in %"PRIu64" usec\n", wait);
		if (mgr.is_return_to_caller)
			DEBUGF_C("Return to caller triggered\n");
		usleep(wait);
		// GS_EVENT_del(my_e_ptr);
		// my_e_ptr = NULL;
		// GS_EVENT_DEL(&my_e);
	}

	return 0;
}
