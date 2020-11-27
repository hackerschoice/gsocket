/*
 * Event manager by time stamp (usec)
 *
 * FIXME-Performance: reduce calls to gettimeofday(). Use global.
 */
#include "gs-common.h"
#include <gsocket/gsocket.h>
#include "gs-externs.h"

int
GS_EVENT_MGR_init(GS_EVENT_MGR *mgr)
{
 	memset(mgr, 0, sizeof *mgr);
 	GS_LIST_init(&mgr->list_ts, 0);

 	return 0;
}

/*
 * func == NULL is a special function which sets the mgr->is_return_to_caller := 1.
 *         This is used to pass control back to the caller when select() is used
 *         in any kind of 'forever' loop such as GS_select().
 */
GS_EVENT *
GS_EVENT_add_by_ts(GS_EVENT_MGR *mgr, GS_EVENT *gse, uint64_t start, uint64_t interval, gsevent_cb_t func, void *data, size_t len)
{
 	if (gse == NULL)
 	{
 		gse = calloc(1, sizeof *gse);
 		XASSERT(gse != NULL, "calloc(): %s\n", strerror(errno));
 		gse->is_calloc = 1;
 	} else {
 		gse->is_calloc = 0;
 	}

 	// Get start time if not specified
 	// Start can also be an offset to current time if it is
 	// <1000.
 	if (start < 1000)
 	{
 		struct timeval tv;
 		gettimeofday(&tv, NULL);
 		start = GS_TV_TO_USEC(&tv) + GS_MSEC_TO_USEC(start);
 	} 

 	gse->data = data;
 	gse->len = len;
 	gse->mgr = mgr;
 	gse->interval = interval;
 	gse->start = start;
 	gse->due = start + interval;
 	gse->func = func;
 	gse->id = mgr->id_counter;
 	mgr->id_counter += 1;

 	GS_LIST_add(&mgr->list_ts, &gse->li, gse, gse->due);

 	return gse;
}

int
GS_EVENT_del(GS_EVENT *gse)
{
	int is_calloc;

	if (gse == NULL)
		return -1;

	// Already deleted
	if (gse->mgr == NULL)
		return -1;

	GS_LIST_del(&gse->li);

	is_calloc = gse->is_calloc;
	memset(gse, 0, sizeof *gse);

	if (is_calloc)
		XFREE(gse);

	return 0;
}

uint64_t
GS_EVENT_usec_until_event(GS_EVENT_MGR *mgr)
{
	GS_LIST_ITEM *li;

	li = GS_LIST_next(&mgr->list_ts, NULL);

	// Return 1 second if no event scheduled.
	if (li == NULL)
		return GS_SEC_TO_USEC(1);

	struct timeval tv;
	uint64_t now;
	gettimeofday(&tv, NULL);
	now = GS_TV_TO_USEC(&tv);

	// Return if top most entry's time has come...
	if (now > li->id)
		return 0;

	return li->id - now;
}

/*
 * Execute 1 event (if due) and return to the caller.
 *
 * Return 0 if there are more events to be executed.
 * Return the usec until next event is due.
 */
uint64_t
GS_EVENT_execute(GS_EVENT_MGR *mgr)
{
	uint64_t wait;
	int ret;

	wait = GS_EVENT_usec_until_event(mgr);
	if (wait != 0)
		return wait;

	// HERE: top-most event is due. Execute.
	GS_EVENT *event = mgr->list_ts.head->data;

	if (event->func != NULL)
	{
		ret = event->func(event);
		if (ret != 0)
		{
			// CB wants this event to be deleted
			GS_EVENT_del(event);
			return 0;
		}
	} else {
		mgr->is_return_to_caller = 1;
	}

	// Schedule next execution for this event
	// Detect clock skew (e.g. machine was in sleep mode)
	struct timeval tv;
	gettimeofday(&tv, NULL);
	uint64_t now = GS_TV_TO_USEC(&tv);
	uint64_t steps = (now - event->start) / event->interval;
	event->due = event->start + ((steps + 1) * event->interval);
	// DEBUGF("now %llu due %llu diff %llu\n", now, event->due, event->due - now);

	GS_LIST_relink(&event->li, event->due);

	return GS_EVENT_usec_until_event(mgr);
}

/*
 * Execute all events that are due.
 * Return the usec until next event is due (or 1 sec if no event scheduled)
 */
uint64_t
GS_EVENT_execute_all(GS_EVENT_MGR *mgr)
{
	uint64_t next;

	while (1)
	{
		next = GS_EVENT_execute(mgr);
		if (next != 0)
			break;
	}

	return next;
}
