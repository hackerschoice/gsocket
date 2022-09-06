/*
 * Used by GS-NETCAT.
 *
 * Callback for event handler and manager for events
 */

#include "common.h"
#include "event_mgr.h"
#include "console.h"
#include "utils.h"
#include "pkt_mgr.h"
#include "ids.h"

/*
 * When console is visible then send a ping more often.
 */
int
cbe_ping(void *ptr)
{
	GS_EVENT *event = (GS_EVENT *)ptr;

	if (gopt.is_console == 0)
	{
		return 0;
		// Return if data was transmitted recently
		// struct _peer *p = (struct _peer *)event->data;
		// if (p->gs->ts_net_io + GS_SEC_TO_USEC(gopt.app_keepalive_sec) >= GS_TV_TO_USEC(&gopt.tv_now))
			// return 0;
	}

	cmd_ping(event->data);

	return 0;
}

// CLIENT - Called every second
int
cbe_bps(void *ptr)
{
	GS_EVENT *event = (GS_EVENT *)ptr;

	// Calculate BPS
	CONSOLE_update_bps((struct _peer *)event->data);

	return 0;
}

// SERVER: add a log file to a peer
static void
add_log(struct _peer *p, GS_LIST *gsl, uint8_t log_type, const char *fmt)
{
	GS_LIST_ITEM *li = NULL;

	while (1)
	{
		li = GS_LIST_next(gsl, li);
		if (li == NULL)
			break;

		struct _pkt_app_log *log = malloc(sizeof *log);
		log->type = log_type;
		snprintf((char *)log->msg, sizeof log->msg, fmt, (char *)li->data);
		GS_LIST_add(&p->logs, NULL, log, GS_LIST_ID_COUNT(&p->logs));
	}

	if (gsl->n_items > 0)
	{
		p->is_pending_logs = 1;
		GS_SELECT_FD_SET_W(p->gs);
	}
}

// SERVER - Alert gs-user if Muggles are about. Also update
// least idle Muggle (ping will use this information).
int
cbe_ids(void *ptrNOTUSED)
{
	struct _peer *p;

	if (gopt.ids_peers.n_items == 0)
	{
		DEBUGF_R("No peer interested. Removing event IDS\n");
		gopt.event_ids = NULL; // caller will free this. We
		return -1;
	}

	// Check for IDS messages.
	GS_LIST new_login;
	GS_LIST new_active;
	GS_LIST_init(&new_login, 0);
	GS_LIST_init(&new_active, 0);
	GS_IDS_utmp(&new_login, &new_active, &gopt.ids_active_user, &gopt.ids_idle, &gopt.n_users);
	if (gopt.ids_idle < 15)
		gopt.ids_idle = 0; // treat anything below 15 as fully active (0)

	// DEBUGF_C("Least Idle: %s (%d)\n", gopt.ids_active_user, gopt.ids_idle);
	// DEBUGF_W("Login: %d, active %d, Total %d\n", new_login.n_items, new_active.n_items, gopt.n_users);

	/* Search through all peers that want IDS messages */
	GS_LIST_ITEM *li = NULL;

	while (1)
	{
		li = GS_LIST_next(&gopt.ids_peers, li);
		if (li == NULL)
			break;

		p = (struct _peer *)li->data;

		add_log(p, &new_login,  GS_PKT_APP_LOG_TYPE_ALERT, "Login : %s");
		add_log(p, &new_active, GS_PKT_APP_LOG_TYPE_ALERT, "Active: %s");
	}

	GS_LIST_del_all(&new_login, 0);
	GS_LIST_del_all(&new_active, 0);

	return 0;
}



