/*
 * For GS-NETCAT.
 * 
 * Monitor various aspect of the system (such as new user login
 * and idle time of users).
 */


#include "common.h"
#include "pkt_mgr.h"
#include "utils.h"

struct utmp_db_user
{
	char user[UT_NAMESIZE];
	char msg[128];
	int idle;
	int idle_old;
	int token;
};

GS_LIST udb;
static int is_udb_init;

static int
utmp_db_find(const char *needle, struct utmp_db_user **uret)
{
	GS_LIST_ITEM *li = NULL;

	while (1)
	{
		li = GS_LIST_next(&udb, li);
		if (li == NULL)
			break;

		struct utmp_db_user *u = (struct utmp_db_user *)li->data;
		if (strcmp(u->user, needle) != 0)
			continue;

		// User Name matches the needle
		*uret = u;
		return 0;
	}

	*uret = NULL;
	return -1; // User Name not found
}

static struct utmp_db_user *
utmp_db_add(const char *user, int idle, int token)
{
	struct utmp_db_user *new;

	DEBUGF_C("Adding new user %s with idle %d\n", user, idle);
	new = malloc(sizeof *new);
	new->idle = idle;
	new->idle_old = 0;
	new->token = token;
	snprintf(new->user, sizeof new->user, "%s", user);

	GS_LIST_add(&udb, NULL, new, new->idle);

	return new;
}

/*
 */
void
GS_IDS_utmp_free(void)
{
	GS_LIST_ITEM *li = NULL;

	while (1)
	{
		li = GS_LIST_next(&udb, NULL);
		if (li == NULL)
			break;

		XFREE(li->data);
		GS_LIST_del(li);
	}

	is_udb_init = 0;
}

// When to consider a user transitioning from IDLE to not IDLE
#ifdef DEBUG
#define IDLE_THRESHOLD		(10)
#else
#define IDLE_THRESHOLD		(60 * 60)  // 1h
#endif

/*
 * Call every second.
 * Compare DB from memory with utmp file.
 *
 * Find any new user.
 * Find any known user that is no longer idle.
 * Find least idle user.
 */
void
GS_IDS_utmp(GS_LIST *new_login, GS_LIST *new_active, char **least_idle, int *sec_idle, int *n_users)
{
	struct utmpx *ut;
	int idle;
	int ret;
	struct stat s;
	char buf[MAX(UT_NAMESIZE, 128)];
	int token = gopt.tv_now.tv_sec;

	if (is_udb_init == 0)
	{
		GS_LIST_init(&udb, 0);
	}
	*least_idle = NULL;
	*sec_idle = INT_MAX;

	gettimeofday(&gopt.tv_now, NULL);
	setutxent();
	while ((ut = getutxent()) != NULL)
	{
		if (ut->ut_type != USER_PROCESS)
			continue;
		ut->ut_user[UT_NAMESIZE - 1] = 0x00;  // be sure for strcmp...

		// Get idle time of the user's tty
		snprintf(buf, sizeof buf, "/dev/%s", ut->ut_line);
		stat(buf, &s);
		idle = MAX(0, gopt.tv_now.tv_sec - s.st_atime);

		struct utmp_db_user *u;
		snprintf(buf, sizeof buf, "%s", ut->ut_user); // -Wstringop-overflow
		ret = utmp_db_find(buf, &u);
		if (ret != 0)
		{
			// NOT found. Add user.
			u = utmp_db_add(ut->ut_user, idle, token);
			if (is_udb_init != 0)
			{
				snprintf(u->msg, sizeof u->msg, "%.20s [%.20s]", ut->ut_user, ut->ut_host[0]?ut->ut_host:"console");

				DEBUGF("New Login detected '%s'\n", u->msg);
				GS_LIST_add(new_login, NULL, u->msg, 0);
			}
		} else {
			// Update idle if this is a new run over utmp.
			// Otherwise u->idle will never get larger when user
			// idles. Slower method would be to set all records
			// u->idle to INT_MAX before while loop.
			if (u->token != token)
			{
				u->token = token;
				u->idle = idle;
			}
			// Update current user's idle if lower.
			if (idle < u->idle)
			{
				// DEBUGF_W("Updating idle to %d of user %s\n", idle, u->user);
				u->idle = idle;
			}
		}
		XASSERT(u != NULL, "utmp entry is NULL\n");

		if (idle > *sec_idle)
			continue;
		// HERE: least idle user (so far)
		*sec_idle = idle;
		*least_idle = u->user;
	}
	endutxent();

	if (is_udb_init == 0)
		goto done;

	// Check which user has awoken (from IDLE to NOT IDLE)
	GS_LIST_ITEM *li = NULL;
	li = GS_LIST_next(&udb, NULL);
	while (li != NULL)
	{
		if (li == NULL)
			break;

		struct utmp_db_user *u = (struct utmp_db_user *)li->data;
		if (u->token != token)
		{
			// User in db is no longer in utmp. Remove from db.
			DEBUGF("Removing DB user %s\n", u->user);
			GS_LIST_ITEM *next = GS_LIST_next(&udb, li);
			XFREE(li->data);
			GS_LIST_del(li);
			li = next;
			continue;
		}

		if ((u->idle_old >= IDLE_THRESHOLD) && (u->idle < u->idle_old))
		{
			snprintf(u->msg, sizeof u->msg, "%.20s [idled for %d mins]", u->user, u->idle_old / 60);
			GS_LIST_add(new_active, NULL, u->msg, 0);
			DEBUGF_R("Now ACTIVE (was %d, now %d): '%s'\n", u->idle_old, u->idle, u->msg);
		}
		u->idle_old = u->idle;
		li = GS_LIST_next(&udb, li);
	}

done:
	*n_users = udb.n_items;
	is_udb_init = 1;
}


static void
add_log_str(struct _peer *p, uint8_t type, const char *str)
{
	struct _pkt_app_log *log = malloc(sizeof *log);
	log->type = type;
	snprintf((char *)log->msg, sizeof log->msg, "%.62s", str);
	GS_LIST_add(&p->logs, NULL, log, GS_LIST_ID_COUNT(&p->logs));
	p->is_pending_logs = 1;
	GS_SELECT_FD_SET_W(p->gs);
}
/*
 * Report to any other connected GS-PEER (that is requesting IDS info)
 * that a new GS user has logged in via gs-netcat.
 */
void
ids_gs_login(struct _peer *self_peer)
{
	GS_LIST_ITEM *li = NULL;
	struct _peer *other_peer;

	while (1)
	{
		li = GS_LIST_next(&gopt.ids_peers, li);
		if (li == NULL)
			break;

		other_peer = (struct _peer *)li->data;
		if (self_peer == other_peer)
			continue;  // Do not send to myself

		char buf[128];
		snprintf(buf, sizeof buf, "[%d] GS login detected. Total Users: %d.", self_peer->id, gopt.peer_count);
		add_log_str(other_peer, GS_PKT_APP_LOG_TYPE_INFO /*green*/, buf);
	}
}

void
ids_gs_logout(struct _peer *self_peer)
{
	GS_LIST_ITEM *li = NULL;
	struct _peer *other_peer;

	while (1)
	{
		li = GS_LIST_next(&gopt.ids_peers, li);
		if (li == NULL)
			break;

		other_peer = (struct _peer *)li->data;
		if (self_peer == other_peer)
			continue;  // Do not send to myself
		char buf[128];
		snprintf(buf, sizeof buf, "[%d] GS logout detected. Remaining Users: %d%s.", self_peer->id, gopt.peer_count - 1, (gopt.peer_count-1)==1?" {you}":"");

		add_log_str(other_peer, GS_PKT_APP_LOG_TYPE_NOTICE /*yellow*/, buf);
	}
}


