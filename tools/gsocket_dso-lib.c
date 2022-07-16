#include "common.h"
#include "gsocket_dso-lib.h"

struct _gopt gopt; // defined in common.h
#ifdef DEBUG
struct _g_debug_ctx g_dbg_ctx;
#endif

void
authcookie_gen(uint8_t *cookie, const char *secret, uint16_t port)
{
	char buf[128];

	// gs-netcat -I is passed the secret as '<secret>-<port>' and thus
	// when called from gs-netcat -I we do not need to append the port here.
	if (port == 0)
		snprintf(buf, sizeof buf, "AUTHCOOKIE-%s", secret);
	else
		snprintf(buf, sizeof buf, "AUTHCOOKIE-%u-%s", port, secret);

	DEBUGF_Y("AC='%s'\n", buf);
	SHA256((unsigned char *)buf, strlen(buf), cookie);
}




// Add a portrange to the list. Return number of ports added.
// range = '1-65535' or '53' or '22 -    4321'.
static int
gs_portrange_add(struct _gs_portrange_list *l, char *range)
{
	char *ptr = range;
	char *last = range;
	char *end = range + strlen(range);
	uint16_t low = 0;
	uint16_t high = 0;

	while ((*ptr >= '0') && (*ptr <= '9'))
		ptr += 1;

	*ptr = '\0';
	low = atoi(last);
	high = low;
	ptr += 1;

	if (ptr < end)
	{

		// Skip anything that's not a number
		while (ptr < end)
		{
			if ((*ptr >= '0') && (*ptr <= '9'))
				break;

			ptr += 1;
		}

		last = ptr;

		// Skip until non-number.
		while ((*ptr >= '0') && (*ptr <= '9'))
			ptr += 1;

		*ptr = '\0';
		if (ptr - last > 0)
			high = atoi(last);
		if (high < low)
			high = low;
	}

	if (low == 0)
		return 0; // error

	if (l->n_entries >= l->n_max)
	{
		l->n_max += 10;
		l->list = realloc(l->list, l->n_max * sizeof *l->list);
	}
	DEBUGF("Ports %u-%u\n", low, high);
	l->list[l->n_entries].low = low;
	l->list[l->n_entries].high = high;
	l->n_entries += 1;

	return high - low + 1;
}

int
GS_portrange_is_match(struct _gs_portrange_list *l, uint16_t port)
{
	int i;

	for (i = 0; i < l->n_entries; i++)
	{
		if ((l->list[i].low <= port) && (port <= l->list[i].high))
		{
			DEBUGF("%u <= port %u <= %u\n", l->list[i].low, port, l->list[i].high);
			return 1; // TRUE
		}
	}

	return 0; // FALSE
}

// Return the number of ports 
int
GS_portrange_new(struct _gs_portrange_list *l, const char *range_orig)
{
	char *ptr;
	int added = 0; // no port range added (zero)

	DEBUGF("ORIG=%s %zu\n", range_orig, strlen(range_orig));
	char *range = strdup(range_orig);
	char *last = range;
	memset(l, 0, sizeof *l);
	if (range_orig == NULL)
		return 0;

	// Find a range '53' '1-2345' '22-38' among string like ' 53, 1-2456;22-38'
	while (1)
	{
		// Remove all spaces
		while ((*last == ' ') || (*last == ','))
			last += 1;

		// Find deliminator
		ptr = strchr(last, ',');
		if (ptr == NULL)
		{
			ptr = strchr(last, ' ');
			if (ptr == NULL)
			{
				ptr = strchr(last, ';');
				if (ptr == NULL)
					break;
			}
		}
		*ptr = '\0';
		ptr += 1;

		// HERE: '23-3843'
		added += gs_portrange_add(l, last);
		last = ptr;
	}

	added += gs_portrange_add(l, last);

	XFREE(range);
	return added;
}

void
GS_portrange_free(struct _gs_portrange_list *l)
{
	XFREE(l->list);
}

char *
gs_getenv(const char *name)
{
	char *ptr = getenv(name);
	if (ptr == NULL)
		return NULL;
	if (*ptr == '\0')
		return NULL;

	return ptr;
}



