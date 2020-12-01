/*
 * Used by GS-NETCAT.
 *
 * Console Display is a display area for log messages and other messages.
 * Normally 3 rows and with a history (to scroll up/down).
 *
 * This is where log messages are being displayed.
 */


#include "common.h"
#include "console_display.h"
#include "pkt_mgr.h"
#include "utils.h"

struct condis_line
{
	// int type;
	const char *color_str;
	char line[CONDIS_LINE_MAX_LEN];
};

typedef struct
{
	int fd;
	struct condis_line cdl[CONDIS_MAX_HISTORY];  // Ring Buffer
	int pos_add;
	int pos_display;
	int rows;
	int y;
	int max_char;
} GS_CONDIS;

static GS_CONDIS cd;

int
GS_condis_init(int fd, int rows)
{
	memset(&cd, 0, sizeof cd);
	cd.rows = rows;
	cd.fd = fd;
	cd.y = 25 - rows;
	cd.max_char = 80;

	return 0;
}


void
GS_condis_add(int level, const char *str)
{
	size_t len;
	struct condis_line *cdl = &cd.cdl[cd.pos_add];

	len = MIN(sizeof cdl->line - 1, strlen(str));
	memcpy(cdl->line, str, len);
	cdl->line[len] = 0x00;
	switch (level)
	{
	case GS_PKT_APP_LOG_TYPE_ALERT:
		cdl->color_str = "\x1B[31;1m"; // BRIGHT RED
		break;
	case GS_PKT_APP_LOG_TYPE_NOTICE:
		cdl->color_str = "\x1B[0m\x1B[33m"; // Reset brightness. Yellow
		break;
	case GS_PKT_APP_LOG_TYPE_INFO:
		cdl->color_str = "\x1B[0m\x1B[32m"; // Reset brightness. green
		break;
	default:
		cdl->color_str = NULL; // default color
		break;
	}
	cd.pos_add = (cd.pos_add + 1) % CONDIS_MAX_HISTORY;
}

void
GS_condis_log(int level, const char *str)
{
	char buf[1024];

	snprintf(buf, sizeof buf, "%s %s", GS_logtime(), str);
	GS_condis_add(level, buf);
}

/*
 * Set the position and max line length.
 * Normally called if the dispaly is resized.
 */
void
GS_condis_pos(int y, int max_char)
{
	cd.y = y;
	// Always have space for \0
	cd.max_char = MIN(CONDIS_LINE_MAX_LEN - 1, max_char);
}

// Increase ptr by number of characters added to ptr.
#define SXPRINTF(ptr, len, a...) do {\
	size_t n = snprintf(ptr, len, a); \
	ptr += MIN(n, len); \
} while(0)

/*
 * Draw the console at position and with each string
 * up to max_char length. Add '..' if string is longer...
 */
void
GS_condis_draw(void)
{
	int pos = cd.pos_add - cd.rows;
	if (pos < 0)
		pos += CONDIS_MAX_HISTORY;

	char buf[1024];
	char *end = buf + sizeof (buf) - 1; // Space for \n
	char *ptr = buf;

	ptr += snprintf(ptr, end - ptr, "\x1B[%d;1f", cd.y);
	write(cd.fd, buf, ptr - buf);

	const char *last_color_str = NULL;
	struct condis_line *cdl;
	while (pos != cd.pos_add)
	{
		cdl = &cd.cdl[pos];

		ptr = buf;
		if (last_color_str != cdl->color_str)
		{
			if (cdl->color_str == NULL)
				SXPRINTF(ptr, end - ptr, "\x1B[0m");
			else
				SXPRINTF(ptr, end - ptr, "%s", cdl->color_str);
			last_color_str = cdl->color_str;
		}
		SXPRINTF(ptr, MIN(end - ptr, cd.max_char + 1), "%s", cdl->line);

		pos = (pos + 1) % CONDIS_MAX_HISTORY;
		write(cd.fd, buf, ptr - buf);
		write(cd.fd, "\x1B[K", 3); // Clear to end of line
		if (pos != cd.pos_add)
			write(cd.fd, "\r\n", 2); // Add \n to all but last line		
	}

	// Reset color if last color was not the default color
	if (last_color_str != NULL)
		write(cd.fd, "\x1B[0m", 4);
}






