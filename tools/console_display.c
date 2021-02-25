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

int
GS_condis_init(GS_CONDIS *cd, int fd, int rows)
{
	memset(cd, 0, sizeof *cd);
	cd->rows = rows;
	cd->fd = fd;
	cd->y = 25 - rows;
	cd->max_char = 80;
	cd->pos_display = (cd->pos_add + CONDIS_MAX_HISTORY - cd->rows) % CONDIS_MAX_HISTORY;

	return 0;
}

void
GS_condis_clear(GS_CONDIS *cd)
{
	cd->entries = 0;
	cd->pos_add = 0;
	cd->pos_display = (cd->pos_add + CONDIS_MAX_HISTORY - cd->rows) % CONDIS_MAX_HISTORY;
	cd->is_redraw_needed = 1;
}

void
GS_condis_add(GS_CONDIS *cd, int level, const char *str)
{
	size_t len;
	struct condis_line *cdl = &cd->cdl[cd->pos_add];

	DEBUGF("%s\n", str);
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
	cd->pos_add = (cd->pos_add + 1) % CONDIS_MAX_HISTORY;
	cd->pos_display = (cd->pos_add + CONDIS_MAX_HISTORY - cd->rows) % CONDIS_MAX_HISTORY;
	cd->entries = MIN(CONDIS_MAX_HISTORY, cd->entries + 1);
	cd->is_redraw_needed = 1;
}

void
GS_condis_printf(GS_CONDIS *cd, int level, const char *fmt, ...)
{
	va_list ap;
	char buf[CONDIS_LINE_MAX_LEN];

	va_start(ap, fmt);
	vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);

	GS_condis_add(cd, level, buf);
}

// Add "<TIMESTAMP> <str>" to console display.
void
GS_condis_log(GS_CONDIS *cd, int level, const char *str)
{
	char buf[1024];

	snprintf(buf, sizeof buf, "%s %s", GS_logtime(), str);
	GS_condis_add(cd, level, buf);
}

/*
 * Set the position and max line length.
 * Normally called if the dispaly is resized.
 */
void
GS_condis_pos(GS_CONDIS *cd, int y, int max_char)
{
	cd->y = y;
	// Always have space for \0
	cd->max_char = MIN(CONDIS_LINE_MAX_LEN - 1, max_char);
	cd->is_redraw_needed = 1;
}

void
GS_condis_up(GS_CONDIS *cd)
{
	int apos = cd->pos_add;
	int dpos = cd->pos_display;

	if (dpos >= apos)
		apos += CONDIS_MAX_HISTORY;

	// Here: apos is larger
	if (dpos == apos)
		return; // Cant scroll any further. Out of buffer.

	if (cd->entries <= cd->rows)
		return; // Not enough entries to scroll.

	int max_scroll;
	int scroll;
	max_scroll = cd->entries - (apos - dpos);
	scroll = MIN(cd->rows, max_scroll);

	cd->pos_display = (dpos + CONDIS_MAX_HISTORY - scroll) % CONDIS_MAX_HISTORY;
	cd->is_redraw_needed = 1;
}

void
GS_condis_down(GS_CONDIS *cd)
{
	int apos = cd->pos_add;
	int dpos = cd->pos_display;

	if (dpos >= apos)
		apos += CONDIS_MAX_HISTORY;

	if (dpos + cd->rows >= apos)
		return; // Cant scroll any further. Last entry

	int scroll = MIN(cd->rows, apos - (dpos + cd->rows));
	cd->pos_display = (dpos + scroll) % CONDIS_MAX_HISTORY;
	cd->is_redraw_needed = 1;
}

static void
cd_write(int fd, void *buf, size_t len)
{
	// Failed write() to stdout is fatal. 
	if (write(fd, buf, len) != len)
		ERREXIT("write()\n");
}

/*
 * Draw the console at position and with each string
 * up to max_char length. Add '..' if string is longer...
 *
 * THIS WILL LEAVE THE CURSOR ASTRAY. Use CONSOLE_draw() to correct cursor position.
 */
void
GS_condis_draw(GS_CONDIS *cd, int force)
{
	int pos = cd->pos_display;

	if (force == 0)
	{
		if (cd->is_redraw_needed == 0)
			return;
	}
	cd->is_redraw_needed = 0;

	char buf[1024];
	char *end = buf + sizeof (buf) - 1; // Space for \n
	char *ptr = buf;

	DEBUGF("Moving cursor to %d:1f\n", cd->y);
	SXPRINTF(ptr, end - ptr, "\x1B[%d;1f", cd->y);
	cd_write(cd->fd, buf, ptr - buf);

	const char *last_color_str = NULL;
	struct condis_line *cdl;
	int i = 0;
	for (i = 0; i < cd->rows; i++)
	{
		if (cd->rows - (i+1) < cd->entries)
		{
			cdl = &cd->cdl[pos];
			ptr = buf;
			if (last_color_str != cdl->color_str)
			{
				if (cdl->color_str == NULL)
					SXPRINTF(ptr, end - ptr, "\x1B[0m");
				else
					SXPRINTF(ptr, end - ptr, "%s", cdl->color_str);
				last_color_str = cdl->color_str;
			}
			SXPRINTF(ptr, MIN(end - ptr, cd->max_char + 1), "%s", cdl->line);

			cd_write(cd->fd, buf, ptr - buf);
		}
		pos = (pos + 1) % CONDIS_MAX_HISTORY;
		cd_write(cd->fd, "\x1B[K", 3); // Clear to end of line
		if (i < cd->rows - 1)
			cd_write(cd->fd, "\r\n", 2); // Add \n to all but last line		
	}

	// Reset color if last color was not the default color
	if (last_color_str != NULL)
		cd_write(cd->fd, "\x1B[0m", 4);
}






