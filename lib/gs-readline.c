#include "gs-common.h"
#include <gsocket/gsocket.h>
#include "gs-externs.h"

#define	GS_RL_DEL		0x7f  /* ^? */

int
GS_RL_init(GS_RL_CTX *rl, int len)
{
	memset(rl, 0, sizeof *rl);

	rl->visible_len = MIN(GS_RL_VISIBLE_MAX, len);
	rl->row = -1;

	return 0;
}


/*
 */
static void
handle_backspace(GS_RL_CTX *rl)
{
	if (rl->pos > 0)
		rl->pos--;
	rl->line[rl->pos] = 0x00;
}

/*
 * Create visible characters based on normal 'key' input
 * and limited to visible_len (may add '..' to start)
 *
 * Create esc-sequence to handle arrow/del/backspace
 *
 * Might be called with key == 0 on resize.
 */
static void
visible_create(GS_RL_CTX *rl, int row, int col, uint8_t key)
{
	char *s_end = rl->line + rl->pos;
	char *src = rl->line;

	// Location of prompt has changed (window resize?)
	if ((rl->row != row) || (rl->col != col))
	{
		// First time. Assume caller has cursor in correct pos
		if (rl->row != -1)
			rl->is_need_redraw = 1;

		rl->row = row;
		rl->col = col;
	}

	if (rl->pos > rl->visible_len)
		rl->is_need_redraw = 1;

	if ((rl->v_pos == 0) && (key == GS_RL_DEL))
	{
		// No data left to delete. Skip.
		rl->esc_len = 0;
		goto done;
	}

	if (rl->is_need_redraw == 0)
	{
		/* Try to just add character */
		if (rl->pos == rl->visible_len)
		{
			// From "..<string>" to "<string>"
			rl->is_need_redraw = 1;
		} else if (rl->pos < rl->visible_len) {
			if (key == GS_RL_DEL)
			{
				// Move left, print \s, move left
				memcpy(rl->esc_data, "\x1B[D \x1B[D", 7);
				rl->esc_len = 7;
				goto done;
			}
			rl->esc_data[0] = key;
			rl->esc_len = 1;
			rl->vline[rl->v_pos] = key;
			goto done;
		}
	}

	if (rl->pos > rl->visible_len)
		src = s_end - rl->visible_len;

	char *d_end = rl->esc_data + GS_RL_ESC_MAX - 1;
	char *ptr = rl->esc_data;

	if (rl->is_need_redraw)
	{
		DEBUGF_Y("moving to %d;%df\n", row, col);
		SXPRINTF(ptr, d_end - ptr, "\x1B[%d;%df", row, col);
	}

	size_t len;
	len = MIN(s_end - src, d_end - ptr);
	memcpy(ptr, src, len);

	// Set '..' is larger than visible length...
	if (rl->pos > rl->visible_len)
		memset(ptr, '.', 2);

	len = MIN(rl->visible_len, rl->pos);
	memcpy(rl->vline, ptr, len);

	len = ptr - rl->esc_data + len;
	XASSERT(len < sizeof (rl->esc_data), "BO len = %zd\n", len);
	rl->esc_data[len] = 0x00;

	rl->esc_len = len;
	rl->is_need_redraw = 0;
done:
	rl->v_pos = MIN(rl->visible_len, rl->pos);
	rl->vline[rl->v_pos] = 0x00;
}

void
GS_RL_reset(GS_RL_CTX *rl)
{
	size_t vl = rl->visible_len;
	int row = rl->row;

	DEBUGF_Y("RL reset\n");
	memset(rl, 0, sizeof *rl);

	rl->visible_len = vl;
	rl->row = row;
}

/*
 * len is the length.
 * row/col is the starting position of the prompt.
 *
 * Should be called every time the screen resizes.
 */
void
GS_RL_resize(GS_RL_CTX *rl, int len, int row, int col)
{
	rl->visible_len = MIN(GS_RL_VISIBLE_MAX, len);
	rl->row = 0; // triggers a is_need_redraw := 1
	visible_create(rl, row, col, 0);
}

/*
 * Offer data to readline.
 *
 * row/col are the cordinated where the input line starts (and to which pos)
 *     the cursor resets when '\n' is hit.
 *
 * Return <0 if it was an unhandled control character (stored in *key)
 *    This is also set if \n is pressed (end of readline input)
 * Return 1 if more data is required.
 */
int
GS_RL_add(GS_RL_CTX *rl, uint8_t c, uint8_t *key, int row, int col)
{
	uint8_t k = 0;

	// rl->is_need_redraw = 1;  // DEFAULT: FIXME-PERFORMANCE
	// ^A or ^OA
	DEBUGF_W("esc=%d c=0x%02x r%d,c%d\n", rl->is_in_esc, c, row, col);
	if (rl->is_in_esc)
	{
		if ((rl->is_in_esc == 1) && (c == 'O'))
		{
			rl->is_in_esc = 2;
			return 1; // More data required.
		}

		int rv = 1;
		if ((c >= 'a') && (c <= 'z'))
			rv = 0;
		else if ((c >= 'A') && (c <= 'Z'))
			rv = 0;
		if (rv == 1)
			return 1; // More data required.

		DEBUGF_W("Out of ESC with c = 0x%02x\n", c);
		rl->is_in_esc = 0;
		k = c;
	}

	if (k != 0)
	{
		// Cursor left
		if (k == 'D')
		{
			handle_backspace(rl);
			visible_create(rl, row, col, GS_RL_DEL);
			return 1;
		}

		// Any other cursor
		// if ((k == 'A') || (k == 'B') || (k == 'C'))
			// return 1;

		goto ret_unhandled;
	}

	if (c == 0x1b)
	{
		DEBUGF_W("Going into escape\n");
		rl->esc_len = 0;
		rl->is_in_esc = 1;
		return 1; // More data required
	}

	if ((c == GS_RL_DEL /*^?*/) || (c == 0x08 /*^H*/))
	{
		// Backspace
		handle_backspace(rl);
		visible_create(rl, row, col, GS_RL_DEL);
		return 1;
	}

	if (c == '\r')
		c = '\n'; // treat all \r as \n

	k = c;
	if (c == '\n')
	{
		/* Enter pressed */
		rl->line[rl->pos] = 0x00;
		rl->len = rl->pos;
		/* Delete visible input from screen */
		if (rl->pos > 0)
		{
			rl->esc_len = 0;
			rl->v_pos = 0;
		}
		rl->pos = 0;

		goto ret_unhandled;
	}

	// Unhandled control character
	if ((c < 0x20) || (c > 0x7E))
	{
		DEBUGF("Unhandled: 0x%02x\n", c);
		goto ret_unhandled;
	}

	if (rl->pos >= GS_RL_LINE_MAX)
		return 1;

	rl->line[rl->pos] = c;
	rl->pos++;
	rl->line[rl->pos] = 0x00;

	visible_create(rl, row, col, c);

	return 1;

ret_unhandled:
	rl->esc_len = 0;
	*key = k;
	return -1;
}
