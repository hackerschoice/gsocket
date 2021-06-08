/*
 * Process console-action (ctrl keys) and console-commands and dispatch
 * the action.
 *
 * Handle drawing of console and command line input.
 *
 * https://invisible-island.net/xterm/ctlseqs/ctlseqs.html
 * http://ascii-table.com/ansi-escape-sequences-vt-100.php
 * https://www.andreasen.org/letters/vt100.txt
 * https://www.linuxquestions.org/questions/programming-9/get-cursor-position-in-c-947833/
 */
#include "common.h"
#include <wordexp.h>
#include <dirent.h>
#include "pkt_mgr.h"
#include "console.h"
#include "console_display.h"
#include "utils.h"

#define ESCAPE(string) "\033" string
// #define PTY_RESIZE_STR	ESCAPE("7") ESCAPE("[r") ESCAPE("[9999;9999H") ESCAPE("[6n")
// #define PTY_RESTORE		ESCAPE("8")
// #define PTY_SIZE_STR	ESCAPE("[%d;%dR")
#define UIntClr(dst,bits) dst = dst & (unsigned) ~(bits)

#define GS_CONSOLE_PROMPT		"#!ADM> "
#define GS_CONSOLE_PROMPT_LEN	(sizeof (GS_CONSOLE_PROMPT) - 1)  // without \0
// 1 less than max input so that cursor on last pos looks better
#define GS_CONSOLE_INPUT_LEN	(gopt.winsize.ws_col - GS_CONSOLE_PROMPT_LEN - 1)

#define GS_CON_SB_MAX_USERLEN	8  // StatusBar Max User Len

static void console_reset(void);
static void console_start(void);
static void console_stop(void);
static int console_command(struct _peer *p, const char *cmd);

static uint8_t chr_last;
static int tty_fd = -1;
static int stdout_fd = -1;
static void console_draw(int fd, int force);
static int is_init_called;
static GS_RL_CTX rl;
static int is_console_welcome_msg;
static int is_console_cursor_needs_reset;
static const char *sb_color = "\x1B[44m\x1B[30m"; // Black on Blue

#define GS_CONSOLE_BUF_SIZE	    (1024)
#define GS_CONDIS_ROWS          (GS_CONSOLE_ROWS - 2)

enum _gs_ut_cursor_flags {
	GS_UT_CURSOR_ON    = 0x01,
	GS_UT_CURSOR_OFF   = 0x02
};
enum _gs_ut_cursor_flags ut_cursor;


struct _console_info
{
	char statusbar[512];
	size_t sb_len;
	int is_sb_redraw_needed;
	int is_prompt_redraw_needed;
	float ping_ms;
	uint8_t n_users;
	int load;
	char user[14];
	int sec_idle;

	// Bytes Per Second 
	double last_usec;
	int64_t last_pos;
	double bps;
	double last_bps;

	float ft_last_perc;
	float ft_perc;   // FileTransfer percent completion
};

struct _console_info ci;
GS_CONDIS gs_condis; // ConsoleDisplay

static double
get_usec(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);

	return (double)tv.tv_sec * 1000000 + tv.tv_usec;
}

static void
console_init(int fd)
{
	if (is_init_called)
		return;

	// Use YELLOW if TOR (socks) is being used
	if (gopt.gs_ctx.socks_ip != 0)
		sb_color = "\x1B[43m\x1B[30m"; // Black on Yellow

	DEBUGF_R("prompt size %zd\n", GS_CONSOLE_PROMPT_LEN);
	is_init_called = 1;	// Set also if any of the calls below fail

	ci.last_usec = get_usec();

	GS_RL_init(&rl, gopt.winsize.ws_col - GS_CONSOLE_PROMPT_LEN);
	// GS_RL_init(&rl, 10);

	GS_condis_init(&gs_condis, fd, GS_CONDIS_ROWS /* 3*/);

	stdout_fd = fd;
	// tty_fd = fd;	// mad but works 99% if tty fails
	char *tty_name = ttyname(fd);
	if (tty_name == NULL)
		return;

	tty_fd = open(tty_name, O_RDWR | O_NOCTTY);
	if (tty_fd < 0)
		return;
	int rv;
	struct termios tio;
	rv = tcgetattr(tty_fd, &tio);
    if (rv != 0)
		return;
    UIntClr(tio.c_iflag, ICRNL);
    UIntClr(tio.c_lflag, (ICANON | ECHO));
    tio.c_cflag |= CS8;
    tio.c_cc[VMIN] = 6;
    tio.c_cc[VTIME] = 1;
	rv = tcsetattr(tty_fd, TCSADRAIN, &tio);
	if (rv != 0)
		return;
}

static ssize_t
tty_write(void *src, size_t len)
{
	errno = ENOTTY;

	if (tty_fd < 0)
		return -1;

	errno = 0;
	return write(tty_fd, src, len);
}

static int is_cursor_in_console;

// For the upper tier we do not know the coordinates.
// Rely on Saved-cursor position instead.
static void
cursor_to_ut(void)
{
	char buf[64];
	char *end = buf + sizeof (buf);
	char *ptr = buf;

	// If Upper Tier disabled the cursor then do NOT show it.
	if (ut_cursor == GS_UT_CURSOR_OFF)
		SXPRINTF(ptr, end - ptr, "\x1B[?25l");

	DEBUGF_C("cursor-restore (cursor_to_upper_tier)\n");
	SXPRINTF(ptr, end - ptr, "\x1B""8"); // Restore cursor

	tty_write(buf, ptr - buf);
	is_cursor_in_console = 0;
}

// For the lower tier we know exactly our cordinates.
static void
cursor_to_lt(void)
{
	char buf[64];
	char *end = buf + sizeof (buf);
	char *ptr = buf;

	int row = gopt.winsize.ws_row;
	int col = 1 + GS_CONSOLE_PROMPT_LEN + MIN(rl.pos, rl.visible_len);

	// DEBUGF_W("Cursor to CONSOLE (Lower Tier) (%d:%df)\n", row, col);
	SXPRINTF(ptr, end - ptr, "\x1B[%d;%df", row, col);
	// ESC[?2004l = Reset bracketed paste mode
	if (is_console_cursor_needs_reset)
	{
		SXPRINTF(ptr, end - ptr, "\x1B[?2004l");
		is_console_cursor_needs_reset = 0;
	}

	// If Upper Tier disabled the cursor then show it in console
	// DEBUGF_R("ut-cursor = %d\n", ut_cursor);
	if (ut_cursor == GS_UT_CURSOR_OFF)
		SXPRINTF(ptr, end - ptr, "\x1B[?25h");

	tty_write(buf, ptr - buf);

	is_cursor_in_console = 1;
}

// Add to string and increase visual counter
#define VSADDF(xptr, xend, xv, a...) do{ \
	size_t n; \
	n = snprintf(xptr, xend-xptr, a); \
	xv += n; \
	xptr += n; \
} while(0)


static void
mk_statusbar(void)
{
	char *ptr = ci.statusbar;
	char *end = ptr + sizeof ci.statusbar;
	int row = gopt.winsize.ws_row - (GS_CONSOLE_ROWS - 1);
	size_t vc = 0;  // visible characters

	// DEBUGF_C("mk_statusbar() called\n");
	SXPRINTF(ptr, end - ptr, "\x1B[%d;1f", row);
	SXPRINTF(ptr, end - ptr, "%s", sb_color);

	memset(ptr, ':', end - ptr);

	float ms = ci.ping_ms;
	if (ms >= 1000)
		VSADDF(ptr, end, vc, "[%1.01fs ]", ms / 1000);
	else
		VSADDF(ptr, end, vc, "[%3dms]", (int)ms);

	if (ci.load >= 1000)
		VSADDF(ptr, end, vc, "[Load %02.02f][User(%u) ", (float)ci.load / 100, ci.n_users);
	else
		VSADDF(ptr, end, vc, "[Load % 4.02f][User(%u) ", (float)ci.load / 100, ci.n_users);

	// User name
	VSADDF(ptr, end, vc, "%*s ", GS_CON_SB_MAX_USERLEN, ci.user);

	// IDLE timer
	if (ci.sec_idle < 100)
	{
		SXPRINTF(ptr, end - ptr, "\x1b[31m");
		VSADDF(ptr, end, vc, "%2d sec", ci.sec_idle);
		SXPRINTF(ptr, end - ptr, "\x1B[30m");
	}
	else if (ci.sec_idle / 60 < 100)
		VSADDF(ptr, end, vc, "%2d min", ci.sec_idle / 60);
	else 
		VSADDF(ptr, end, vc, "*idle*");
	VSADDF(ptr, end, vc, "]");

	// BYTES/sec
	char buf[GS_FT_SPEEDSTR_MAXSIZE];
	GS_format_bps(buf, sizeof buf, (int64_t)ci.bps, "/s");
	VSADDF(ptr, end, vc, "[%s]", buf);

	// Percent of FileTransfer completed [99.2%] or [ 0.4%] or [-----]
	if (ci.ft_perc <= 0)
	{
		VSADDF(ptr, end, vc, "[-----]");
	} else {
		char perc[5];
		snprintf(perc, sizeof perc, "%1.1f", ci.ft_perc);
		VSADDF(ptr, end, vc, "[%4s%%]", perc);
	}

	// Fill until end
	size_t v_left = gopt.winsize.ws_col - vc;
	ptr += v_left + 1;

	SXPRINTF(ptr, end - ptr, "\x1B[0m");  // Reset color
	ci.sb_len = ptr - ci.statusbar;

	ci.is_sb_redraw_needed = 1;
}

static void
update_bps(struct _peer *p)
{
	double now_usec;
	int64_t cur_pos;

	now_usec = get_usec();
	cur_pos = p->gs->bytes_read + p->gs->bytes_written;

	ci.last_bps = ci.bps;

	if (now_usec == ci.last_usec)
		ci.bps = 0;
	else
		ci.bps = (cur_pos - ci.last_pos) * 1000000 / (now_usec - ci.last_usec);

	// Slowly adjust BPS to make it appear less jumpy
	ci.bps = ci.last_bps + (ci.bps - ci.last_bps) * 0.8;
	if (ci.bps < 50)
		ci.bps = 0;

	ci.last_usec = now_usec;
	ci.last_pos = cur_pos;

	if (ci.last_bps != ci.bps)
		ci.is_sb_redraw_needed += 1;

	// Percentage of File Transfer
	ci.ft_last_perc = ci.ft_perc;
	GS_FT *ft = &p->ft;
	GS_FT_stats *s = &ft->stats;

	if (s->xfer_amount_scheduled == 0)
		ci.ft_perc = 0;
	else {
		float f = ((float)(s->xfer_amount * 100)/ s->xfer_amount_scheduled);
		ci.ft_perc = MIN(f, 99.9);
	}

	if (ci.ft_last_perc != ci.ft_perc)
		ci.is_sb_redraw_needed += 1;
}

void
CONSOLE_update_pinginfo(struct _peer *p, float ms, int load, char *user, int sec_idle, uint8_t n_users)
{
	int fd = p->fd_out;
	ci.ping_ms = ms;
	ci.load = load;
	ci.n_users = n_users;

	if (strlen(user) > GS_CON_SB_MAX_USERLEN)
		memcpy(user + GS_CON_SB_MAX_USERLEN - 2, "..", 3);

	snprintf(ci.user, sizeof ci.user, "%s", user);
	ci.sec_idle = sec_idle;

	mk_statusbar();
	console_draw(fd, 0);
}

/*
 * Called when the window size changed (sigwinch)
 */
void
CONSOLE_resize(struct _peer *p)
{
	char buf[128];
	char *ptr = buf;
	char *end = buf + sizeof buf;
	int delta;

	DEBUGF_R("RESIZE to %d;%d\n", gopt.winsize.ws_col, gopt.winsize.ws_row);
	if (gopt.is_console)
	{
		delta = gopt.winsize.ws_row - gopt.winsize_prev.ws_row;
		if (delta > 0)
		{
			// Longer:
			// Assign scrolling area. Will reset cursor to 1;1
			SXPRINTF(ptr, end - ptr, "\x1b[1;%dr", gopt.winsize.ws_row - GS_CONSOLE_ROWS);
			// Restore cursor to upper tier
			SXPRINTF(ptr, end - ptr, "\x1B""8");
			// Clear screen
			SXPRINTF(ptr, end - ptr, "\x1B[J");
		}

		if (delta < 0)
		{
			// Shorter: 
			DEBUGF_R("Shorter. ScrollingArea to %d\n", gopt.winsize.ws_row - GS_CONSOLE_ROWS);
			if (is_cursor_in_console)
			{
				DEBUGF_R("cursor is IN console\n");
				SXPRINTF(ptr, end - ptr, "\x1B""8""\x1B[J");
				SXPRINTF(ptr, end - ptr, "\x1B[%dA", 0-delta);
				SXPRINTF(ptr, end - ptr, "\x1B""7");
				SXPRINTF(ptr, end - ptr, "\x1b[1;%dr", gopt.winsize.ws_row - GS_CONSOLE_ROWS);
				SXPRINTF(ptr, end - ptr, "\x1B""8");
			} else {
				DEBUGF_R("cursor is UPPER TIER\n");
				SXPRINTF(ptr, end - ptr, "\x1B[%dS", 0-delta);
				SXPRINTF(ptr, end - ptr, "\x1b[1;%dr", gopt.winsize.ws_row - GS_CONSOLE_ROWS);
				SXPRINTF(ptr, end - ptr, "\x1B""8""\x1B[%dA", 0-delta);
			}
		}
		// do nothing if idendical (no change)
		tty_write(buf, ptr - buf);
	}

	GS_condis_pos(&gs_condis, (gopt.winsize.ws_row - GS_CONSOLE_ROWS) + 1 + 1, gopt.winsize.ws_col);
	GS_RL_resize(&rl, GS_CONSOLE_INPUT_LEN, gopt.winsize.ws_row /*last row*/, 1 + GS_CONSOLE_PROMPT_LEN);
	mk_statusbar();
	console_draw(p->fd_out, 1);
}

void
CONSOLE_update_bps(struct _peer *p)
{
	update_bps(p);

	if (gopt.is_console == 0)
		return;

	// Only redraw if there was a change
	if (ci.is_sb_redraw_needed)
	{
		mk_statusbar();
		console_draw(p->fd_out, 0);
	}
}

/*
 * status bar (sb) is drawn (Normally black on blue background).
 */
static void
GS_sb_draw(int force)
{
	if ((force == 0) && (ci.is_sb_redraw_needed == 0))
		return;
	ci.is_sb_redraw_needed = 0;

	tty_write(ci.statusbar, ci.sb_len);
}


static void
GS_prompt_draw(int force)
{
	char buf[512];
	char *ptr = buf;;
	char *end = buf + sizeof buf;

	if ((force == 0) && (ci.is_prompt_redraw_needed == 0))
		return;
	ci.is_prompt_redraw_needed = 0;

	ptr = buf;
	SXPRINTF(ptr, end - ptr, "\x1B[%d;1f" GS_CONSOLE_PROMPT "%s", gopt.winsize.ws_row /*last*/, rl.vline);
	tty_write(buf, ptr - buf);
}

/*
 * Position active cursor to user input in console
 */
static void
GS_prompt_cursor(void)
{
	char buf[64];
	char *ptr = buf;
	char *end = buf + sizeof buf;

	SXPRINTF(ptr, end - ptr, "\x1B[%d;%zuf", gopt.winsize.ws_row /*last*/, 1 + GS_CONSOLE_PROMPT_LEN + MIN(rl.pos, rl.visible_len));
	tty_write(buf, ptr - buf);
}

void
CONSOLE_draw(int fd)
{
	console_draw(fd, 0);
}

static void
console_draw(int fd, int force)
{
	if (gopt.is_console == 0)
		return;

	int redraw_needed = 0;
	redraw_needed += ci.is_sb_redraw_needed;
	redraw_needed += gs_condis.is_redraw_needed;
	redraw_needed += ci.is_prompt_redraw_needed;
	// DEBUGF_W("CONSOLE DRAW (force=%d, redraw_needed=%d, cursor-in-console=%d)\n", force, redraw_needed, is_cursor_in_console);

	if ((force == 0) && (redraw_needed == 0))
	{
		// DEBUGF("nothing to draw..\n");
		return;
	}

	if (is_cursor_in_console == 0)
	{
		// DEBUGF_G("saving cursor (draw)\n");
		tty_write("\x1B""7", 2);  // Save position (upper tier)
	}

	// Status Bar (Normally black on blue)
	GS_sb_draw(force);

	// Log messages
	GS_condis_draw(&gs_condis, force);

	// Prompt
	GS_prompt_draw(force);

	// Restore cursor position
	if (is_cursor_in_console == 0)
	{
		tty_write("\x1B""8", 2);  // Restore position (upper tier)
		// DEBUGF_G("C restored...(draw)\n");
	} else {
		// if (redraw_needed)
		GS_prompt_cursor();
	}
}

/*
 * Up-Arrow ^[OA or ^[[A
 * Return 0 if more data is needed.
 * Return 1 otherwise (set *esc if arrow received)
 */
static int ca_last;
static int
check_arrow(int *esc, uint8_t c)
{
	*esc = 0;

	if ((c == 0x1b) && (ca_last == 0))
	{
		ca_last = c;
		return 0; // more data needed
	}

	// Not inside ^[ sequence (0x1b)
	if (ca_last == 0)
		return 1;

	if (ca_last == 0x1b)
	{
		if ((c == 'O') || (c == '['))
		{
			ca_last = '[';
			return 0;
		}
		ca_last = 0;
		return 0; // unknonw escape (?)
	}
	if (ca_last == '[')
	{
		*esc = 1;
		ca_last = 0;
		return 1;
	}

	return 1;
}

/*
 * Check for any Ctrl+E in user input.
 *
 * 1. any    == submit=any. Send submit. Return -1
 * 2. ^E + E == submit=^E . Send submit. Return -1
 * 3. ^E == do not submit. Return 0
 * 4. ^E + <known> == do not submit. Open console. Return 'c'
 * 5. ^E + ^E      == submit=^E   . Send ^E + ^E. Return -2
 * == behavior non-screen like:
 * 6. ^E + <other> == submit=other. Send ^E + submit. Return -2
 * ==> behavior screen like (see *#1* below)
 * 6. ^E + <other> == do not submit. Return 0
 *
 * Return 0 : Caller not to process received character (more data required).
 * Return -1: Caller to process character in *submit
 * Return -2: not used.
 * Return >0: Escaped character.
 */
int
CONSOLE_check_esc(uint8_t c, uint8_t *submit)
{
	int esc;

	// DEBUGF_Y("key = 0x%02x\n", c);
 	if (chr_last == GS_CONSOLE_ESC)
 	{
 		if (check_arrow(&esc, c) == 0)
 			return 0; // More data required

 		chr_last = c;
 		switch (c)
 		{
 		case 'A': // UP
 			if (esc == 0)
 				break;
 			if (gopt.is_console == 0)
 				return 0; // Ignore if no console

			DEBUGF_G("^E-UP received. Calling cursor_to_ut()\n");
 			cursor_to_ut();
 			return 0;
 		case 'B': // DOWN
 			if (esc == 0)
 				break;
 			if (gopt.is_console == 0)
 				return 0; // Ignore if no console
 			// Arrow Down
 			cursor_to_lt();
 			return 0;
 		case GS_CONSOLE_ESC_CHR:
 		case GS_CONSOLE_ESC_LCHR:
			DEBUGF_Y("esc-chr (last=0x%02x, this=0x%02x)\n", GS_CONSOLE_ESC, c);
 			*submit = GS_CONSOLE_ESC;
 			return -1;
 		case GS_CONSOLE_ESC:  // ^E + ^E
 			DEBUGF_Y("esc\n");
			*submit = GS_CONSOLE_ESC;
 			chr_last = 0; // reset or ^E+^E+any wont work
			return -1;
 		}
 		return c;	// screen-like (*#1*)

 		// Not reached (non-screen behavior)
		// *submit = c;
		// return -2;
 	}

 	chr_last = c;

 	if (c == GS_CONSOLE_ESC)
 		return 0;

 	*submit = c;
 	return -1;
}

void
CONSOLE_reset(void)
{
	char buf[1024];
	char *ptr = buf;
	char *end = buf + sizeof (buf);

	if (tty_fd < 0)
		return;

	DEBUGF_R("Resetting scolling area (rows %d)\n", gopt.winsize.ws_row);
	if (gopt.is_console)
	{
		ptr = buf;
		// Reset scrolling area. Will set cursor to 1;1.
		// SXPRINTF(ptr, end - ptr, "\x1B[r");
		SXPRINTF(ptr, end - ptr, "\x1b[1;%dr", gopt.winsize.ws_row);
		/* Move cursor to last line */
		SXPRINTF(ptr, end - ptr, "\x1B[9999;9999H");
		/* Restore cursor */
		if (write(stdout_fd, buf, ptr - buf) != ptr - buf)
			ERREXIT("write()\n");
	}

	close(tty_fd);
	tty_fd = -1;
}

struct _pat
{
	char *data;
	size_t len;
	int type;
};

static struct _pat cls_pattern[] = {
	{"\x1B[0J", 4, 1},     // Clear screen from cursor down
	{"\x1B[J", 3, 1},      // Clear screen from cursor down
	{"\x1B[2J", 4, 1},     // Clear entire screen
	{"\x1B""c", 2, 4}        // Reset terminal to initial state
};
static struct _pat sb_pattern[] = {
	{"\x1B[?1049h", 8, 2}, // Switch Alternate Screen Buffer (clears screen)
	{"\x1B[?1049l", 8, 3} // Switch Normal Screen Buffer (clears screen)
};

/*
 * Parse output and check for a any terminal escape sequence that clears
 * the screen.
 *
 * FIXME-PERFORMANCE: Could substitute [J and [2J and [0J with code
 * that goes to last line, then clears line '[K' and then scrools up
 * x line to clear the screen. That way the console would not need
 * to be re-drawn on every 'clear screen' by the app.
 *
 * Return 0 if not found.
 * cls_code = 1 => Clear screen
 * cls_code = 2 => Switched to screen buffer
 * cls_code = 3 => Switched to normal buffer
 *
 * amount => Amount of data save to process (remaining is part of an
 * unfinished ansi sequence).
 */

// Parse through the ansi sequence until it is finished.
// Return length of ansi sequence or 0 if more data is required (ansi sequence hasnt finished yet)
static size_t
ansi_until_end(uint8_t *src, size_t src_sz, int *ignore)
{
	uint8_t *src_end = src + src_sz;
	uint8_t *src_orig = src;

	// Must start with ^[
	XASSERT(*src == '\x1b', "src not starting with 0x1B (0x02%c)\n", *src);
	src += 1;
	*ignore = 0;

	while (src < src_end)
	{
		if (*src == '\x1B')
		{
			// Huh? An ESC inside an ESC sequence?
			*ignore = 1;
			return src - src_orig;
		}

		if (src > src_orig + 16)
		{
			// ESC sequence is to long. We are not interested....
			*ignore = 1;
			return src - src_orig;
		}

		// Check for 2 octet ESC sequence that does not end in A-Za-z
		if (src_orig + 1 == src)
		{
			switch (*src)
			{
			case '8':
			case '7':
			case '>':
			case '<':
			case '=':
			case '\\':
				src++;
				return src - src_orig;
			}
		}

		// Check if this is the end of an ansi sequence
		if ((*src >= 'a') && (*src <= 'z'))
		{
			src++;
			return src - src_orig;
		}

		if ((*src >= 'A') && (*src <= 'Z'))
		{
			src++;
			return src - src_orig;
		}

		src++;
	}

	return 0; // Not enough data // src - src_orig;
}

static size_t
ansi_until_esc(uint8_t *src, size_t src_sz, int *in_esc)
{
	uint8_t *src_end = src + src_sz;
	uint8_t *src_orig = src;

	while (src < src_end)
	{
		if (*src == '\x1B')
		{
			*in_esc = 1;
			// DEBUGF("at pos %zd=0x%02x\n", src - src_orig, *src);
			break;
		}
		src++;
	}

	return src - src_orig;
}

static int in_esc;

// Parse 'src' for an ansi sequence that we might be interested in.
// *tail_len contains a number of bytes if there is an incomplete ansi-sequence (and we
// do not have enough data yet)
//
// Return: Length of data in dst.
static void
ansi_parse(uint8_t *src, size_t src_sz, GS_BUF *dst, size_t *tail_len, int *cls_code, int *sb_code)
{
	uint8_t *src_end = src + src_sz;
	size_t len;
	int ignore;

	*tail_len = 0;
	while (src < src_end)
	{
		if (in_esc)
		{
			len = ansi_until_end(src, src_end - src, &ignore);
			// DEBUGF("esc len=%zd, ignore=%d, dst=%zd, left=%zd\n", len, ignore, GS_BUF_USED(dst), src_end - src);
			if (len == 0)
			{
				// Not enough data
				DEBUGF_R("Not Enough Data. TAIL %zd\n", src_end - src);
				DEBUGF("esc len=%zd, ignore=%d, dst=%zd, left=%zd\n", len, ignore, GS_BUF_USED(dst), src_end - src);
				HEXDUMP(src, src_end - src);
				*tail_len = src_end - src;
				return; //break;
			}

			in_esc = 0;
#ifdef DEBUG
			// Output some ANSI but ignore some often re-occuring codes:
			while (1)
			{
				// if (len <= 4)
					// break;  // Ignore short ones...like [1m
				if ((len == 8) && (src[7] == 'm'))
					break; // Ingore [39;49m to debug 'top'
				if ((len == 5) && (src[4] == 'm'))
					break; // Ingore [39m to debug 'mc'
				if ((len == 4) && (src[3] == 'm'))
					break; // Ingore [1m to debug
				DEBUGF_B("ANSI %.*s\n", (int)len -1, src+1);
				break;
			}
#endif
			if (ignore)
			{
				GS_BUF_add_data(dst, src, len);
				src += len;
				continue;
			}
			int is_substitute = 0;

			// Check if the Upper Tier (ut) wants the cursor prompt ON or OFF
			// Check for this even if the console is closed so that when we open the console
			// that the right cursor can be displayed
			is_substitute = 0;
			while (len == 6)
			{
				if (memcmp(src + 1, "[?25l", 5) == 0)
					ut_cursor = GS_UT_CURSOR_OFF; // OFF
				else if (memcmp(src + 1, "[?25h", 5) == 0)
					ut_cursor = GS_UT_CURSOR_ON; // ON
				else
					break;

				// DEBUGF_R("ut_cursor=%d, in-console=%d\n", ut_cursor, is_cursor_in_console);
				// If cursor is in console then ignore all requests
				if (is_cursor_in_console)
				{
					is_substitute = 1;
					src += len;
					break;
				}
				break;
			}
			if (is_substitute)
				continue;

			// Check for Bracketed paste mode [?2004l
			if (len == 8)
			{
				if (memcmp(src + 1, "[?2004l", 7) == 0)
					is_console_cursor_needs_reset = 0;
				else if (memcmp(src + 1, "[?2004h", 7) == 0)
					is_console_cursor_needs_reset = 1;
			}

			// If console is not open then we do not have to check any other ansi symboles
			if (gopt.is_console == 0)
			{
				GS_BUF_add_data(dst, src, len);
				src += len;
				continue;
			}

			// Replace [2J (clear entire screen) with move to last line. Clear Line. Clear from cursor up
			if ((len == 4) && (memcmp(src + 1, "[2J", 3) == 0))
			{
				// Move to last line. [K => Clear until end of line. [1J => Clear up]]
				GS_BUF_printf(dst, "\x1b[%d;1f\x1b[K\x1b[1J", gopt.winsize.ws_row - GS_CONSOLE_ROWS);
				src += len;
				continue;
			}

			// [J = Clear from cursor down
			// I dont have a solution how to do this more efficient beside re-drawing entire console :/
			// or the need to track the cursor position or request the position from the terminal.
			// If the cursor position is known (as cordinated) then it's easy: Set up new scrolling area.
			// Use [<nnn>S (scroll up n lines) to scroll black.
			// Reset scrolling area to original.
			// if ((len == 3) && (memcmp(src + 1, "[J", 2) == 0))
			// {
			// 	src += len;
			// 	continue;
			// }

			if ((len == 3) && memcmp(src + 1, "[r", 2) == 0)
			{
				DEBUGF_R("Scrolling area reset received.\n");
				if (gopt.is_console)
				{
					GS_BUF_printf(dst, "\x1B[1;%dr", gopt.winsize.ws_row - GS_CONSOLE_ROWS);
					src += len;
					continue;
				}
			}

			// Check if this was a cursor-position request that moved the course
			// outside its boundary (and into our console, like debian's top does (!))
			//  '\x1b' + '[1;1h'
			is_substitute = 0;
			while (1)
			{
				if (len < 6)
					break;
				// DEBUGF_W("len %d\n", len);
				if ((src[len-1] != 'H') && (src[len-1] != 'h'))
					break;
				// search for ';' between src+2 and src+len
				uint8_t *ptr = src+2;
				for (ptr = src + 2; ptr < src+len; ptr++)
				{
					if (*ptr == ';')
						break;
				}
				if (*ptr != ';')
					break;

				int row = atoi((char *)src+2);
				int col = atoi((char *)ptr+1);
				// DEBUGF_W("pos %d:%d\n", row, col);
 				if (row > gopt.winsize.ws_row - GS_CONSOLE_ROWS)
				{
					DEBUGF_R("CURSOR MOVE outside area DENIED. Changed to: %d;%d\n", gopt.winsize.ws_row - GS_CONSOLE_ROWS, col);
					GS_BUF_printf(dst, "\x1B[%d;%dH\r\n", gopt.winsize.ws_row - GS_CONSOLE_ROWS, col);
					src += len;
					is_substitute = 1;
				}
				break;
			}
			if (is_substitute)
				continue;

			// Check for any ANSI sequence that may have cleared the screen:
			int i;
			for (i = 0; i < sizeof cls_pattern / sizeof *cls_pattern; i++)
			{
				if (cls_pattern[i].len != len)
					continue;
				if (memcmp(cls_pattern[i].data, src, len) != 0)
					continue;
				DEBUGF_W("CLS found %d\n", cls_pattern[i].type);
				*cls_code = cls_pattern[i].type;
			}

			// Check for any ANSI sequence that changed Screen Buffer
			for (i = 0; i < sizeof sb_pattern / sizeof *sb_pattern; i++)
			{
				if (sb_pattern[i].len != len)
					continue;
				if (memcmp(sb_pattern[i].data, src, len) != 0)
					continue;
				// Handle if we receive [?1049h + [?1049l in one go then do nothing.
				if (*sb_code == 0)
				{
					*sb_code = sb_pattern[i].type;
				} else {
					if (*sb_code != sb_pattern[i].type)
						*sb_code = 0;
					else
						*sb_code = sb_pattern[i].type;
				}
				DEBUGF_W("SB change found (%d), sb_code set to %d\n", sb_pattern[i].type, *sb_code);
			}

			// We are not interested to substitute it. Let it pass through.
			GS_BUF_add_data(dst, src, len);
			src += len;
		} else {
			// DEBUGF_Y("#%zd not in esc\n", src - src_orig);
			len = ansi_until_esc(src, src_end - src, &in_esc);
			GS_BUF_add_data(dst, src, len);
			src += len; // *src points to ESC or is done.
		}

	}
}

GS_BUF g_dst;
GS_BUF g_ansi;
/*
 * Buffered write to ansi terminal. All output to terminal needs to be analyzed
 * and checked for 'clear screen' ansi code. If found then the console needs
 * to be re-drawn as well.
 *
 * Also need to find a good place to inject ansi sequence to move cursor
 * to upper tier (if in console).
 * 
 * We do this by buffering the output and to only write complete ansi sequences
 * and never an incomplete sequences (as it would then not be possible to issue
 * another ESC sequence to move the cursor).
 * 
 * - Find a good place to inject to move cursor from console to upper tier
 * - If half way inside an ansi sequence then buffer the remaining
 * - Also return if an ansi sequence was sent that clears the screen
 */

// Parse ANSI:
// 1. Find any ansi sequence that clears the screen (so we know when to draw our console again)
// 2. Substitute ESC-sequences with our own to stop console from getting fucked.
// 3. If the ESC-sequence stops half way then write *dst and record
//    the remaining sequence (if we have that much space)
static ssize_t
ansi_write(int fd, void *src, size_t src_len, int *cls_code, int *sb_code)
{
	// size_t amount = 0;
	size_t tail_len = 0;
	size_t src_len_orig = src_len;

	if (!GS_BUF_IS_INIT(&g_dst))
	{
		GS_BUF_init(&g_dst, 1024);
		GS_BUF_init(&g_ansi, 1024);
	}

	if (GS_BUF_USED(&g_ansi) > 0)
	{
		GS_BUF_add_data(&g_ansi, src, src_len);
		src = GS_BUF_DATA(&g_ansi);
		src_len = GS_BUF_USED(&g_ansi);
	}

	// HEXDUMP(src, src_len);
	ansi_parse(src, src_len, &g_dst, &tail_len, cls_code, sb_code);

	if (GS_BUF_USED(&g_dst) > 0)
	{
		if (write(fd, GS_BUF_DATA(&g_dst), GS_BUF_USED(&g_dst)) != GS_BUF_USED(&g_dst))
		{
			DEBUGF_R("Failed to write() all data...\n"); // SHOULD NOT HAPPEN
			return -1;
		}
	}
	GS_BUF_empty(&g_dst);
	GS_BUF_empty(&g_ansi);

	if (tail_len > 0)
	{
		// Use memmove() here because src might be pointing to same data but further along
		GS_BUF_memmove(&g_ansi, src + src_len - tail_len, tail_len);
	}


	// From the caller's perspective this function has processed all data
	// and this function will buffer (if needed) any data not yet passed
	// to 'write()'. Thus return 'len' here to satisfy caller that all supplied
	// data is or will be processed.
	return src_len_orig;
}

static int is_console_before_sb;  // before Alternate Screen Buffer

/*
 * Parse all output and check if the screen is cleared. If so then
 * redraw the console (if console is active)
 *
 * Situation to think about:
 * - console is visible
 * - top switches to frame buffer (console is visible)
 * - console is turned off
 * - top exits.
 * -> Still need to parse all output to check when we switch back to normal
 *    buffer. The console was VISIBILE before we entered 'top' and now
 *    need to be diabled after exiting 'top'.
 * Midnight commander:
 * - console is visible
 * - launch mc. mc does not use Screen Buffer (t should!) but instead remembers
 *   the max screen size.
 * - while in mc, turn the console off. Then exit mc.
 * - mc will set the scroll area as when the console was visibile (but it aint
 *   anymore).
 *
 * FIXME unsolved nested console problem:
 * - Both consoles fight to use ^[7 to save the cursor position:
 *   Start outter gs-netcat. Open console. Move cursor to (outter) Upper Tier.
 *
 *   Start another gs-netcat (inner from within outter). Open console. Sends [7 to save
 *   (*1) cursor position from (inner) Upper Tier. Both consoles are not open (inner & outter).
 *
 *   Outter updates its StatusBar (every second): It sends a [7 to save cursor position
 *   from its Upper Tier.
 *   That [7 request will overwrite the [7 that was sent under (*1) and will now store the position
 *   of the cursor from inners console prompt. When the inner wants to move cursor its upper tier
 *   it will send a [8 but that will move the cursor to its own prompt and not to its upper tier.
 *
 * - Workaround: Always leave cursor in up-most tier. Use a 'fake' cursor for the console
 *   (like '_', [7m) and if cursor is supposed to be in the console then make it invisible
 *   in upper tier (but move it back to upper tier [while invisilbe] as soon as console
 *   update is completed).
 *   The tricky parts are two:
 *   1. The outter does not know if the inner has the cursor in the console or its Upper Tier.
 *      What should happen if ESC-e UP is pressed in outter tier? Cursor ON or OFF?
 *      -> Could be solved by inner sending an 'in-band' custom ESC-sequence to outter that outter
 *      intercepts (or if there is no outter but xterm, then ignored by xterm).
 *   2. The inner does not know when to disable its own fake-cursor (e.g. when outter presses ESC-e DOWN)
 *      to move from its (outter) Upper Tier to (outter) console.
 *      There is no signal send to the inner that its cursor should be disabled because the outter
 *      moved it into its own console.
 */
ssize_t
CONSOLE_write(int fd, void *data, size_t len)
{
	int is_detected_clearscreen = 0;
	int is_sb_detected = 0;

	/* Move cursor to upper tier if cursor inside console */
	if (is_cursor_in_console)
	{
		// DEBUGF_C("CURSOR-restore\n");
		if (ut_cursor == GS_UT_CURSOR_OFF)
			tty_write("\x1B[?25l\x1B""8", 6+2); // Restore cursor to upper tier
		else
			tty_write("\x1B""8", 2); // Restore cursor to upper tier
	}

	ssize_t sz;
	sz = ansi_write(fd, data, len, &is_detected_clearscreen, &is_sb_detected);

	// The write() to upper tier may have set some funky paste modes and
	// screen-buffer modes. Track this (even if console is currently
	// closed - because it may have been closed while in a screen-buffer).

	if (is_cursor_in_console)
	{
		// DEBUGF_C("CURSOR-save\n");
		tty_write("\x1B""7", 2);  // Save new cursor position after writing to upper tier
	}


	// Now check if console needs to be re-drawn
	if (is_sb_detected == 2)
	{
		// Switch to Alternate Screen Buffer detected
		is_console_before_sb = gopt.is_console;
		DEBUGF_W("saving is_console=%d\n", gopt.is_console);
	}

	// DEBUGF_G("cls = %d iscon-before = %d, iscon-now %d\n", is_detected_clearscreen, is_console_before_sb, gopt.is_console);
	if (is_sb_detected == 3)
	{
		// Switched to Normal Screen Buffer detected
		DEBUGF_W("saved-is-console=%d, is_console=%d\n", is_console_before_sb, gopt.is_console);
		if (is_console_before_sb != gopt.is_console)
		{
			// Console has changed while operating on screen buffer
			if (gopt.is_console == 0)
				console_stop();
			else
				console_reset();
		}
	}

	if (is_detected_clearscreen == 4)
	{
		DEBUGF_R("RESET of terminal detected.\n");
		if (gopt.is_console)
			console_reset();
	}

	// Now we can safely return (after we tracked the ansi codes).
	if (gopt.is_console == 0)
		return sz;

	if ((is_detected_clearscreen) || (is_sb_detected))
	 	console_draw(fd, 1 /*force*/);

	if (is_cursor_in_console)
	 	cursor_to_lt();

	return sz;
}

/*
 * Offer data to console for readline. If cursor is in console then
 * we shall read those data in readline style.
 *
 * Return 1 if data was for console.
 * Return 0 otherwise
 */
int
CONSOLE_readline(struct _peer *p, void *data, size_t len)
{
	int fd = p->fd_out;
	uint8_t *src = (uint8_t *)data;
	uint8_t *s_end = src + len;
	uint8_t key;
	int rv;
	int is_got_line = 0;

	if (!(is_cursor_in_console))
		return 0;

	for (; src < s_end; src++)
	{
		rv = GS_RL_add(&rl, *src, &key, gopt.winsize.ws_row, 1 + GS_CONSOLE_PROMPT_LEN);
		if (rl.esc_len > 0)
		{
			if (write(fd, rl.esc_data, rl.esc_len) != rl.esc_len)
				ERREXIT("write()\n");
		}

		if (rv < 0)
		{
			// HERE: Special character (like UP/DOWN or ENTER)
			if (key == '\n')
			{
				is_got_line = 1;
				break;
			} else if (key == 'A') {
				DEBUGF_Y("UP\n");
				GS_condis_up(&gs_condis);
				CONSOLE_draw(gs_condis.fd);
			} else if (key == 'B') {
				GS_condis_down(&gs_condis);
				CONSOLE_draw(gs_condis.fd);
			}
			// Unhandled control character (ignore for input)
			continue;
		}
	}
	if (is_got_line)
	{
		console_command(p, rl.line);
		GS_RL_reset(&rl);
	}
	// DEBUGF("final line: '%s'\n", rl.line);

	return 1;
}

/*
 * Set up terminal to display console (e.g. scroll upper tier up
 * and save cursor location of upper tier).
 * Called when console starts or when change in screenbuffer is detected.
 */
static void
console_reset(void)
{
	char buf[GS_CONSOLE_BUF_SIZE];
	char *end = buf + sizeof (buf);
	char *ptr = buf;
	int row;
	row = gopt.winsize.ws_row - GS_CONSOLE_ROWS;

	int i;
	// Scroll up i lines
	for (i = 0; i < GS_CONSOLE_ROWS; i++)
		SXPRINTF(ptr, end - ptr, "\x1B""D");
	// Move cursor up. Then save cursor pos.
	SXPRINTF(ptr, end - ptr, "\x1B[%dA\x1B""7", GS_CONSOLE_ROWS);
	// Set scrolling area. Will set cursor to 1;1.
	DEBUGF("Setting Scrolling area to %d\n", row);
	SXPRINTF(ptr, end - ptr, "\x1b[1;%dr", row);
	// Restore cursor to saved location
	SXPRINTF(ptr, end - ptr, "\x1B""8");
	tty_write(buf, ptr - buf);
}

static void
console_start(void)
{
	console_reset();

	gopt.is_console = 1;

	cursor_to_lt(); // Start with cursor in console
}

/*
 * configure terminal back to normal (no console)
 */
static void
console_stop(void)
{
	char buf[GS_CONSOLE_BUF_SIZE];
	char *end = buf + sizeof (buf);
	char *ptr = buf;

	// Clear console
	SXPRINTF(ptr, end - ptr, "\x1B[%d;1f", gopt.winsize.ws_row - GS_CONSOLE_ROWS);
	SXPRINTF(ptr, end - ptr, "\x1B[J");
	// Reset scroll size
	SXPRINTF(ptr, end - ptr, "\x1B[r");
	// Upper Tier wants cursor OFF
	if (ut_cursor == GS_UT_CURSOR_OFF)
		SXPRINTF(ptr, end - ptr, "\x1B[?25l");
	// Restore cursor to upper tier (shell)
	SXPRINTF(ptr, end - ptr, "\x1B""8");

	tty_write(buf, ptr - buf);
	is_cursor_in_console = 0;
	gopt.is_console = 0;
}

/*
 * Equivalent to ssh's ~. quick exit.
 */
static int
hard_quit(void)
{
	CONSOLE_reset();
	stty_reset();
	exit(0); // hard exit.
}

/*
 * Process single action keys (e.g. CTRL+E + <action>)
 */
int
CONSOLE_action(struct _peer *p, uint8_t key)
{
	console_init(p->fd_out);

	DEBUGF("\nConsole Key Action 0x%02x\n", key);

	if (key == 'q')
		hard_quit();

#ifdef DEBUG
	if (key == 'l')
	{
		DEBUGF_B("redraw\n");
		mk_statusbar();
		console_draw(p->fd_out, 1);
	}
#endif

	if (key == 'c')
	{
		gopt.is_win_resized = 1; // Trigger: Send new window size to peer
		gopt.is_want_ids_on = 1;
		GS_SELECT_FD_SET_W(p->gs);

		if (gopt.is_console == 1)
		{
			// Close console and restore cursor
			console_stop();
			return 0;
		}

		console_start();

		GS_condis_pos(&gs_condis, (gopt.winsize.ws_row - GS_CONSOLE_ROWS) + 1 + 1, gopt.winsize.ws_col);
		if (is_console_welcome_msg == 0)
		{
			GS_condis_add(&gs_condis, 0, "Press Ctrl-e + c to close this console or Ctrl-e + q to quit.");
			GS_condis_add(&gs_condis, 0, "Press Ctrl-e + UP to leave the console.");
			GS_condis_add(&gs_condis, 0, "Press Ctrl-e + DOWN to enter the console.");
			GS_condis_add(&gs_condis, 0, "Use UP/DOWN to scroll through the console's log");
			GS_condis_add(&gs_condis, 0, "Type 'help' for a list of commands.");
			is_console_welcome_msg = 1;
		}
		// Draw console needed? Resizing remote will trigger a CLEAR (=> re-draw)
		mk_statusbar();
		console_draw(p->fd_out, 1);
	}

	return 0;
}

static void
cmd_help(int fd)
{
	GS_condis_add(&gs_condis, 0, "quit       - Quit          | Ctrl-e q : quit    | Ctrl-e c : toggle console");
	GS_condis_add(&gs_condis, 0, "ping       - RTT to peer   | Ctrl-e UP: Go Up   | Ctrl-e DN: Go Down");
	GS_condis_add(&gs_condis, 0, "put <file> - Upload file   - Example: put /usr/./share/ma*");
	GS_condis_add(&gs_condis, 0, "get <file> - Download file - Example: get ~/*.[ch]");
	GS_condis_add(&gs_condis, 0, "Other commands: lls, lcd, lmkdir, lpwd, pwd");
	GS_condis_draw(&gs_condis, 1);	
}

// Use wordexp(3) to resolve path name with ~/ and variable substitution
static int
path_resolve(const char *pattern, char *dst, size_t len)
{
	wordexp_t p;
	int ret;

	if (len <= 0)
		return -1;

	dst[0] = '\0';
	// On failure return 'pattern' as path 
	snprintf(dst, len, "%.*s", MAX(0, (int)len -1) , pattern);

	signal(SIGCHLD, SIG_DFL);
	ret = wordexp(pattern, &p, WRDE_NOCMD);
	signal(SIGCHLD, SIG_IGN);
	if (ret != 0)
	{
		DEBUGF_R("wordexp(%s) error: %d\n", pattern, ret);
		return -1;
	}

	if (p.we_wordc <= 0)
	{
		wordfree(&p);
		return -1;
	}

	snprintf(dst, len, "%s", p.we_wordv[0]);
	wordfree(&p);

	return 0;
}


static const char *
strip_space(const char *str)
{
	while (*str == ' ')
		str++;
	return str;
}

// Output single file information
static void
cmd_lls_file(const char *name)
{
	struct stat sr;
	if (stat(name, &sr) != 0)
	{
		// ERROR
		GS_condis_printf(&gs_condis, GS_PKT_APP_LOG_TYPE_DEFAULT, "%s: %s", strerror(errno), name);
		return;
	}
#ifdef __APPLE__
	struct timespec ts = sr.st_mtimespec;
#else
	struct timespec ts = sr.st_mtim;
#endif

	struct tm tm;
	localtime_r(&ts.tv_sec, &tm);
	// MS-DOS style output (oldskewl)
	char tmstr[32];
	strftime(tmstr, sizeof tmstr, "%Y-%m-%d %H:%M", &tm);
	const char *typestr = "<\?\?\?>";
	if (S_ISDIR(sr.st_mode))
		typestr = "<DIR>";
	else if (S_ISLNK(sr.st_mode))
		typestr = "<LNK>";
	else if (S_ISFIFO(sr.st_mode))
		typestr = "<FIF>";
	else if (S_ISBLK(sr.st_mode))
		typestr = "<BLK>";
	else if (S_ISCHR(sr.st_mode))
		typestr = "<DEV>";
	else if (S_ISREG(sr.st_mode))
		typestr = "";

	GS_condis_printf(&gs_condis, GS_PKT_APP_LOG_TYPE_DEFAULT, "%16s %5.5s %' 16"PRId64" %s", tmstr, typestr, (int64_t)sr.st_size, name);
}

// List local files.
static void
cmd_lls_single(const char *exp)
{
	wordexp_t p;
	char **w;
	DIR *d = NULL;
	char buf[GS_PATH_MAX];

	int ret;
	signal(SIGCHLD, SIG_DFL);
	ret = wordexp(exp, &p, 0);
	signal(SIGCHLD, SIG_IGN);
	if (ret != 0)
		return; // error (0 found)

	setlocale(LC_NUMERIC, ""); // for printf("'%d" thausand separator

	w = p.we_wordv;
	// If there is only ONE result and that result is a DIRECTORY then output the content
	// of that directory instead. (e.g. 'ls .' or 'ls /tmp')
	struct stat sr;
	if ((p.we_wordc == 1) && (stat(w[0], &sr) == 0) && S_ISDIR(sr.st_mode))
	{
		// Opendir etc..
		d = opendir(w[0]);
		if (d == NULL)
		{
			// ERROR
			GS_condis_printf(&gs_condis, GS_PKT_APP_LOG_TYPE_DEFAULT, "%s: %s", strerror(errno), w[0]);
			goto err;
		}

		struct dirent *entry;
		for (entry = readdir(d); entry != NULL; entry = readdir(d))
		{
			if (memcmp(w[0], ".\0", 2) == 0)
				snprintf(buf, sizeof buf, "%s", entry->d_name);
			else
				snprintf(buf, sizeof buf, "%s/%s", w[0], entry->d_name);
			cmd_lls_file(buf);
		}
	} else {
		int i;
		for (i = 0; i < p.we_wordc; i++)
			cmd_lls_file(w[i]);
	}

err:
	if (d != NULL)
		closedir(d);

	wordfree(&p);
}

static void
cmd_lls(const char *str)
{
	char *orig = strdup(str);
	char *next;
	char *name = orig;


	while (name != NULL)
	{
		next = strchr(name, ' ');
		if (next != NULL)
		{
			*next = '\0';
			next += 1;
		}
		cmd_lls_single(name);
		name = next;
	}

	XFREE(orig);
}

static int
console_command(struct _peer *p, const char *cmd)
{
	int fd = p->fd_out;
	char buf[GS_CONSOLE_BUF_SIZE];
	char path[GS_PATH_MAX + 1];
	char *end = buf + sizeof (buf);
	char *ptr;
	const char *arg;

	if (strlen(cmd) <= 0)
		return 0;
	
	if (memcmp(cmd, "help", 4) == 0)
	{
		cmd_help(fd);
	} else if (memcmp(cmd, "ping", 4) == 0) {
		cmd_ping(p);
	} else if (memcmp(cmd, "quit", 4) == 0) {
		hard_quit();
	} else if (memcmp(cmd, "pwd", 3) == 0) {
		cmd_pwd(p);
	} else if (memcmp(cmd, "clear", 5) == 0) {
		GS_condis_clear(&gs_condis);
		GS_condis_draw(&gs_condis, 1);
	} else if (memcmp(cmd, "put ", 4) == 0) {
		GS_FT_put(&p->ft, cmd+4);
		GS_SELECT_FD_SET_W(p->gs);
	} else if (memcmp(cmd, "get ", 4) == 0) {
		GS_FT_get(&p->ft, cmd+4);
		GS_SELECT_FD_SET_W(p->gs);
	} else if (memcmp(cmd, "xaitax", 6) == 0) {
		GS_condis_add(&gs_condis, GS_PKT_APP_LOG_TYPE_DEFAULT, "Thanks xaitax for testing!");
		GS_condis_draw(&gs_condis, 1);
	} else if (strncmp(cmd, "lpwd", 4) == 0) {
		char *cwd = getcwdx();
		GS_condis_add(&gs_condis, GS_PKT_APP_LOG_TYPE_DEFAULT, cwd);
		XFREE(cwd);
		GS_condis_draw(&gs_condis, 1);
	} else if (strncmp(cmd, "lcd ", 4) == 0) {
		arg = strip_space(cmd + 4);
		path_resolve(arg, path, sizeof path);
		if (chdir(path) != 0)
			GS_condis_printf(&gs_condis, GS_PKT_APP_LOG_TYPE_DEFAULT, "%s: %.512s", strerror(errno), path);
		else {
			char *cwd = getcwdx();
			GS_condis_printf(&gs_condis, GS_PKT_APP_LOG_TYPE_DEFAULT, "%s", cwd);
			XFREE(cwd);
		}
		GS_condis_draw(&gs_condis, 1);
	} else if (strncmp(cmd, "lmkdir ", 7) == 0) {
		arg = strip_space(cmd + 7);
		if (mkdir(arg, 0777) != 0)
		{
			GS_condis_printf(&gs_condis, GS_PKT_APP_LOG_TYPE_DEFAULT, "%s: %.512s", strerror(errno), arg);
			GS_condis_draw(&gs_condis, 1);
		}
	} else if (strncmp(cmd, "lls", 3) == 0) {
		arg = strip_space(cmd + 3);
		if (*arg == 0)
			arg = "."; // 'lls' should be 'lls .' (current directory)
		cmd_lls(arg);
		GS_condis_draw(&gs_condis, 1);
	} else {
		GS_condis_printf(&gs_condis, 0, "Command not known: '%s'", cmd);
		GS_condis_draw(&gs_condis, 1);
	}

	ptr = buf;
	SXPRINTF(ptr, end - ptr, "\x1B[%d;%zuf\x1B[K", gopt.winsize.ws_row, 1 + GS_CONSOLE_PROMPT_LEN);
	tty_write(buf, ptr - buf);

	return 0;
}

