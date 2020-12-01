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
#include "console.h"
#include "console_display.h"
#include "utils.h"

#define ESCAPE(string) "\033" string
#define PTY_RESIZE_STR	ESCAPE("7") ESCAPE("[r") ESCAPE("[9999;9999H") ESCAPE("[6n")
#define PTY_RESTORE		ESCAPE("8")
#define PTY_SIZE_STR	ESCAPE("[%d;%dR")
#define UIntClr(dst,bits) dst = dst & (unsigned) ~(bits)

#define GS_CONSOLE_PROMPT		"#!ADM> "
#define GS_CONSOLE_PROMPT_LEN	(sizeof (GS_CONSOLE_PROMPT) - 1)  // without \0
// 1 less than max input so that cursor on last pos looks better
#define GS_CONSOLE_INPUT_LEN	(gopt.winsize.ws_col - GS_CONSOLE_PROMPT_LEN - 1)

#define GS_CON_SB_MAX_USERLEN	8  // StatusBar Max User Len

static void console_start(void);
static void console_stop(void);
static int console_command(struct _peer *p, const char *cmd);
static void get_cursor_pos(int *row, int *col);

static uint8_t chr_last;
static int tty_fd = -1;
static int stdout_fd = -1;
static void console_draw(int fd);
static int is_init_called;
static GS_RL_CTX rl;

#define GS_CONSOLE_BUF_SIZE	    (1024)
#define GS_CONDIS_ROWS          (3)

struct _console_info
{
	char statusbar[512];
	size_t sb_len;
	float ping_ms;
	int load;
	char user[14];
	int sec_idle;

	// Bytes Per Second 
	double last_usec;
	int64_t last_pos;
	double bps;
	double last_bps;
};

struct _console_info ci;

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
	DEBUGF_R("prompt size %zd\n", GS_CONSOLE_PROMPT_LEN);
	is_init_called = 1;	// Set also if any of the calls below fail

	ci.last_usec = get_usec();

	GS_RL_init(&rl, gopt.winsize.ws_col - GS_CONSOLE_PROMPT_LEN);
	// GS_RL_init(&rl, 10);

	GS_condis_init(fd, GS_CONDIS_ROWS /* 3*/);

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



static int
readstring(int fd, char *buf, size_t sz, const char *str)
{
    unsigned char last;
    unsigned char c;
    int n;
    int rv = -1;
    char *end = buf + sz;

    if (fd < 0)
    	return -1;

    // signal(SIGALRM, resize_timeout);
    // alarm(10);
    n = read(fd, &c, 1);
    if (n <= 0)
		goto err;

    if (c == 0233)
    {	/* meta-escape, CSI */
		*buf++ = ESCAPE("")[0];
		*buf++ = '[';
    } else {
		*buf++ = (char) c;
    }
    if (c != *str)
		goto err;

    last = str[strlen(str) - 1];	// R
    while (1)
    {
		n = read(fd, &c, 1);
		if (n <= 0)
			goto err;
		*buf++ = c;
		if (c == last)
			break;
		if (buf >= end)
			goto err;
    }

    alarm(0);
    *buf = 0;
    rv = 0;
err:
	// if (rv != 0)
	// {
	// 	signal(SIGALRM, SIG_DFL);
	// 	alarm(0);	// CANCEL alarm
	// }
    return rv;
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

static void
console_cursor_off(void)
{
	tty_write("\x1B[u", 3); // Move cursor to upper tier

	is_cursor_in_console = 0;
}

static void
console_cursor_on(void)
{
	char buf[64];
	char *end = buf + sizeof (buf);
	char *ptr = buf;

	// DEBUGF_W("Console Cursor ON\n");
	// ESC[?2004l = Reset bracketed paste mode
	ptr += snprintf(ptr, end - ptr, "\x1B[%d;%ldf\x1B[?2004l", gopt.winsize.ws_row, 1 + GS_CONSOLE_PROMPT_LEN + MIN(rl.pos, rl.visible_len));
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
	ptr += snprintf(ptr, end - ptr, "\x1B[%d;1f", row);
	ptr += snprintf(ptr, end - ptr, "\x1B[44m\x1B[30m");

	memset(ptr, ':', end - ptr);

	float ms = ci.ping_ms;
	if (ms >= 1000)
		VSADDF(ptr, end, vc, "[%1.01fs ]", ms / 1000);
	else
		VSADDF(ptr, end, vc, "[%3dms]", (int)ms);

	if (ci.load >= 1000)
		VSADDF(ptr, end, vc, "[Load %02.02f][User ", (float)ci.load / 100);
	else
		VSADDF(ptr, end, vc, "[Load % 4.02f][User ", (float)ci.load / 100);

	// User name
	VSADDF(ptr, end, vc, "%*s ", GS_CON_SB_MAX_USERLEN, ci.user);

	// IDLE timer
	if (ci.sec_idle < 100)
	{
		ptr += snprintf(ptr, end - ptr, "\x1b[31m");
		VSADDF(ptr, end, vc, "%2d sec", ci.sec_idle);
		ptr += snprintf(ptr, end - ptr, "\x1B[30m");
	}
	else if (ci.sec_idle / 60 < 100)
		VSADDF(ptr, end, vc, "%2d min", ci.sec_idle / 60);
	else 
		VSADDF(ptr, end, vc, "*idle*");
	VSADDF(ptr, end, vc, "]");

	char buf[8];
	format_bps(buf, sizeof buf, (int64_t)ci.bps);
	VSADDF(ptr, end, vc, "[%s/s]", buf);

	// Fill until end
	size_t v_left = gopt.winsize.ws_col - vc;
	ptr += v_left + 1;

	ptr += snprintf(ptr, end - ptr, "\x1B[0m");  // Reset color
	ci.sb_len = ptr - ci.statusbar;
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
}

void
CONSOLE_update_pinginfo(struct _peer *p, float ms, int load, char *user, int sec_idle)
{
	int fd = p->fd_out;
	ci.ping_ms = ms;
	ci.load = load;

	if (strlen(user) > GS_CON_SB_MAX_USERLEN)
		memcpy(user + GS_CON_SB_MAX_USERLEN - 2, "..", 3);

	snprintf(ci.user, sizeof ci.user, "%s", user);
	ci.sec_idle = sec_idle;

	mk_statusbar();
	console_draw(fd);
}

/*
 * Called when the window size changes (sigwinch)
 */
void
CONSOLE_resize(struct _peer *p)
{
	char buf[128];
	char *ptr = buf;
	char *end = buf + sizeof buf;
	int delta;

	if (gopt.is_console)
	{
		delta = gopt.winsize.ws_row - gopt.winsize_prev.ws_row;
		// currently working on: cursor in console. 1 short, 1 longer
		if (delta > 0)
		{
			// Assign scrolling area. Will reset cursor to 1;1
			ptr += snprintf(ptr, end - ptr, "\x1b[1;%dr", gopt.winsize.ws_row - GS_CONSOLE_ROWS);
			// Restore cursor to upper tier
			if (is_cursor_in_console)
				ptr += snprintf(ptr, end - ptr, "\x1B[u");
			// Clear screen
			ptr += snprintf(ptr, end - ptr, "\x1B[J");
		}

		if (delta < 0)
		{
			// Shorter: 
			if (is_cursor_in_console)
			{
				ptr += snprintf(ptr, end - ptr, "\x1B[u\x1B[J");
				// ptr += snprintf(ptr, end - ptr, "\x1B[%dT", 0-delta);
				ptr += snprintf(ptr, end - ptr, "\x1B[%dA", 0-delta);
				ptr += snprintf(ptr, end - ptr, "\x1B[s");
				ptr += snprintf(ptr, end - ptr, "\x1b[1;%dr", gopt.winsize.ws_row - GS_CONSOLE_ROWS);
				ptr += snprintf(ptr, end - ptr, "\x1B[u");

				// WORKING
				// ptr += snprintf(ptr, end - ptr, "\x1B[u\x1B[J");
				// ptr += snprintf(ptr, end - ptr, "\x1B[%dA", 0-delta);
				// ptr += snprintf(ptr, end - ptr, "\x1B[s");
				// ptr += snprintf(ptr, end - ptr, "\x1b[1;%dr", gopt.winsize.ws_row - GS_CONSOLE_ROWS);
				// ptr += snprintf(ptr, end - ptr, "\x1B[u");
			} else {
				// WORKING
				ptr += snprintf(ptr, end - ptr, "\x1B[%dS", 0-delta);
				ptr += snprintf(ptr, end - ptr, "\x1b[1;%dr", gopt.winsize.ws_row - GS_CONSOLE_ROWS);
				ptr += snprintf(ptr, end - ptr, "\x1B[u\x1B[%dA", 0-delta);
			}
		}
		tty_write(buf, ptr - buf);
	}

	GS_RL_resize(&rl, GS_CONSOLE_INPUT_LEN, gopt.winsize.ws_row, 1 + GS_CONSOLE_PROMPT_LEN);
	mk_statusbar();
	console_draw(p->fd_out);
}

void
CONSOLE_update_bps(struct _peer *p)
{
	update_bps(p);

	if (gopt.is_console == 0)
		return;

	// Only redraw if there was a change
	if (ci.last_bps != ci.bps)
	{
		mk_statusbar();
		console_draw(p->fd_out);
	}
}

static void
console_draw(int fd)
{
	int row = gopt.winsize.ws_row - (GS_CONSOLE_ROWS - 1);
	char buf[2048];
	char *ptr = buf;
	char *end = buf + sizeof (buf);

	if (gopt.is_console == 0)
		return;

	DEBUGF_R("CONSLE DRAW\n");
	GS_condis_pos(row + 1, gopt.winsize.ws_col);

	if (is_cursor_in_console == 0)
		tty_write("\x1B[s", 3);
		// ptr += snprintf(ptr, end - ptr, "\x1B[s");

	tty_write(ci.statusbar, ci.sb_len);
	// END print headline

	GS_condis_draw();

	// START print prompt
	ptr = buf;
	ptr += snprintf(ptr, end - ptr, "\x1B[%d;1f" GS_CONSOLE_PROMPT "%s", row + GS_CONSOLE_ROWS, rl.vline);
	tty_write(buf, ptr - buf);
	// END print prompt

	// Restore cursor position
	if (is_cursor_in_console == 0)
		tty_write("\x1B[u", 3);
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
 * 1. any    == submit=any. Send submit. Return -1
 * 2. ^B + B == submit=^B . Send submit. Return -1
 * 3. ^B == do not submit. Return 0
 * 4. ^B + <known> == do not submit. Open console. Return 'c'
 * 5. ^B + ^B      == submit=^B   . Send ^B + ^B. Return -2
 * == behavior non-screen like:
 * 6. ^B + <other> == submit=other. Send ^B + submit. Return -2
 * ==> behavior scren like (see *#1* below)
 * 6. ^B + <other> == do not submit. Return 0
 */
int
CONSOLE_check_esc(uint8_t c, uint8_t *submit)
{
	int esc;

 	if (chr_last == GS_CONSOLE_ESC)
 	{
 		if (check_arrow(&esc, c) == 0)
 			return 0; // More data required

 		chr_last = c;
 		switch (c)
 		{
 		case 'A':
 			if (esc == 0)
 				break;
 			if (gopt.is_console == 0)
 				return 0; // Ignore if no console

 			console_cursor_off();
 			// console_stop();
 			// gopt.is_console = 0;
 			return 0;
 		case 'B':
 			if (esc == 0)
 				break;
 			if (gopt.is_console == 0)
 				return 0; // Ignore if no console
 			// Arrow Down
 			console_cursor_on();
 			return 0;
 		case GS_CONSOLE_ESC_CHR:
 			*submit = GS_CONSOLE_ESC;
 			return -1;
 		case GS_CONSOLE_ESC:  // ^B + ^B
 			chr_last = 0; // reset or ^B^Bid wont work.
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

	if (gopt.is_console)
	{
		/* Reset scrolling area */
		ptr = buf;
		ptr += snprintf(ptr, end - ptr, "\x1B[r");
		/* Move cursor to last line */
		ptr += snprintf(ptr, end - ptr, "\x1B[9999;9999H");
		/* Restore cursor */
		write(stdout_fd, buf, ptr - buf);
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
	{"\x1B[?1049h", 8, 2}, // Switch Alternate Screen Buffer (clears screen)
	{"\x1B[?1049l", 8, 3}  // Switch Normal Screen Buffer (clears screen)
};

static uint8_t cls_buf[8];
static size_t cls_pos;
/*
 * Parse output and check for a any terminal escape sequence that clears
 * the screen.
 *
 * FIXME-PERFORMANCE: Could substitute [J and [2J and [0J with code
 * that goes to last line, then clears line '[K' and then scrools up
 * x line to clea the screen. That way the console would not need
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
static int in_esc;
static int in_esc_pos;

static void
ansi_parse(void *data, size_t len, size_t *amount, int *cls_code)
{
	uint8_t *src = (uint8_t *)data;
	uint8_t *src_orig = src;
	uint8_t *src_end = src + len;
	int rv = 0;

	while (src < src_end)
	{
		if (*src == '\x1B')
		{
			in_esc = 1;
			*amount = src - src_orig; 
			in_esc_pos = 0;
			/* Start of pattern */
			cls_pos = 0;
		} else {
			if (in_esc == 0)
				goto skip;  // ESC not yet encountered
		}

		// Check when escape finishes
		while (in_esc != 0)
		{
			if (*src == '\x1B')
				break;
			in_esc_pos++;

			if (in_esc_pos == 1)
			{
				// Check if multi character esc sequence
				if (*src == '[')
					break;
				if (*src == '(')
					break;
				if (*src == ')')
					break;
				if (*src == '#')
					break; // Esc-#2
				if (*src == '6')
					break; // Esc-6n
				if (*src == '5')
					break;
				if (*src == '0')
					break;
				if (*src == '3')
					break;
			}

			if (in_esc_pos >= 2)
			{
				if ((*src >= '0') && (*src <= '9'))
					break;
				if (*src == ';')
					break;
				if (*src == '?')
					break;
			}

			/* *src is last character of escape sequence */
			in_esc = 0;
			break;
		}

		/* None of our sequences is longer than this. */
		if (cls_pos >= sizeof cls_buf)
			goto skip;

		/* Record sequence */
		cls_buf[cls_pos] = *src;
		cls_pos++;

		/* Any sequence we are interested in is at least 3 chars long */
		if (cls_pos < 3)
			goto skip;

		/* Check if any ESC sequence matches */
		int i;
		for (i = 0; i < sizeof cls_pattern / sizeof *cls_pattern; i++)
		{
			if (cls_pattern[i].len != cls_pos)
				continue;
			if (memcmp(cls_pattern[i].data, cls_buf, cls_pos) != 0)
				continue;
			rv = cls_pattern[i].type;
			cls_pos = 0;
		}
skip:
		src++;
	}
	// Not stuck inside esc sequence.
	if (in_esc == 0)
		*amount = len;

	*cls_code = rv;
}

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
static uint8_t ansi_buf[64];
static size_t ansi_buf_len;

static ssize_t
ansi_write(int fd, void *data, size_t len, int *cls_code)
{
	size_t amount;

	ansi_parse(data, len, &amount, cls_code);
	// DEBUGF_W("len = %zd amount = %zd\n", len, amount);
	if (amount == 0)
		goto done;
	if (ansi_buf_len > 0)
	{
		write(fd, ansi_buf, ansi_buf_len);
		ansi_buf_len = 0;
	}

	write(fd, data, amount);

	if (amount < len)
	{
		uint8_t *end = ansi_buf + sizeof (ansi_buf);
		uint8_t *ptr = ansi_buf + ansi_buf_len;

		XASSERT(end - ptr >= len - amount, "ANSI buffer to small\n");

		memcpy(ptr, (uint8_t *)data + amount, len - amount);
		ansi_buf_len += (len - amount);
		// HEXDUMPF(ansi_buf, ansi_buf_len, "ansi buffer (%zd)", ansi_buf_len);
	}

done:
	return len;
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
 * FIXME: mc issue such as these
 * - console is visible
 * - launch mc. mc does not use Screen Buffer (as it should!) but instead remembers
 *   the max screen size.
 * - while in mc, turn the console off. Then exit mc.
 * - mc will set the scroll area as when the console was visibile (but it aint
 *   anymore).
 */
ssize_t
CONSOLE_write(int fd, void *data, size_t len)
{
	int is_detected_clearscreen = 0;

	/* Move cursor to upper tier if cursor inside console */
	if (is_cursor_in_console)
		tty_write("\x1B[u", 3); // Restore cursor

	ssize_t sz;
	sz = ansi_write(fd, data, len, &is_detected_clearscreen);

	// if (len > 16)
		// HEXDUMP(data, MIN(16, len));

	if (is_cursor_in_console)
		tty_write("\x1B[s", 3);  // Save cursor position

	if (is_detected_clearscreen == 2)
	{
		// Switch to Alternate Screen Buffer detected
		is_console_before_sb = gopt.is_console;
	}

	// DEBUGF_G("cls = %d before = %d, now %d\n", is_detected_clearscreen, is_console_before_sb, gopt.is_console);
	if (is_detected_clearscreen == 3)
	{
		// Switched to Normal Screen Buffer detected
		if (is_console_before_sb != gopt.is_console)
		{
			// Console has changed while operating on screen buffer
			if (gopt.is_console == 0)
				console_stop();
			else
				console_start();
		}
	}

	if (gopt.is_console == 0)
		return sz;

	if (is_detected_clearscreen)
	 	console_draw(fd);

	 if (is_cursor_in_console)
	 	console_cursor_on();

	return sz;
}


/*
 * Offer data to console for readline. If cursor is in console then
 * we shall read those data in readline style.

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
		rv = GS_RL_add(&rl, *src, &key, GS_CONSOLE_INPUT_LEN, 1 + GS_CONSOLE_PROMPT_LEN);
		// HEXDUMP(rl.esc_data, rl.esc_len);
		write(fd, rl.esc_data, rl.esc_len);

		if (rv < 0)
		{
			if (key == '\n')
			{
				is_got_line = 1;
				break;
			}
			/* Unhandled control character */
			continue;
		}

		// Move Cursor & Write visible line
		// ptr = buf;
		// ptr += snprintf(ptr, end - ptr, "\x1B[%d;%luf%s", gopt.winsize.ws_row, GS_CONSOLE_PROMPT_LEN, rl.visible_line);
	}
	if (is_got_line)
	{
		console_command(p, rl.line);
		GS_RL_reset(&rl);
	}
	// DEBUGF("final line: '%s'\n", rl.line);

	// FIXME STOP HERE: Handle action characters
	return 1;
}

static void
get_cursor_pos(int *row, int *col)
{
	*row = -1;
	*col = -1;
	int rv;
	char buf[64];

	tty_write("\x1b" "[6n", 4);
    rv = readstring(tty_fd, buf, sizeof buf, PTY_SIZE_STR);

    if (rv == 0)
	    sscanf(buf, PTY_SIZE_STR, row, col);

	DEBUGF_G("Current Cursor row=%d col=%d\n", *row, *col);
}

// static void
// set_cursor_pos(int row, int col)
// {
// 	char buf[64];
// 	ssize_t len;

// 	len = snprintf(buf, sizeof buf, "\x1B[%d;%df", row, col);

// 	tty_write(buf, len);
// 	DEBUGF_G("Moving cursor to row=%d col=%d\n", row, col);
// }

/*
 * Set up terminal to display console (e.g. scroll upper tier up
 * and save cursor location of upper tier).
 */
static void
console_start(void)
{
	char buf[GS_CONSOLE_BUF_SIZE];
	char *end = buf + sizeof (buf);
	char *ptr = buf;
	int row;
	row = gopt.winsize.ws_row - GS_CONSOLE_ROWS;

	// Get cursor's current location.
	// int rv;
	int current_row;
	int current_col;
	get_cursor_pos(&current_row, &current_col);

	// Current cursor is inside console's space. Scroll up...
	if (current_row > row)
		ptr += snprintf(ptr, end - ptr, "\x1b[%dS", current_row - row);

	// Reduce scrolling area (will reset cursor to 0;0)
	ptr += snprintf(ptr, end - ptr, "\x1b[1;%dr", row);

	// We scrolled up. Cursor was in console area. Set to last row.
	int new_row = current_row; // Default: Leave cursor where it was
	if (current_row > row)
		new_row = row;	// Set cursor to last row of new scrolling area

	// Adjust cursor to new location after [r moved it to 0;0
	ptr += snprintf(ptr, end - ptr, "\x1b[%d;%dH", new_row, current_col);

	// Save the cursor location from upper tier
	ptr += snprintf(ptr, end - ptr, "\x1B[s");

	tty_write(buf, ptr - buf);
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
	ptr += snprintf(ptr, end - ptr, "\x1B[%d;1f", gopt.winsize.ws_row - GS_CONSOLE_ROWS - 1);
	ptr += snprintf(ptr, end - ptr, "\x1B[J");
	// Reset scroll size
	ptr += snprintf(ptr, end - ptr, "\x1B[r");
	// Restore cursor to upper tier (shell)
	ptr += snprintf(ptr, end - ptr, "\x1B[u");
	tty_write(buf, ptr - buf);
	is_cursor_in_console = 0;
}

int
CONSOLE_action(struct _peer *p, uint8_t key)
{
	console_init(p->fd_out);

	DEBUGF("\nConsole Key Action 0x%02x\n", key);

	if (key == 'q')
		exit(0);

	if (key == 'c')
	{
		/* Trigger: Send new window size to peer */
		gopt.is_win_resized = 1;
		GS_SELECT_FD_SET_W(p->gs);

		if (gopt.is_console == 1)
		{
			// Close console and restore cursor
			console_stop();
			gopt.is_console = 0;
			return 0;
		}

		console_start();
		gopt.is_console = 1;

		// Draw console neede? Resizing remote will trigger a CLEAR (=> re-draw)
		mk_statusbar();
		console_draw(p->fd_out);
		console_cursor_on();
	}

	return 0;
}

static void
cmd_help(int fd)
{
	// char buf[GS_CONSOLE_BUF_SIZE];
	// char *end = buf + sizeof (buf);
	// char *ptr = buf;
	// ptr += snprintf(ptr, end - ptr, "\x1B[%d;1f", gopt.winsize.ws_row - GS_CONSOLE_ROWS + 2);
	// ptr += snprintf(ptr, end - ptr, ""

	// tty_write(buf, ptr - buf);

	GS_condis_add(0, "quit       - Quit          | Ctrl-e q : quit    | Ctrl-e c : toggle console");
	GS_condis_add(0, "put <file> - Upload file   | Ctrl-e UP: Go Up   |");
	GS_condis_add(0, "get <file> - Download file | Ctrl-e DN: Go Down |");
	GS_condis_draw();	
}



static int
console_command(struct _peer *p, const char *cmd)
{
	int fd = p->fd_out;
	char buf[GS_CONSOLE_BUF_SIZE];
	char *end = buf + sizeof (buf);
	char *ptr;
	int row = gopt.winsize.ws_row - (GS_CONSOLE_ROWS - 1);

	if (memcmp(cmd, "help", 4) == 0)
	{
		cmd_help(fd);
	} else if (memcmp(cmd, "ping", 4) == 0) {
		cmd_ping(p);
	} else if (memcmp(cmd, "quit", 4) == 0) {
		exit(0); // hard exit.
	} else {
		snprintf(buf, sizeof buf, "Command not known: '%s'", cmd);
		GS_condis_add(0, buf);
		GS_condis_draw();
	}

	ptr = buf;
	ptr += snprintf(ptr, end - ptr, "\x1B[%d;%luf\x1B[K", row + GS_CONSOLE_ROWS, 1 + GS_CONSOLE_PROMPT_LEN);
	tty_write(buf, ptr - buf);

	return 0;
}

