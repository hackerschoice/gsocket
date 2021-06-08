/*
 * Test programm to test gs readline sub-system
 *
 * clear; stty -echo -icanon && ./readline-test 2>x.log; stty echo icanon
 */
#include "common.h"
#include "utils.h"

#define PROMPT	">"
#define PROMPT_LEN  (1)

int is_win_resized = 0;

static void
cb_sigwinch(int sig)
{
	// DEBUGF("Window Size changed\n");
	is_win_resized = 1;
}


static void
my_write(int fd, void *data, size_t len)
{
	if (write(fd, data, len) != len)
		ERREXIT("write()\n");
}

int
main(int argc, char *argv[])
{
	GS_RL_CTX rl;

	GS_library_init(stderr, stderr, NULL);
	gopt.err_fp = stderr;
	gopt.log_fp = stderr;

	get_winsize();

	signal(SIGWINCH, cb_sigwinch);

	GS_RL_init(&rl, gopt.winsize.ws_col - PROMPT_LEN);

	printf("\x1B[%d;%df" PROMPT, gopt.winsize.ws_row, 1);
	fflush(stdout);

	uint8_t c;
	uint8_t key;
	int rv;
	while (1)
	{
		rv = read(0, &c, 1);
		if (rv != 1)
			break;
		rv = GS_RL_add(&rl, c, &key, gopt.winsize.ws_col - PROMPT_LEN, 1 + PROMPT_LEN);
		if (is_win_resized)
		{
			is_win_resized = 0;
			get_winsize();
			printf("\x1B[%d;%df" PROMPT, gopt.winsize.ws_row, 1); fflush(stdout);
			GS_RL_resize(&rl, gopt.winsize.ws_col - PROMPT_LEN, gopt.winsize.ws_row, 1 + PROMPT_LEN);
			my_write(1, rl.vline, rl.v_pos);
		}
		DEBUGF_Y("line(%zd) '%s'\n", rl.len, rl.line);
		HEXDUMP(rl.esc_data, rl.esc_len);
		my_write(1, rl.esc_data, rl.esc_len);
		fflush(stdout);
		// DEBUGF_G("ESCL(%zd) '\x1B[s%s\x1B[u'\n", rl.esc_len, rl.esc_line);

		if (rv == 1)
			continue;
		if (rv < 0)
		{
			if (key != '\n')
				DEBUGF_R("Unhandled control key: %02x\n", key);
			DEBUGF_B("Final line: '%s'\n", rl.line);
			printf("\x1B[%d;%df\x1B[K" PROMPT, gopt.winsize.ws_row, 1); fflush(stdout);

		}

	}

	return 0;
}
