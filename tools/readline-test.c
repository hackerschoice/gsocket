/*
 * Test programm to test gs readline sub-system
 *
 * clear; stty -echo -icanon && ./readline-test 2>x.log; stty echo icanon
 */
#include "common.h"
#include "utils.h"

int
main(int argc, char *argv[])
{
	GS_RL_CTX rl;

	GS_library_init(stderr, stderr);
	gopt.err_fp = stderr;
	gopt.log_fp = stderr;

	GS_RL_init(&rl, 10);
	int row = 25;
	int col = 60;
	printf("\x1B[%d;%df>", row, col-1);
	fflush(stdout);

	uint8_t c;
	uint8_t key;
	int rv;
	while (1)
	{
		rv = read(0, &c, 1);
		if (rv != 1)
			break;
		rv = GS_RL_add(&rl, c, &key, 25, 60);
		DEBUGF_Y("line(%zd) '%s'\n", rl.len, rl.line);
		HEXDUMP(rl.esc_data, rl.esc_len);
		write(1, rl.esc_data, rl.esc_len);
		fflush(stdout);
		// DEBUGF_G("ESCL(%zd) '\x1B[s%s\x1B[u'\n", rl.esc_len, rl.esc_line);

		if (rv == 1)
			continue;
		if (rv < 0)
		{
			if (key != '\n')
				DEBUGF_R("Unhandled control key: %02x\n", key);
			DEBUGF_B("Final line: '%s'\n", rl.line);
		}

	}

	return 0;
}