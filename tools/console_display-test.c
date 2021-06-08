
/*
 * Test programm to test the console display sub-system. Needed by GS-NETCAT.
 *
 * clear; stty -echo -icanon && ./console_display-test 2>x.log; stty echo icanon
 *
 * Use A for UP, Z for DOWN and ENTER for new line. R to redraw. Any other key to quit
 */
#include "common.h"
#include "pkt_mgr.h"
#include "utils.h"
#include "console_display.h"

GS_CONDIS cd;

int
main(int argc, char *argv[])
{
	char buf[1024];

	GS_library_init(stderr, stderr, NULL);
	gopt.err_fp = stderr;
	gopt.log_fp = stderr;
	srand(time(NULL));

	DEBUGF("mark\n");
	GS_condis_init(&cd, 1, 3);
	DEBUGF("mark\n");
	GS_condis_pos(&cd, 25-3+1, 80);
	// snprintf(buf, sizeof buf, "*2 Hello 1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890");
	// GS_condis_add(1, buf);

	int i = 0;
	while (1)
	{
		snprintf(buf, sizeof buf, "%d 1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890", i);

		GS_condis_add(&cd, rand() % (GS_PKT_APP_LOG_TYPE_MAX + 1), buf);
		GS_condis_draw(&cd, 0);
		usleep(100 * 1000);
		i++;
		if (i > 16)
			break;
	}

	uint8_t c;
	int rv;
	while (1)
	{
		rv = read(0, &c, 1);
		if (rv != 1)
			break;

		switch (c)
		{
		case 'c':
			GS_condis_clear(&cd);
			GS_condis_draw(&cd, 0);
		case 'a': // scroll UP
			GS_condis_up(&cd);
			GS_condis_draw(&cd, 0);
			break;
		case 'b': // scroll DOWN
		case 'z':
			GS_condis_down(&cd);
			GS_condis_draw(&cd, 0);
			break;
		case 'r':
			GS_condis_draw(&cd, 1 /*force*/);
			break;
		case '\n':
			snprintf(buf, sizeof buf, "%d another new line", i++);
			GS_condis_add(&cd, rand() % (GS_PKT_APP_LOG_TYPE_MAX + 1), buf);
			GS_condis_draw(&cd, 0);
			break;
		case 'q':
		default:
			exit(0);

		}
	}



	return 0;
}
