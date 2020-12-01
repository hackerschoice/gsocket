

#include "common.h"
#include "pkt_mgr.h"
#include "utils.h"
#include "console_display.h"

int
main(int argc, char *argv[])
{
	char buf[1024];

	GS_library_init(stderr, stderr);
	gopt.err_fp = stderr;
	gopt.log_fp = stderr;
	srand(time(NULL));

	GS_condis_init(1, 3);
	GS_condis_pos(25-3+1, 80);
	// snprintf(buf, sizeof buf, "*2 Hello 1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890");
	// GS_condis_add(1, buf);

	int i = 0;
	while (1)
	{
		snprintf(buf, sizeof buf, "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890");

		GS_condis_add(rand() % (GS_PKT_APP_LOG_TYPE_MAX + 1), buf);
		GS_condis_draw();
		sleep(1);
		i++;
	}


	return 0;
}