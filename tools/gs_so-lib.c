#include "common.h"

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


