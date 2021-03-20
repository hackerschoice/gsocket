/*
 * A FIFO like buffer to. Used by file transfer as a write-buffer to queue
 * control messages (such as chn_accept, chn_error, ...).
 */
#include "gs-common.h"
#include <gsocket/gsocket.h>
#include "gs-externs.h"

void
GS_BUF_init(GS_BUF *gsb, size_t sz_max_add)
{
	memset(gsb, 0, sizeof *gsb);
	gsb->sz_max_add = sz_max_add;

	// gsb->sz_total = 16*1024*1024; // FIXME
	// gsb->data = malloc(gsb->sz_total); // FIXME

	GS_BUF_resize(gsb, 0);
}

void
GS_BUF_free(GS_BUF *gsb)
{
	XFREE(gsb->data);
	memset(gsb, 0, sizeof *gsb);
}

// Adjust size to have at least sz_min_free available.
int
GS_BUF_resize(GS_BUF *gsb, size_t sz_new)
{
	if (GS_BUF_UNUSED(gsb) >= sz_new + gsb->sz_max_add)
		return 0;

	size_t t = gsb->sz_used + sz_new + gsb->sz_max_add;
	// Round the new size to the next 1k boundary
	gsb->sz_total = t - (t % 1024) + 1024;
	DEBUGF_R("realloc to %zu, used %zu\n", gsb->sz_total, gsb->sz_used);
	gsb->data = realloc(gsb->data, gsb->sz_total);
	if (gsb->data == NULL)
	{
		// Fatal.
		GS_BUF_free(gsb);
		return -1;
	}

	return 0;
}

int
GS_BUF_add_length(GS_BUF *gsb, size_t len)
{
	// Bail. There is sz_max_add space available but looks like caller wrote
	// more data...
	XASSERT(len <= GS_BUF_UNUSED(gsb), "Not enough space in buffer\n");

	gsb->sz_used += len;

	// Resize
	GS_BUF_resize(gsb, 0);

	return 0;
}

int
GS_BUF_add_data(GS_BUF *gsb, void *data, size_t len)
{
	GS_BUF_resize(gsb, len);
	memcpy((uint8_t *)gsb->data + gsb->sz_used, data, len);

	gsb->sz_used += len;

	return 0;
}

int
GS_BUF_printf(GS_BUF *gsb, const char *fmt, ...)
{
	va_list ap;
	int rv;

	va_start(ap, fmt);
	rv = vsnprintf((char *)GS_BUF_WDST(gsb), GS_BUF_UNUSED(gsb), fmt, ap);
	va_end(ap);

	if (rv <= 0)
		return 0;

	if (rv >= GS_BUF_UNUSED(gsb))
	{
		// Make buffer larger...
		GS_BUF_resize(gsb, rv - GS_BUF_UNUSED(gsb) + 1 /*\0*/);
		va_start(ap, fmt);
		rv = vsnprintf((char *)GS_BUF_WDST(gsb), GS_BUF_UNUSED(gsb), fmt, ap);
		va_end(ap);

		if (rv <= 0)
			return 0;
	}

	gsb->sz_used += rv;
	GS_BUF_resize(gsb, 0);

	return 0;
}

int
GS_BUF_memmove(GS_BUF *gsb, void *data, size_t len)
{
	GS_BUF_resize(gsb, len);
	memmove((uint8_t *)gsb->data + gsb->sz_used, data, len);

	gsb->sz_used += len;

	return 0;
}

/*
 * Consume data from beginning.
 */
int
GS_BUF_del(GS_BUF *gsb, size_t len)
{
	XASSERT(gsb->sz_used >= len, "Cant. used=%zu, len=%zu\n", gsb->sz_used, len);
	gsb->sz_used -= len;
	memmove(gsb->data, (uint8_t *)gsb->data + len, gsb->sz_used);

	return 0;
}

