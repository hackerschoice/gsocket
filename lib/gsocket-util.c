
#include "gs-common.h"
#include <gsocket/gsocket.h>
#include "gs-externs.h"

static char *
user_secret_from_stdin(GS_CTX *ctx)
{
	size_t n = 0;
	char *ptr = NULL;
	ssize_t len;

	while (1)
	{
		fprintf(ctx->out, "Enter Secret (or press Enter to generate): ");
		fflush(ctx->out);
		len = getline(&ptr, &n, stdin);
		XASSERT(len > 0, "getline()\n");
		if (ptr[len - 1] == '\n')
			ptr[len - 1] = 0;	// Remove '\n' 
		if (strlen(ptr) == 0)
			return NULL;
		if (strlen(ptr) >= 16)
			break;
		fprintf(ctx->out, "Too short. Minimum length of 16 characters.\n");
		fflush(ctx->out);
	}

	return strdup(ptr);
}


static char *
user_secret_from_file(const char *file)
{
	FILE *fp;
	char buf[256];
	int ret;

	if (file == NULL)
		return NULL;

	memset(buf, 0, sizeof buf);
	fp = fopen(file, "r");
	if (fp == NULL)
		return NULL;

	ret = fread(buf, 1, sizeof buf - 1, fp);
	fclose(fp);

	if (ret <= 0)
		return NULL;
	if (buf[ret-1] == '\n')
		buf[ret-1] = 0;

	return strdup(buf);
}

const char *
GS_gen_secret(void)
{
	int ret;

	GS_library_init();

	/* Generate a new secret */
	uint8_t buf[GS_SECRET_MAX_LEN + 1];
	ret = RAND_bytes(buf, GS_SECRET_MAX_LEN);
	XASSERT(ret == 1, "RAND_bytes() failed.\n");

	GS_ADDR addr;
	GS_ADDR_bin2addr(&addr, buf, GS_SECRET_MAX_LEN);

	return strdup(addr.b58str);
}

const char *
GS_user_secret(GS_CTX *ctx, const char *sec_file, const char *sec_str)
{
	const char *ptr;
	DEBUGF("mark\n");

	/* Secret from file has priority of sec_str value */
	ptr = user_secret_from_file(sec_file);
	if (ptr != NULL)
		return ptr;

	/* If sec_str is set by command line parameters then use it */
	if (sec_str != NULL)
		return sec_str;

	/* Ask user to enter a secret or if empty generate one */
	ptr = user_secret_from_stdin(ctx);
	if (ptr != NULL)
		return ptr;

	/* Genexrate a new secret */
	ptr = GS_gen_secret();

	return ptr;
}