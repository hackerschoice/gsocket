#ifndef __CONSOLE_DISPLAY_H__
#define __CONSOLE_DISPLAY_H__ 1

#define CONDIS_LINE_MAX_LEN			(125)
#define CONDIS_MAX_HISTORY			(16)

int GS_condis_init(int fd, int rows);
void GS_condis_add(int color, const char *str);
void GS_condis_log(int color, const char *str);
void GS_condis_pos(int y, int maxlen);
void GS_condis_draw(void);

// enum condis_type = {}

#endif /* !__CONSOLE_DISPLAY_H__ */
