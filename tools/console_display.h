#ifndef __CONSOLE_DISPLAY_H__
#define __CONSOLE_DISPLAY_H__ 1

#define CONDIS_LINE_MAX_LEN			(125)
#define CONDIS_MAX_HISTORY			(256)

struct condis_line
{
	const char *color_str;
	char line[CONDIS_LINE_MAX_LEN];
};

typedef struct
{
	int fd;
	struct condis_line cdl[CONDIS_MAX_HISTORY];  // Ring Buffer
	int entries;     // scrolling if less than MAX entries
	int pos_add;     // idx of next used entry
	int pos_display;
	int rows;        // Number of rows. Normally 3
	int y;           // starting top ROW (y-cordinate).
	int max_char;    // Max displayeable characters. Normally 79.
	int is_redraw_needed;
} GS_CONDIS;

int GS_condis_init(GS_CONDIS *cd, int fd, int rows);
void GS_condis_add(GS_CONDIS *cd, int color, const char *str);
void GS_condis_printf(GS_CONDIS *cd, int color, const char *fmt, ...);
void GS_condis_log(GS_CONDIS *cd, int color, const char *str);
void GS_condis_pos(GS_CONDIS *cd, int y, int maxlen);
void GS_condis_draw(GS_CONDIS *cd, int force);
void GS_condis_up(GS_CONDIS *cd);
void GS_condis_down(GS_CONDIS *cd);
void GS_condis_clear(GS_CONDIS *cd);

// enum condis_type = {}

#endif /* !__CONSOLE_DISPLAY_H__ */
