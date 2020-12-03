#ifndef __GS_READLINE_H__
#define __GS_READLINE_H__ 1


#ifdef DEBUG
# define GS_RL_LINE_MAX		(512)
// # define GS_RL_LINE_MAX		(32)
#else
# define GS_RL_LINE_MAX		(512)
#endif
#define GS_RL_VISIBLE_MAX	(127)
#define GS_RL_ESC_MAX		(GS_RL_LINE_MAX + 32) // including ESCs (color & position)

typedef struct
{
	char line[GS_RL_LINE_MAX + 1]; // Full Length without ascii sequence
	char vline[GS_RL_VISIBLE_MAX + 1]; // Might be shorted with '..' at the end
	size_t pos;  // pointing to next unused field in line.
	size_t len;  // Set when '\n' encountered

	size_t visible_len;
	size_t esc_len;	// without 0-termianted string
	char esc_data[GS_RL_ESC_MAX + 1];
	size_t v_pos; // cursor x-position (col) relative to beginning of visible line

	int col;
	int row;
	int is_need_redraw;
	int is_in_esc;
} GS_RL_CTX;

int GS_RL_init(GS_RL_CTX *rl, int len_visible);
int GS_RL_add(GS_RL_CTX *rl, uint8_t c, uint8_t *key, int row, int col);
void GS_RL_reset(GS_RL_CTX *rl);
void GS_RL_resize(GS_RL_CTX *rl, int len, int row, int col);

#endif /* !__GS_READLINE_H__ */