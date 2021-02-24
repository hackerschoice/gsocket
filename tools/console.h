#ifndef __GST_CONSOLE_H__
#define __GST_CONSOLE_H__ 1

// #define GS_CONSOLE_ESC	    0x1d   // ctrl-] (^])
// #define GS_CONSOLE_ESC_CHR  ']'
// #define GS_CONSOLE_ESC_STR  "^]"

// #define GS_CONSOLE_ESC	    0x02   // ctrl-b (^B)
// #define GS_CONSOLE_ESC_CHR  'B'
// #define GS_CONSOLE_ESC_STR  "^B"

#define GS_CONSOLE_ESC	    0x05   // ctrl-E (^E)
#define GS_CONSOLE_ESC_CHR  'E'
#define GS_CONSOLE_ESC_LCHR 'e'
#define GS_CONSOLE_ESC_STR  "^E"

#define GS_CONSOLE_ROWS     (8)    // Status-bar + Display + Prompt

ssize_t CONSOLE_write(int fd, void *data, size_t len);
int CONSOLE_check_esc(uint8_t c, uint8_t *submit);
int CONSOLE_action(struct _peer *p, uint8_t key);
int CONSOLE_command(struct _peer *p, const char *cmd);
void CONSOLE_reset(void);
void CONSOLE_resize(struct _peer *p);
int CONSOLE_readline(struct _peer *p, void *data, size_t len);
void CONSOLE_draw(int fd);

void CONSOLE_update_pinginfo(struct _peer *p, float ms, int load, char *active_user, int sec_idle, uint8_t n_users);
void CONSOLE_update_bps(struct _peer *p);


#endif /* !__GST_CONSOLE_H__ */
