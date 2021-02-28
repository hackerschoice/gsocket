
#ifndef __GS_SO_UTILS_H__
#define __GS_SO_UTILS_H__ 1

#define GS_AUTHCOOKIE_LEN     (SHA256_DIGEST_LENGTH)  // 32

void authcookie_gen(uint8_t *cookie, const char *secret, uint16_t port);

#endif /* !__GS_SO_UTILS_H__ */