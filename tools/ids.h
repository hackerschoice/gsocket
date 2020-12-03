#ifndef __GS_IDS_H__
#define __GS_IDS_H__ 1

void GS_IDS_utmp(GS_LIST *new, GS_LIST *new_active, char **least_idle, int *sec_idle, int *n_users);
void ids_gs_login(struct _peer *self_peer);
void ids_gs_logout(struct _peer *self_peer);


#endif /* !__GS_IDS_H__ */