
#ifndef H__NC_AESNI
#define H__NC_AESNI

#include <sys/types.h>

void _nc_aesni_derive_key (const u_char *key, u_char *rk0, u_int rounds);
void _nc_aesni_invert_key (const u_char *rk0, u_char *kr0, u_int rounds);

void _nc_aesni_enc (const u_char src[16], u_char dst[16], const u_char *rk0, u_int rounds);
void _nc_aesni_dec (const u_char src[16], u_char dst[16], const u_char *rk0, u_int rounds);

void _nc_aesni_enc8 (const u_char src[128], u_char dst[128], const u_char *rk0, u_int rounds);
void _nc_aesni_dec8 (const u_char src[128], u_char dst[128], const u_char *rk0, u_int rounds);

int _nc_aesni_rk_size (u_int rounds);

#endif
