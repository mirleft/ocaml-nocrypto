
#if defined (__i386__) || defined (__x86_64__)
#include <x86intrin.h>
#endif

#include "misc.h"

#define u_long_s sizeof (unsigned long)

static inline void xor_into (u_char *src, u_char *dst, u_int n) {
#if defined (__SSE2__)
  while (n >= 16) {
    _mm_storeu_si128 (
        (__m128i*) dst,
        _mm_xor_si128 (
          _mm_loadu_si128 ((__m128i*) src),
          _mm_loadu_si128 ((__m128i*) dst)));
    src += 16 ; dst += 16 ; n -= 16 ;
  }
#endif
  while (n >= u_long_s) {
    *((u_long *) dst) = *((u_long *) src) ^ *((u_long *) dst);
    src += u_long_s ; dst += u_long_s ; n -= u_long_s ;
  }
  while (n > 0) {
    *dst = *(src ++) ^ *dst;
    dst++;
  }
}

CAMLprim value
caml_nc_xor_into (value b1, value off1, value b2, value off2, value n) {
  xor_into (_ba_uchar_off (b1, off1), _ba_uchar_off (b2, off2), Long_val(n));
  return Val_unit;
}
