#include "nocrypto.h"

static inline void xor_into (uint8_t *src, uint8_t *dst, size_t n) {

#if defined (__nc_SSE__)
  for (; n >= 16; n -= 16, src += 16, dst += 16)
    _mm_storeu_si128 (
        (__m128i*) dst,
        _mm_xor_si128 (
          _mm_loadu_si128 ((__m128i*) src),
          _mm_loadu_si128 ((__m128i*) dst)));
#endif

  for (; n >= 8; n -= 8, src += 8, dst += 8)
    *(uint64_t*) dst ^= *(uint64_t*) src;

  for (; n --; ++ src, ++ dst) *dst = *src ^ *dst;
}

CAMLprim value
caml_nc_xor_unsafe (value bs1, value off1, value bs2, value off2, value n) {
  xor_into (_bp_uint8_off (bs1, off1), _bp_uint8_off (bs2, off2), Int_val (n));
  return Val_unit;
}

CAMLprim value
caml_nc_xor_ba_unsafe (value b1, value off1, value b2, value off2, value n) {
  xor_into (_ba_uint8_off (b1, off1), _ba_uint8_off (b2, off2), Int_val (n));
  return Val_unit;
}
