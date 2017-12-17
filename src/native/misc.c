#include "nocrypto.h"


static inline void xor_into (uint8_t *src, uint8_t *dst, size_t n) {

#if defined (__nc_SSSE3__)
  while (n >= 16) {
    _mm_storeu_si128 (
        (__m128i*) dst,
        _mm_xor_si128 (
          _mm_loadu_si128 ((__m128i*) src),
          _mm_loadu_si128 ((__m128i*) dst)));
    src += 16;
    dst += 16;
    n   -= 16;
  }
#endif

  while (n >= 8) {
    *(uint64_t*) dst ^= *(uint64_t*) src;
    src += 8;
    dst += 8;
    n   -= 8;
  }

  while (n --) {
    *dst = *(src ++) ^ *dst;
    dst++;
  }
}

static inline void _nc_count_8_be (uint64_t *init, uint64_t *dst, size_t blocks) {
  uint64_t qw = be64toh (*init);
  while (blocks --) *(dst++) = htobe64 (qw++);
}

/* XXX
 *
 * Counters are garbage. ;_;
 * This code approaches 2/3 of 10-round AES' time on large bulks.
 *
 * What slows things down:
 *   - Naive __uint128_t.
 *   - Loop unrolling.
 */
static inline void _nc_count_16_be (uint64_t *init, uint64_t *dst, size_t blocks) {
  uint64_t qw1 = init[0], qw2 = be64toh (init[1]);
  while (blocks --) {
    dst[0] = qw1;
    dst[1] = htobe64 (qw2);
    if ((++ qw2) == 0) qw1 = htobe64 (be64toh (qw1) + 1);
    dst += 2;
  }
}

static inline void _nc_count_16_be_4 (uint64_t *init, uint64_t *dst, size_t blocks) {
  uint64_t qw1 = init[0];
  uint32_t dw3 = ((uint32_t*) init)[2],
           dw4 = be32toh (((uint32_t*) init)[3]);
  while (blocks --) {
    dst[0] = qw1;
    ((uint32_t*) dst)[2] = dw3;
    ((uint32_t*) dst)[3] = htobe32 (dw4++);
    dst += 2;
  }
}

CAMLprim value
caml_nc_xor_into (value b1, value off1, value b2, value off2, value n) {
  xor_into (_ba_uint8_off (b1, off1), _ba_uint8_off (b2, off2), Int_val (n));
  return Val_unit;
}

#define __export_counter(name, f)                                        \
  CAMLprim value name (value ctr, value dst, value off, value blocks) {  \
    f ( (uint64_t*) Bp_val (ctr),                                        \
        (uint64_t*) _ba_uint8_off (dst, off), Long_val (blocks) );       \
    return Val_unit;                                                     \
  }

__export_counter (caml_nc_count_8_be, _nc_count_8_be);
__export_counter (caml_nc_count_16_be, _nc_count_16_be);
__export_counter (caml_nc_count_16_be_4, _nc_count_16_be_4);
