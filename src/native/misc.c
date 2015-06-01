#include "nocrypto.h"

#define u_long_s sizeof (unsigned long)


static inline void xor_into (uint8_t *src, uint8_t *dst, size_t n) {
#if defined (__SSE2__)
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
  while (n >= u_long_s) {
    *((u_long *) dst) = *((u_long *) src) ^ *((u_long *) dst);
    src += u_long_s;
    dst += u_long_s;
    n   -= u_long_s;
  }
  while (n-- > 0) {
    *dst = *(src ++) ^ *dst;
    dst++;
  }
}

static inline void nc_count_8_be (uint64_t *init, uint64_t *dst, size_t blocks) {
  uint64_t qw = be64_to_cpu (*init);
  while (blocks --) {
    *dst = cpu_to_be64(qw);
    ++qw;
    ++dst;
  }
}

static inline void nc_count_16_be (uint64_t *init, uint64_t *dst, size_t blocks) {
  uint64_t qw1 = be64_to_cpu  (init[0]),
           qw2 = be64_to_cpu  (init[1]);
  while (blocks --) {
    dst[0] = cpu_to_be64 (qw1);
    dst[1] = cpu_to_be64 (qw2);
    qw1 += ((++qw2) == 0);
    dst += 2;
  }
}


CAMLprim value
caml_nc_xor_into (value b1, value off1, value b2, value off2, value n) {
  xor_into (_ba_uint8_off (b1, off1), _ba_uint8_off (b2, off2), Int_val (n));
  return Val_unit;
}

CAMLprim value
caml_nc_count_8_be (value init, value off1, value dst, value off2, value blocks) {
  nc_count_8_be ( (uint64_t *) _ba_uint8_off (init, off1),
                  (uint64_t *) _ba_uint8_off (dst, off2),
                  Long_val (blocks) );
  return Val_unit;
}

CAMLprim value
caml_nc_count_16_be (value init, value off1, value dst, value off2, value blocks) {
  nc_count_16_be ( (uint64_t *) _ba_uint8_off (init, off1),
                   (uint64_t *) _ba_uint8_off (dst, off2),
                   Long_val (blocks) );
  return Val_unit;
}
