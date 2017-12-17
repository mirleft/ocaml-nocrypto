/* Copyright (c) 2017 David Kaloper Meršinjak. All rights reserved.
 * See LICENSE.md.
 *
 *
 * References:
 * - Intel Carry-Less Multiplication Instruction and its Usage for Computing the
 *   GCM Mode. Shay Gueron and Michael E. Kounavis.
 *   https://software.intel.com/sites/default/files/managed/72/cc/clmul-wp-rev-2.02-2014-04-20.pdf
 *
 * */


/* #define __NC_GHASH_KARATSUBA */
/* #define __NC_GHASH_REFLECTED_REDUCE */

#include "../nocrypto.h"
#if defined (__nc_PCLMUL__)

#include <string.h>

#define xor(a, b) _mm_xor_si128 (a, b) 
#define xor4(a, b, c, d) xor (xor (a, b), xor (c, d))

static inline __m128i __slli_128 (__m128i a, uint8_t bits) {
  return _mm_or_si128 (
    _mm_slli_epi64 (a, bits),
    _mm_srli_epi64 (_mm_slli_si128 (a, 8), 64 - bits) );
}

/* Shifts by up to 64 bits, pretty unconvincingly.
 * See if there is a more direct way. */
static inline void __slli_256 (__m128i *r1, __m128i *r0, __m128i w1, __m128i w0, uint8_t bits) {
  __m128i t1 = _mm_slli_epi64 (w1, bits),
          t0 = _mm_slli_epi64 (w0, bits),
          s1 = _mm_or_si128 (_mm_slli_si128 (w1, 8), _mm_srli_si128 (w0, 8)),
          s0 = _mm_slli_si128 (w0, 8);

  *r1 = _mm_or_si128 (t1, _mm_srli_epi64 (s1, 64 - bits));
  *r0 = _mm_or_si128 (t0, _mm_srli_epi64 (s0, 64 - bits));
}

static inline __m128i __srli_128 (__m128i a, uint8_t bits) {
  return _mm_or_si128 (
    _mm_srli_epi64 (a, bits),
    _mm_slli_epi64 (_mm_srli_si128 (a, 8), 64 - bits) );
}

static inline __m128i __reverse_si128 (__m128i x) {
  __m128i mask = _mm_set_epi64x (0x0001020304050607, 0x08090a0b0c0d0e0f);
  return _mm_shuffle_epi8 (x, mask);
}

static inline __m128i __reflect (__m128i x) {
  __m128i and_mask = _mm_set_epi32 (0x0f0f0f0f, 0x0f0f0f0f, 0x0f0f0f0f, 0x0f0f0f0f),
          lo_mask  = _mm_set_epi32 (0x0f070b03, 0x0d050901, 0x0e060a02, 0x0c040800),
          hi_mask  = _mm_set_epi32 (0xf070b030, 0xd0509010, 0xe060a020, 0xc0408000);

  return xor (
    _mm_shuffle_epi8 (hi_mask, _mm_and_si128 (x, and_mask)), 
    _mm_shuffle_epi8 (lo_mask, _mm_and_si128 (_mm_srli_epi16 (x, 4), and_mask)));
}

static inline __m128i __loadu_si128_with_padding (const uint8_t *src, size_t n) {
  uint64_t buf[2] = { 0 };
  memcpy (buf, src, n);
  return _mm_loadu_si128 ((__m128i *) buf);
}

#if !defined (__NC_GHASH_KARATSUBA)
static inline void __clmul_128 (__m128i *r1, __m128i *r0, __m128i a, __m128i b) {

  __m128i w0 = _mm_clmulepi64_si128 (a, b, 0x00),
          w1 = _mm_clmulepi64_si128 (a, b, 0x11),
          t  = xor (_mm_clmulepi64_si128 (a, b, 0x01),
                    _mm_clmulepi64_si128 (a, b, 0x10));

  *r0 = xor (w0, _mm_slli_si128 (t, 8));
  *r1 = xor (w1, _mm_srli_si128 (t, 8));
}
#else
static inline void __clmul_128 (__m128i *r1, __m128i *r0, __m128i a, __m128i b) {

  __m128i w0 = _mm_clmulepi64_si128 (a, b, 0x00),
          w1 = _mm_clmulepi64_si128 (a, b, 0x11),
          t  = _mm_clmulepi64_si128 (xor (a, _mm_slli_si128 (a, 8)),
                                     xor (b, _mm_slli_si128 (b, 8)), 0x11);

  t   = xor (t, xor (w0, w1));
  *r0 = xor (w0, _mm_slli_si128 (t, 8));
  *r1 = xor (w1, _mm_srli_si128 (t, 8));
}
#endif /* __NC_GHASH_KARATSUBA */

#if !defined (__NC_GHASH_REFLECTED_REDUCE)
static inline __m128i __reduce_g (__m128i w1, __m128i w0) {

  __m128i t = _mm_srli_si128 (w1, 8);

  t = xor4 (w1, _mm_srli_epi64 (t, 63), _mm_srli_epi64 (t, 62), _mm_srli_epi64 (t, 57));

  return xor (w0, xor4 (t, __slli_128 (t, 1), __slli_128 (t, 2), __slli_128 (t, 7)));
}
#define __repr_xform __reflect
#else
static inline __m128i __reduce_g (__m128i w1, __m128i w0) {

  __m128i t;
  __slli_256 (&w1, &w0, w1, w0, 1);

  t = _mm_slli_si128 (w0, 8);
  t = xor4 (w0, _mm_slli_epi64 (t, 63), _mm_slli_epi64 (t, 62), _mm_slli_epi64 (t, 57));

  return xor (w1, xor4 (__srli_128 (t, 1), __srli_128 (t, 2), __srli_128 (t, 7), t));
}
#define __repr_xform __reverse_si128
#endif

static inline __m128i __gfmul (__m128i a, __m128i b) {
  __m128i w1, w0;
  __clmul_128 (&w1, &w0, a, b);
  return __reduce_g (w1, w0);
}

static inline __m128i __gf_feed_block (__m128i key, __m128i acc, __m128i x) {
  return __gfmul (key, _mm_xor_si128 (acc, __repr_xform (x)));
}

static inline void __ghash (uint64_t key[2], uint64_t hash[2], const uint8_t *src, size_t n) {
  __m128i k   = __repr_xform (_mm_loadu_si128 ((__m128i *) key)),
          acc = __repr_xform (_mm_loadu_si128 ((__m128i *) hash));
  while (n >= 16) {
    acc = __gf_feed_block (k, acc, _mm_loadu_si128 ((__m128i *) src));
    src += 16;
    n   -= 16;
  }
  if (n > 0)
    acc = __gf_feed_block (k, acc, __loadu_si128_with_padding (src, n));
  _mm_storeu_si128 ((__m128i *) hash, __repr_xform (acc));
}

CAMLprim value caml_nc_ghash_key_size (__unit ()) { return Val_int (0); }

CAMLprim value caml_nc_ghash_init_key (__unit (), value __unused (__)) { return Val_unit; }

CAMLprim value
caml_nc_ghash (value k, value hash, value src, value off, value len) {
  __ghash ( (uint64_t *) Bp_val (k), (uint64_t *) Bp_val (hash),
            _ba_uint8_off (src, off), Int_val (len) );
  return Val_unit;
}

CAMLprim value caml_nc_ghash_mode (__unit ()) { return Val_int (1); }

#endif /* __nc_PCLMUL__ */
