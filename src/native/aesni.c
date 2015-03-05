#include "aesni.h"
#include <wmmintrin.h>

/* xmm: [D, C, B, A] */
#define _S_3333 0xff
#define _S_2222 0xaa
#define _S_1111 0x55
#define _S_0000 0x00

static inline __m128i __mix (__m128i r1, __m128i r2) {
  __m128i r = r1;
  r = _mm_xor_si128 (r, _mm_slli_si128 (r1, 0x4));
  r = _mm_xor_si128 (r, _mm_slli_si128 (r1, 0x8));
  r = _mm_xor_si128 (r, _mm_slli_si128 (r1, 0xc));
  r = _mm_xor_si128 (r, r2);
  return r;
}

#define __assist(r1, r2, mode) (__mix (r1, _mm_shuffle_epi32 (r2, mode)))

static inline void __pack (__m128i *o1, __m128i *o2, __m128i r1, __m128i r2, __m128i r3) {
  *o1 = (__m128i) _mm_shuffle_pd ((__m128d) r1, (__m128d) r2, 0);
  *o2 = (__m128i) _mm_shuffle_pd ((__m128d) r2, (__m128d) r3, 1);
}

void _nc_aesni_derive_key (const u_char *key, u_char *rk0, u_int rounds) {

  __m128i *rk = (__m128i*) rk0;
  __m128i temp1, temp2;

  switch (rounds) {
    case 10:

      rk[0]  = _mm_loadu_si128 ((__m128i*) key);
      rk[1]  = __assist (rk[0], _mm_aeskeygenassist_si128 (rk[0], 0x01), _S_3333);
      rk[2]  = __assist (rk[1], _mm_aeskeygenassist_si128 (rk[1], 0x02), _S_3333);
      rk[3]  = __assist (rk[2], _mm_aeskeygenassist_si128 (rk[2], 0x04), _S_3333);
      rk[4]  = __assist (rk[3], _mm_aeskeygenassist_si128 (rk[3], 0x08), _S_3333);
      rk[5]  = __assist (rk[4], _mm_aeskeygenassist_si128 (rk[4], 0x10), _S_3333);
      rk[6]  = __assist (rk[5], _mm_aeskeygenassist_si128 (rk[5], 0x20), _S_3333);
      rk[7]  = __assist (rk[6], _mm_aeskeygenassist_si128 (rk[6], 0x40), _S_3333);
      rk[8]  = __assist (rk[7], _mm_aeskeygenassist_si128 (rk[7], 0x80), _S_3333);
      rk[9]  = __assist (rk[8], _mm_aeskeygenassist_si128 (rk[8], 0x1b), _S_3333);
      rk[10] = __assist (rk[9], _mm_aeskeygenassist_si128 (rk[9], 0x36), _S_3333);
      break;

    case 12:
      /* XXX
       * Simplify this horror. */

      rk[0] = _mm_loadu_si128 ((__m128i*) key);
      rk[1] = _mm_loadu_si128 ((__m128i*) (key+8));
      rk[1] = _mm_shuffle_epi32 (rk[1], 0xee); /* XXX shift */

      temp1 = __assist (rk[0], _mm_aeskeygenassist_si128 (rk[1], 0x01), _S_1111);
      temp2 = __assist (rk[1], temp1, _S_3333);

      __pack (&rk[1], &rk[2], rk[1], temp1, temp2);

      rk[3] = __assist (temp1, _mm_aeskeygenassist_si128 (temp2, 0x02), _S_1111);
      rk[4] = __assist (temp2, rk[3], _S_3333);

      temp1 = __assist (rk[3], _mm_aeskeygenassist_si128 (rk[4], 0x04), _S_1111);
      temp2 = __assist (rk[4], temp1, _S_3333);

      __pack (&rk[4], &rk[5], rk[4], temp1, temp2);

      rk[6] = __assist (temp1, _mm_aeskeygenassist_si128 (temp2, 0x08), _S_1111);
      rk[7] = __assist (temp2, rk[6], _S_3333);

      temp1 = __assist (rk[6], _mm_aeskeygenassist_si128 (rk[7], 0x10), _S_1111);
      temp2 = __assist (rk[7], temp1, _S_3333);

      __pack (&rk[7], &rk[8], rk[7], temp1, temp2);

      rk[9] = __assist (temp1, _mm_aeskeygenassist_si128 (temp2, 0x20), _S_1111);
      rk[10] = __assist (temp2, rk[9], _S_3333);

      temp1 = __assist (rk[9], _mm_aeskeygenassist_si128 (rk[10], 0x40), _S_1111);
      temp2 = __assist (rk[10], temp1, _S_3333);

      __pack (&rk[10], &rk[11], rk[10], temp1, temp2);

      rk[12] = __assist (temp1, _mm_aeskeygenassist_si128 (temp2, 0x80), _S_1111);
      break;

    case 14:

      rk[0]  = _mm_loadu_si128((__m128i*) key);
      rk[1]  = _mm_loadu_si128((__m128i*) (key+16));
      rk[2]  = __assist (rk[0],  _mm_aeskeygenassist_si128 (rk[1],  0x01), _S_3333);
      rk[3]  = __assist (rk[1],  _mm_aeskeygenassist_si128 (rk[2],  0x00), _S_2222);
      rk[4]  = __assist (rk[2],  _mm_aeskeygenassist_si128 (rk[3],  0x02), _S_3333);
      rk[5]  = __assist (rk[3],  _mm_aeskeygenassist_si128 (rk[4],  0x00), _S_2222);
      rk[6]  = __assist (rk[4],  _mm_aeskeygenassist_si128 (rk[5],  0x04), _S_3333);
      rk[7]  = __assist (rk[5],  _mm_aeskeygenassist_si128 (rk[6],  0x00), _S_2222);
      rk[8]  = __assist (rk[6],  _mm_aeskeygenassist_si128 (rk[7],  0x08), _S_3333);
      rk[9]  = __assist (rk[7],  _mm_aeskeygenassist_si128 (rk[8],  0x00), _S_2222);
      rk[10] = __assist (rk[8],  _mm_aeskeygenassist_si128 (rk[9],  0x10), _S_3333);
      rk[11] = __assist (rk[9],  _mm_aeskeygenassist_si128 (rk[10], 0x00), _S_2222);
      rk[12] = __assist (rk[10], _mm_aeskeygenassist_si128 (rk[11], 0x20), _S_3333);
      rk[13] = __assist (rk[11], _mm_aeskeygenassist_si128 (rk[12], 0x00), _S_2222);
      rk[14] = __assist (rk[12], _mm_aeskeygenassist_si128 (rk[13], 0x40), _S_3333);
      break;

    default:
      ;
  }
}

void _nc_aesni_invert_key (const u_char *rk0, u_char *kr0, u_int rounds) {

  __m128i *rk = (__m128i*) rk0,
          *kr = (__m128i*) kr0;

  kr[0] = rk[rounds];

  for (int i = 1; i < rounds; i++)
    kr[i] = _mm_aesimc_si128 (rk[rounds - i]);

  kr[rounds] = rk[0];
}

void _nc_aesni_enc (const u_char src[16], u_char dst[16], const u_char *rk0, u_int rounds) {

  __m128i r   = _mm_loadu_si128 ((__m128i*) src),
          *rk = (__m128i*) rk0;

  r = _mm_xor_si128 (r, rk[0]);

  for (int i = 1; i < rounds; i++)
    r = _mm_aesenc_si128 (r, rk[i]);

  r = _mm_aesenclast_si128 (r, rk[rounds]);
  _mm_storeu_si128 ((__m128i*) dst, r);
}

void _nc_aesni_dec (const u_char src[16], u_char dst[16], const u_char *rk0, u_int rounds) {

  __m128i r   = _mm_loadu_si128 ((__m128i*) src),
          *rk = (__m128i*) rk0;

  r = _mm_xor_si128 (r, rk[0]);

  for (int i = 1; i < rounds; i++)
    r = _mm_aesdec_si128 (r, rk[i]);

  r = _mm_aesdeclast_si128 (r, rk[rounds]);
  _mm_storeu_si128 ((__m128i*) dst, r);
}

void _nc_aesni_enc8 (const u_char src[128], u_char dst[128], const u_char *rk0, u_int rounds) {

  __m128i *in  = (__m128i*) src,
          *out = (__m128i*) dst,
          *rk  = (__m128i*) rk0;

  __m128i r0 = _mm_loadu_si128 (in    ),
          r1 = _mm_loadu_si128 (in + 1),
          r2 = _mm_loadu_si128 (in + 2),
          r3 = _mm_loadu_si128 (in + 3),
          r4 = _mm_loadu_si128 (in + 4),
          r5 = _mm_loadu_si128 (in + 5),
          r6 = _mm_loadu_si128 (in + 6),
          r7 = _mm_loadu_si128 (in + 7);

  r0 = _mm_xor_si128 (r0, rk[0]);
  r1 = _mm_xor_si128 (r1, rk[0]);
  r2 = _mm_xor_si128 (r2, rk[0]);
  r3 = _mm_xor_si128 (r3, rk[0]);
  r4 = _mm_xor_si128 (r4, rk[0]);
  r5 = _mm_xor_si128 (r5, rk[0]);
  r6 = _mm_xor_si128 (r6, rk[0]);
  r7 = _mm_xor_si128 (r7, rk[0]);

  for (int i = 1; i < rounds; i++) {
    r0 = _mm_aesenc_si128 (r0, rk[i]);
    r1 = _mm_aesenc_si128 (r1, rk[i]);
    r2 = _mm_aesenc_si128 (r2, rk[i]);
    r3 = _mm_aesenc_si128 (r3, rk[i]);
    r4 = _mm_aesenc_si128 (r4, rk[i]);
    r5 = _mm_aesenc_si128 (r5, rk[i]);
    r6 = _mm_aesenc_si128 (r6, rk[i]);
    r7 = _mm_aesenc_si128 (r7, rk[i]);
  }

  r0 = _mm_aesenclast_si128 (r0, rk[rounds]);
  r1 = _mm_aesenclast_si128 (r1, rk[rounds]);
  r2 = _mm_aesenclast_si128 (r2, rk[rounds]);
  r3 = _mm_aesenclast_si128 (r3, rk[rounds]);
  r4 = _mm_aesenclast_si128 (r4, rk[rounds]);
  r5 = _mm_aesenclast_si128 (r5, rk[rounds]);
  r6 = _mm_aesenclast_si128 (r6, rk[rounds]);
  r7 = _mm_aesenclast_si128 (r7, rk[rounds]);

  _mm_storeu_si128 (out    , r0);
  _mm_storeu_si128 (out + 1, r1);
  _mm_storeu_si128 (out + 2, r2);
  _mm_storeu_si128 (out + 3, r3);
  _mm_storeu_si128 (out + 4, r4);
  _mm_storeu_si128 (out + 5, r5);
  _mm_storeu_si128 (out + 6, r6);
  _mm_storeu_si128 (out + 7, r7);
}

void _nc_aesni_dec8 (const u_char src[128], u_char dst[128], const u_char *rk0, u_int rounds) {

  __m128i *in  = (__m128i*) src,
          *out = (__m128i*) dst,
          *rk  = (__m128i*) rk0;

  __m128i r0 = _mm_loadu_si128 (in    ),
          r1 = _mm_loadu_si128 (in + 1),
          r2 = _mm_loadu_si128 (in + 2),
          r3 = _mm_loadu_si128 (in + 3),
          r4 = _mm_loadu_si128 (in + 4),
          r5 = _mm_loadu_si128 (in + 5),
          r6 = _mm_loadu_si128 (in + 6),
          r7 = _mm_loadu_si128 (in + 7);

  r0 = _mm_xor_si128 (r0, rk[0]);
  r1 = _mm_xor_si128 (r1, rk[0]);
  r2 = _mm_xor_si128 (r2, rk[0]);
  r3 = _mm_xor_si128 (r3, rk[0]);
  r4 = _mm_xor_si128 (r4, rk[0]);
  r5 = _mm_xor_si128 (r5, rk[0]);
  r6 = _mm_xor_si128 (r6, rk[0]);
  r7 = _mm_xor_si128 (r7, rk[0]);

  for (int i = 1; i < rounds; i++) {
    r0 = _mm_aesdec_si128 (r0, rk[i]);
    r1 = _mm_aesdec_si128 (r1, rk[i]);
    r2 = _mm_aesdec_si128 (r2, rk[i]);
    r3 = _mm_aesdec_si128 (r3, rk[i]);
    r4 = _mm_aesdec_si128 (r4, rk[i]);
    r5 = _mm_aesdec_si128 (r5, rk[i]);
    r6 = _mm_aesdec_si128 (r6, rk[i]);
    r7 = _mm_aesdec_si128 (r7, rk[i]);
  }

  r0 = _mm_aesdeclast_si128 (r0, rk[rounds]);
  r1 = _mm_aesdeclast_si128 (r1, rk[rounds]);
  r2 = _mm_aesdeclast_si128 (r2, rk[rounds]);
  r3 = _mm_aesdeclast_si128 (r3, rk[rounds]);
  r4 = _mm_aesdeclast_si128 (r4, rk[rounds]);
  r5 = _mm_aesdeclast_si128 (r5, rk[rounds]);
  r6 = _mm_aesdeclast_si128 (r6, rk[rounds]);
  r7 = _mm_aesdeclast_si128 (r7, rk[rounds]);

  _mm_storeu_si128 (out    , r0);
  _mm_storeu_si128 (out + 1, r1);
  _mm_storeu_si128 (out + 2, r2);
  _mm_storeu_si128 (out + 3, r3);
  _mm_storeu_si128 (out + 4, r4);
  _mm_storeu_si128 (out + 5, r5);
  _mm_storeu_si128 (out + 6, r6);
  _mm_storeu_si128 (out + 7, r7);
}

int _nc_aesni_rk_size (u_int rounds) {
  return (rounds + 1) * 16;
}
