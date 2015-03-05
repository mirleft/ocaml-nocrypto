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

void aes_derive_key (const unsigned char *key, unsigned char *rk0, int rounds) {

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

void aes_invert_key (const unsigned char *rk0, unsigned char *kr0, int rounds) {

  __m128i *rk = (__m128i*) rk0,
          *kr = (__m128i*) kr0;

  kr[0] = rk[rounds];

  for (int i = 1; i < rounds; i++)
    kr[i] = _mm_aesimc_si128 (rk[rounds - i]);

  kr[rounds] = rk[0];
}
