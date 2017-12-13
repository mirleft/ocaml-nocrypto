#if !defined (H__NOCRYPTO)
#define H__NOCRYPTO

#include <stdint.h>
#define __USE_MISC

#if defined(__FreeBSD__) || defined(__DragonFly__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <sys/endian.h>
#elif defined(__APPLE__)
#include <machine/endian.h>
#else
#include <endian.h>
#endif

#include <caml/mlvalues.h>
#include <caml/bigarray.h>

#if defined (__x86_64__) && defined (ACCELERATE)
#include <x86intrin.h>
#endif

#if defined (__x86_64__) && defined (ACCELERATE) && defined (__SSE2__)
#define __nc_SSE2__
#endif

#if defined (__x86_64__) && defined (ACCELERATE) && defined (__AES__)
#define __nc_AES_NI__
#else
#define __nc_AES_GENERIC__
#endif

#ifndef __unused
#define __unused(x) x __attribute__((unused))
#endif
#define __unit() value __unused(unit)

typedef unsigned long u_long;

#define _ba_uint8_off(ba, off) ((uint8_t*) Caml_ba_data_val (ba) + Long_val (off))
#define _ba_uint32_off(ba, off) ((uint32_t*) Caml_ba_data_val (ba) + Long_val (off))
#define _ba_ulong_off(ba, off) ((u_long*) Caml_ba_data_val (ba) + Long_val (off))

#define _ba_uint8(ba) _ba_uint8_off (ba, 0)
#define _ba_uint32(ba) _ba_uint32_off (ba, 0)
#define _ba_ulong(ba) _ba_ulong_off (ba, 0)

#define _ba_uint8_option_off(ba, off) (Is_block(ba) ? _ba_uint8_off(Field(ba, 0), off) : 0)
#define _ba_uint8_option(ba)          _ba_uint8_option_off (ba, 0)

#define __define_bc_6(f) \
  CAMLprim value f ## _bc (value *v, int __unused(c) ) { return f(v[0], v[1], v[2], v[3], v[4], v[5]); }

#define __define_bc_7(f) \
  CAMLprim value f ## _bc (value *v, int __unused(c) ) { return f(v[0], v[1], v[2], v[3], v[4], v[5], v[6]); }

#endif /* H__NOCRYPTO */
