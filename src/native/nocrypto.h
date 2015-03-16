#if !defined (H__NOCRYPTO)
#define H__NOCRYPTO

#if ( defined (__i386__) || defined (__x86_64__) )
#include <x86intrin.h>
#endif

#if ( defined (__i386__) || defined (__x86_64__) ) && defined (__AES__)
#define NC_AES_NI
#else
#define NC_AES_GENERIC
#endif

typedef unsigned char u_char;
typedef unsigned long u_long;
typedef unsigned int u_int;

#include <caml/mlvalues.h>
#include <caml/bigarray.h>

#define _ba_uchar(ba)          ((u_char*) Caml_ba_data_val (ba))
#define _ba_uchar_off(ba, off) ((u_char*) Caml_ba_data_val (ba) + Long_val (off))
#define _ba_ulong(ba)          ((u_long*) Caml_ba_data_val (ba))
#define _ba_ulong_off(ba, off) ((u_long*) Caml_ba_data_val (ba) + Long_val (off))
#define _ba_uint8(ba)          ((uint8_t*) Caml_ba_data_val (ba))
#define _ba_uint8_off(ba, off) ((uint8_t*) Caml_ba_data_val (ba) + Long_val (off))

#endif /* H__NOCRYPTO */
