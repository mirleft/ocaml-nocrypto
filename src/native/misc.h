#if !defined (H__MISC__)
#define H__MISC__

#include <caml/mlvalues.h>
#include <caml/bigarray.h>

#define _ba_uchar(ba) ((u_char*) Caml_ba_data_val (ba))
#define _ba_uchar_off(ba, off) ((u_char*) Caml_ba_data_val (ba) + Long_val (off))

#define _ba_ulong(ba) ((u_long *) Caml_ba_data_val (ba))

#endif
