
#include <sys/types.h>
#include <stdint.h>

#include "sha2.h"
#include "md5.h"
#include "rijndael.h"
#include "d3des.h"

#define CAML_NAME_SPACE
#include <caml/mlvalues.h>
#include <caml/alloc.h>
#include <caml/memory.h>
#include <caml/fail.h>
#include <caml/bigarray.h>


#define nc_ba_alloc(dim) \
  caml_ba_alloc ( CAML_BA_UINT8 | CAML_BA_C_LAYOUT, 1, NULL, (dim) )

#define nc_ba_dim(var) ( Caml_ba_array_val(var) -> dim[0] )


// // ..
// #include <stdio.h>
// 
// void hex (const char *tag, const unsigned char *buf, int size) {
//   int x;
//   printf ("[ %s ]", tag);
//   for (x = 0; x < size; x++) {
//     if (x % 16 == 0) { printf ("\n"); }
//     printf ("%02x ", (unsigned char) buf[x]);
//   }
//   printf("\n\n");
// }
// //


#define HASH_FUNCTION(CTX, FUNCTION)                                      \
                                                                          \
  intnat FUNCTION ## _size_ = FUNCTION ## _DIGEST_LENGTH;                 \
                                                                          \
  CAMLprim value caml_nc_init_ ## FUNCTION () {                           \
    CAMLparam0 ();                                                        \
    CAMLlocal1 (ctx);                                                     \
    intnat size = sizeof (CTX);                                           \
    ctx = nc_ba_alloc (& size);                                           \
    FUNCTION ## _Init ((CTX *) Caml_ba_data_val (ctx));                   \
    CAMLreturn (ctx);                                                     \
  }                                                                       \
                                                                          \
  CAMLprim void caml_nc_feed_ ## FUNCTION (value ctx, value buff) {       \
    CAMLparam2 (ctx, buff) ;                                              \
    FUNCTION ## _Update ( (CTX *) Caml_ba_data_val (ctx),                 \
                           Caml_ba_data_val (buff), nc_ba_dim (buff) );   \
    CAMLreturn0;                                                          \
  }                                                                       \
                                                                          \
  CAMLprim value caml_nc_get_ ## FUNCTION (value ctx) {                   \
    CAMLparam1 (ctx);                                                     \
    CAMLlocal1 (res);                                                     \
    res = nc_ba_alloc (& FUNCTION ## _size_);                             \
    FUNCTION ## _Final ( (unsigned char *) Caml_ba_data_val (res),        \
                         (CTX *) Caml_ba_data_val (ctx) );                \
    CAMLreturn (res);                                                     \
  }

#define MD5_DIGEST_LENGTH 16

HASH_FUNCTION (MD5_CTX, MD5   );
HASH_FUNCTION (SHA_CTX, SHA1  );
HASH_FUNCTION (SHA_CTX, SHA224);
HASH_FUNCTION (SHA_CTX, SHA256);
HASH_FUNCTION (SHA_CTX, SHA384);
HASH_FUNCTION (SHA_CTX, SHA512);


// We stuff the key bits parameter into the rk[0] as a long.
#define AES_KEY_CREATOR(DIR)                                             \
                                                                         \
  CAMLprim value caml_nc_aes_create_ ## DIR ## _key (value key) {        \
    CAMLparam1 (key);                                                    \
    CAMLlocal1 (rk);                                                     \
                                                                         \
    int    keysize = nc_ba_dim (key);                                    \
    int    keybits = keysize * 8;                                        \
    intnat rkbytes = (1 + RKLENGTH (keybits)) * sizeof (unsigned long);  \
                                                                         \
    if (keysize != 16 && keysize != 24 && keysize != 32) {               \
      caml_invalid_argument ("AES: invalid key length");                 \
    }                                                                    \
                                                                         \
    rk                     = nc_ba_alloc (&rkbytes);                     \
    unsigned long *rk_data = Caml_ba_data_val (rk) ;                     \
    rk_data [0]            = keybits;                                    \
    rijndaelSetup ## DIR ## rypt                                         \
        ( rk_data + 1, Caml_ba_data_val (key), keybits );                \
                                                                         \
    CAMLreturn (rk);                                                     \
  }

AES_KEY_CREATOR(Enc);
AES_KEY_CREATOR(Dec);

#define AES_TRANSFORM(DIR)                                       \
                                                                 \
  CAMLprim void caml_nc_aes_ ## DIR (                            \
    value rk, value source, value target) {                      \
    CAMLparam3 (rk, source, target);                             \
                                                                 \
    unsigned long *rk_data = Caml_ba_data_val (rk);              \
    int keybits            = rk_data[0];                         \
                                                                 \
    if ( Caml_ba_array_val (source) -> dim[0] < 16 ||            \
         Caml_ba_array_val (target) -> dim[0] < 16 ) {           \
      caml_invalid_argument ("AES: invalid data length");        \
    }                                                            \
                                                                 \
    rijndael ## DIR ## rypt (                                    \
        rk_data + 1, NROUNDS (keybits),                          \
        Caml_ba_data_val (source), Caml_ba_data_val (target) );  \
                                                                 \
    CAMLreturn0;                                                 \
  }

AES_TRANSFORM(Enc);
AES_TRANSFORM(Dec);


CAMLprim value caml_nc_des_create_key (value key, value dir) {
  CAMLparam2 (key, dir);
  CAMLlocal1 (res);

  if (nc_ba_dim (key) != 24) {
    caml_invalid_argument ("DES3: invalid key length");
  }

  intnat size = 96 * sizeof (unsigned long);

  des3key ( Caml_ba_data_val (key), (Long_val (dir) == 0 ? EN0 : DE1) );
  res = nc_ba_alloc (& size);
  cp3key ( Caml_ba_data_val (res) );

  CAMLreturn (res);
}

CAMLprim void caml_nc_des_transform (value ckey, value source, value target) {
  CAMLparam3 (ckey, source, target);

  if ( nc_ba_dim (source) < 8 || nc_ba_dim (target) < 8 ) {
    caml_invalid_argument ("3DES: invalid data length");
  }

  use3key (Caml_ba_data_val (ckey));
  Ddes (Caml_ba_data_val (source), Caml_ba_data_val (target));

  CAMLreturn0;
}

CAMLprim void caml_nc_des_transform2 (value ckey, value source, value target) {
  CAMLparam3 (ckey, source, target);

  if ( nc_ba_dim (source) < 16 || nc_ba_dim (target) < 16 ) {
    caml_invalid_argument ("3DES double: invalid data length");
  }

  use3key (Caml_ba_data_val (ckey));
  D2des (Caml_ba_data_val (source), Caml_ba_data_val (target));

  CAMLreturn0;
}
