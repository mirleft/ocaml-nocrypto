
#include <sys/types.h>
#include <stdint.h>

#include "sha2.h"
#include "md5.h"
#include "rijndael.h"

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

intnat md5_size = 16;

CAMLprim value caml_nc_MD5 (value buffer) {
  CAMLparam1 (buffer);
  CAMLlocal1 (res);
  res = nc_ba_alloc (&md5_size);
  MD5_CTX *ctx = malloc (sizeof(MD5_CTX));

  MD5_Init (ctx);
  MD5_Update (ctx, Caml_ba_data_val (buffer), nc_ba_dim (buffer));
  MD5_Final ((unsigned char *) Caml_ba_data_val(res), ctx);

  free (ctx);
  CAMLreturn (res);
}

#define SHA_STUFF(FUNCTION)                                                    \
                                                                               \
  intnat FUNCTION ## _size = FUNCTION ## _DIGEST_LENGTH;                       \
                                                                               \
  CAMLprim value caml_nc_ ## FUNCTION (value buffer) {                         \
    CAMLparam1 (buffer);                                                       \
    CAMLlocal1 (res);                                                          \
    res = nc_ba_alloc (& FUNCTION ## _size);                                   \
    SHA_CTX *ctx = malloc (sizeof (SHA_CTX));                                  \
                                                                               \
    FUNCTION ## _Init (ctx) ;                                                  \
    FUNCTION ## _Update (ctx, Caml_ba_data_val (buffer), nc_ba_dim (buffer));  \
    FUNCTION ## _Final ((unsigned char *) Caml_ba_data_val (res), ctx);        \
                                                                               \
    free (ctx);                                                                \
    CAMLreturn (res);                                                          \
  }

SHA_STUFF(SHA1  );
SHA_STUFF(SHA224);
SHA_STUFF(SHA256);
SHA_STUFF(SHA384);
SHA_STUFF(SHA512);


intnat aes_blocksize = 16;

CAMLprim value caml_nc_aes_create_enc_key (value key) {
  CAMLparam1 (key);
  CAMLlocal1 (rk);

  int    keysize = Caml_ba_array_val (key) -> dim[0];
  int    keybits = keysize * 8;
  intnat rkbytes = RKLENGTH (keybits) * sizeof (unsigned long);

  if (keysize != 16 && keysize != 24 && keysize != 32) {
    caml_invalid_argument ("AES: invalid key length");
  }

  rk = caml_ba_alloc (CAML_BA_UINT8 | CAML_BA_C_LAYOUT, 1, NULL, &rkbytes);
  rijndaelSetupEncrypt (Caml_ba_data_val (rk), Caml_ba_data_val (key), keybits);

  CAMLreturn (rk);
}

CAMLprim value caml_nc_aes_create_dec_key (value key) {
  CAMLparam1 (key);
  CAMLlocal1 (rk);

  int    keysize = Caml_ba_array_val (key) -> dim[0];
  int    keybits = keysize * 8;
  intnat rkbytes = RKLENGTH (keybits) * sizeof (unsigned long);

  if (keysize != 16 && keysize != 24 && keysize != 32) {
    caml_invalid_argument ("AES: invalid key length");
  }

  rk = caml_ba_alloc (CAML_BA_UINT8 | CAML_BA_C_LAYOUT, 1, NULL, &rkbytes);
  rijndaelSetupDecrypt (Caml_ba_data_val (rk), Caml_ba_data_val (key), keybits);

  CAMLreturn (rk);
}

void caml_nc_aes_encrypt (
    value keysize, value rk, value plain, value cipher) {

  CAMLparam4 (keysize, rk, plain, cipher);

  int keybits = Int_val (keysize) * 8;

  if ( Caml_ba_array_val (plain)  -> dim[0] < 16 ||
       Caml_ba_array_val (cipher) -> dim[0] < 16 ) {
    caml_invalid_argument ("AES: invalid data length");
  }

  rijndaelEncrypt ( Caml_ba_data_val (rk), NROUNDS (keybits),
                    Caml_ba_data_val (plain), Caml_ba_data_val (cipher) );

  CAMLreturn0;
}

void caml_nc_aes_decrypt (
    value keysize, value rk, value cipher, value plain) {

  CAMLparam4 (keysize, rk, cipher, plain);

  int keybits = Int_val (keysize) * 8;

  if ( Caml_ba_array_val (cipher) -> dim[0] < 16 ||
       Caml_ba_array_val (plain)  -> dim[0] < 16 ) {
    caml_invalid_argument ("AES: invalid data length");
  }

  rijndaelDecrypt ( Caml_ba_data_val (rk), NROUNDS (keybits),
                    Caml_ba_data_val (cipher), Caml_ba_data_val (plain) );

  CAMLreturn0;
}
