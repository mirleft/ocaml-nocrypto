
#include <sys/types.h>
#include <stdint.h>

#include "sha1.h"
#include "md5.h"
#include "rijndael.h"

#define CAML_NAME_SPACE
#include <caml/mlvalues.h>
#include <caml/alloc.h>
#include <caml/memory.h>
#include <caml/fail.h>
#include <caml/bigarray.h>

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

intnat sha1_size = 20;

CAMLprim value caml_DESU_sha1 (value buffer) {
  CAMLparam1 (buffer);
  CAMLlocal1 (res);
  res = caml_ba_alloc (CAML_BA_UINT8 | CAML_BA_C_LAYOUT, 1, NULL, &sha1_size);
  SHA1_CTX *ctx = malloc (sizeof(SHA1_CTX));

  SHA1_Init (ctx);
  SHA1_Update (ctx, Caml_ba_data_val(buffer), Caml_ba_array_val(buffer)->dim[0]);
  SHA1_Final (ctx, (unsigned char *) Caml_ba_data_val(res));

  free (ctx);
  CAMLreturn (res);
}

intnat md5_size = 16;

CAMLprim value caml_DESU_md5 (value buffer) {
  CAMLparam1 (buffer);
  CAMLlocal1 (res);
  res = caml_ba_alloc (CAML_BA_UINT8 | CAML_BA_C_LAYOUT, 1, NULL, &md5_size);
  MD5_CTX *ctx = malloc (sizeof(MD5_CTX));

  MD5_Init (ctx);
  MD5_Update (ctx, Caml_ba_data_val(buffer), Caml_ba_array_val(buffer)->dim[0]);
  MD5_Final ((unsigned char *) Caml_ba_data_val(res), ctx);

  free (ctx);
  CAMLreturn (res);
}

intnat aes_blocksize = 16;

CAMLprim value caml_DESU_aes_create_enc_key (value key) {
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

CAMLprim value caml_DESU_aes_create_dec_key (value key) {
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

CAMLprim value caml_DESU_aes_encrypt (value keysize, value rk, value plain) {
  CAMLparam3 (keysize, rk, plain);
  CAMLlocal1 (cipher);

  int keybits = Int_val (keysize) * 8;

  if (Caml_ba_array_val (plain) -> dim[0] != 16) {
    caml_invalid_argument ("AES: invalid data length");
  }

  cipher = caml_ba_alloc (CAML_BA_UINT8 | CAML_BA_C_LAYOUT, 1, NULL, &aes_blocksize);

  rijndaelEncrypt ( Caml_ba_data_val (rk), NROUNDS (keybits),
                    Caml_ba_data_val (plain), Caml_ba_data_val (cipher) );

  CAMLreturn (cipher);
}

CAMLprim value caml_DESU_aes_decrypt (value keysize, value rk, value cipher) {
  CAMLparam3 (keysize, rk, cipher);
  CAMLlocal1 (plain);

  int keybits = Int_val (keysize) * 8;

  if (Caml_ba_array_val (cipher) -> dim[0] != 16) {
    caml_invalid_argument ("AES: invalid data length");
  }

  plain = caml_ba_alloc (CAML_BA_UINT8 | CAML_BA_C_LAYOUT, 1, NULL, &aes_blocksize);

  rijndaelDecrypt ( Caml_ba_data_val (rk), NROUNDS (keybits),
                    Caml_ba_data_val (cipher), Caml_ba_data_val (plain) );

  CAMLreturn (plain);
}
