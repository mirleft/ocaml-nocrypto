#include "md5.h"
#include "sha2.h"

size_t nocrypto_stub_sizeof_md5_ctx () {
  return sizeof (MD5_CTX);
}

size_t nocrypto_stub_sizeof_sha_ctx () {
  return sizeof (SHA_CTX);
}
