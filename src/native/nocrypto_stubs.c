#include "nocrypto_stubs.h"

size_t nocrypto_stub_sizeof_md5_ctx () {
  return MD5_CTX_SIZE;
}
size_t nocrypto_stub_sizeof_sha1_ctx () {
  return SHA1_CTX_SIZE;
}
size_t nocrypto_stub_sizeof_sha256_ctx () {
  return SHA256_CTX_SIZE;
}
size_t nocrypto_stub_sizeof_sha512_ctx () {
  return SHA512_CTX_SIZE;
}
