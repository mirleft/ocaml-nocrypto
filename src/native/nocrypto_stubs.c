#include "nocrypto_stubs.h"

#define CTX_SIZE_GETTER(HASH, CNAME)            \
  size_t nocrypto_sizeof_ ## HASH ## _ctx () {  \
    return CNAME ## _CTX_SIZE;                  \
  }

CTX_SIZE_GETTER(md5, MD5);
CTX_SIZE_GETTER(sha1, SHA1);
CTX_SIZE_GETTER(sha224, SHA224);
CTX_SIZE_GETTER(sha256, SHA256);
CTX_SIZE_GETTER(sha384, SHA384);
CTX_SIZE_GETTER(sha512, SHA512);
