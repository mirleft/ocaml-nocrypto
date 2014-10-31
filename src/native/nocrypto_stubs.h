#include "stddef.h" // size_t
#include "string.h" // memset

#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "sha512.h"
#include "rijndael.h"
#include "d3des.h"

#define CTX_SIZE_GETTER_DECL(HASH) \
  size_t nocrypto_sizeof_ ## HASH ## _ctx ();

CTX_SIZE_GETTER_DECL(md5);
CTX_SIZE_GETTER_DECL(sha1);
CTX_SIZE_GETTER_DECL(sha224);
CTX_SIZE_GETTER_DECL(sha256);
CTX_SIZE_GETTER_DECL(sha384);
CTX_SIZE_GETTER_DECL(sha512);
