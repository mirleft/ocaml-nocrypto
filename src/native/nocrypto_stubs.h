#include "stddef.h" // size_t
#include "string.h" // memset

#include "hash/md5.h"
#include "hash/sha1.h"
#include "hash/sha256.h"
#include "hash/sha512.h"

#define CTX_SIZE_GETTER_DECL(HASH) \
  size_t nocrypto_sizeof_ ## HASH ## _ctx ();

CTX_SIZE_GETTER_DECL(md5);
CTX_SIZE_GETTER_DECL(sha1);
CTX_SIZE_GETTER_DECL(sha224);
CTX_SIZE_GETTER_DECL(sha256);
CTX_SIZE_GETTER_DECL(sha384);
CTX_SIZE_GETTER_DECL(sha512);
