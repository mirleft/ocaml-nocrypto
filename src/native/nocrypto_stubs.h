#include "stddef.h" // size_t
#include "string.h" // memset

#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "sha512.h"
#include "rijndael.h"
#include "d3des.h"

size_t nocrypto_stub_sizeof_md5_ctx ();
size_t nocrypto_stub_sizeof_sha1_ctx ();
size_t nocrypto_stub_sizeof_sha256_ctx ();
size_t nocrypto_stub_sizeof_sha512_ctx ();
