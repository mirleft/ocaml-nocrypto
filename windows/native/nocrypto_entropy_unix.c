#include <WinDef.h>
#include <bcrypt.h>
#include <caml/mlvalues.h>

CAMLprim value
get_random_bytes(value unit)
{
    PUCHAR *pbBuffer;
    BCRYPT_ALG_HANDLE *phAlgorithm;
    BCryptOpenAlgorithmProvider(*phAlgorithm, BCRYPT_RSA_ALGORITHM, NULL, 0);
    BCryptGenRandom(*phAlgorithm, *pbBuffer, 1024, 0);
    BCryptCloseAlgorithmProvider(*phAlgorithm, 0);

    UCHAR buffer = (UCHAR)*pbBuffer;

    return Val_int(buffer);
}