#include <caml/mlvalues.h>
#include <windows.h>
#include <bcrypt.h>

CAMLprim value
get_random_bytes(PUCHAR *pbBuffer)
{
    BCRYPT_ALG_HANDLE phAlgorithm;
    BCryptOpenAlgorithmProvider(&phAlgorithm, BCRYPT_RSA_ALGORITHM, NULL, 0);
    BCryptGenRandom(phAlgorithm, &pbBuffer, 32, 0);
    BCryptCloseAlgorithmProvider(phAlgorithm, 0);

    return Val_int(32);
}