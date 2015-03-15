//
// public domain
// Philip J. Erdelsky
// http://www.efgh.com/software/rijndael.htm
//

#ifndef H__RIJNDAEL
#define H__RIJNDAEL

int nc_rijndaelSetupEncrypt(unsigned long *rk, const unsigned char *key,
  int keybits);
int nc_rijndaelSetupDecrypt(unsigned long *rk, const unsigned char *key,
  int keybits);
void nc_rijndaelEncrypt(const unsigned long *rk, int nrounds,
  const unsigned char plaintext[16], unsigned char ciphertext[16]);
void nc_rijndaelDecrypt(const unsigned long *rk, int nrounds,
  const unsigned char ciphertext[16], unsigned char plaintext[16]);

#define KEYLENGTH(keybits) ((keybits)/8)
#define RKLENGTH(keybits)  ((keybits)/8+28)
#define NROUNDS(keybits)   ((keybits)/32+6)

#endif


