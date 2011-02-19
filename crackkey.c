/* this is a block of example code I used to test the system early on no longer in use */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <nettle/sha.h>
#include <nettle/hmac.h>

#include <ctype.h>

#define FNV_PRIME_32 16777619
#define MASK_24 (((uint32_t)1<<24)-1)  /* i.e., (u_int32_t)0xffffff */

uint32_t fnv_hasher(uint8_t *str)
{
    uint32_t hval = 0;
    /*
     * FNV-1 hash each octet in the buffer
     */
    int i = 0;
    for (i = 0; i < 32; i++) {

	/* multiply by the 32 bit FNV magic prime mod 2^32 */
	hval *= FNV_PRIME_32;
	/* xor the bottom with the current octet */
	hval ^= (uint32_t)str[i];
    }

    /* return our new hash value */
    return hval;
}

int main(int argc, char **argv)
{
  struct hmac_sha256_ctx sha256;
  uint8_t digest[SHA256_DIGEST_SIZE];
  uint8_t ihatebuffers[4] = {0};
  uint32_t fnv_hash,fnv_hash2;
  uint32_t crack = 0xdd955f;
  uint32_t time = 1296579900;
  memset(digest, 0, sizeof(digest));
  int i,j,k,l;
uint8_t hmacKey[]={
  0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,
  0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,
  0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,
  0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,
  0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,
  0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,
  0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,
  0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,
  0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,
  0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,
  0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,
  0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,
  0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,0x2a,
  0x2a,0x2a,0x2a,0x2a,0x2a
};
  ihatebuffers[3] = (uint8_t)time;
  ihatebuffers[2] = (uint8_t)(time >> 8);
  ihatebuffers[1] = (uint8_t)(time >> 16);
  ihatebuffers[0] = (uint8_t)(time >> 24);
  for(l = 0; l <256; l++) {
  for(k = 0; k < 256; k++) {
  for(j = 0; j < 256; j++) {
      for(i = 0; i < 256; i++) {
	  hmacKey[252] = l;
          hmacKey[253] = k;
          hmacKey[254] = j;
          hmacKey[255] = i;
          hmac_sha256_set_key(&sha256, 256,hmacKey);
          hmac_sha256_update(&sha256, 4, ihatebuffers);
          hmac_sha256_digest(&sha256, SHA256_DIGEST_SIZE, digest);
          fnv_hash = fnv_hasher(digest);
          fnv_hash2 = (fnv_hash>>24) ^ (fnv_hash & MASK_24);
          if(fnv_hash2 == crack)
             printf("24 byte hash:%02X\n", fnv_hash2);
    }
  }
  }
  }
  return EXIT_SUCCESS;


}
