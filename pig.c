#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#include "pig.h"

#define FNV_PRIME_32 16777619
#define FNV_BASIS_32 2166136261
#define MASK_24 (((uint32_t)1<<24)-1)  /* i.e., (u_int32_t)0xffffff */

#define DOMAIN_LENGTH 255

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


int please_verify_key(uint32_t epoch, unsigned char *secret, const char *hash)
{
        char final_fnv[7];
        uint8_t digest[SHA256_DIGEST_SIZE];
        uint8_t time_in_4_bytes[4] = {0};
        uint32_t fnv_hash,fnv_hash2;
        memset(digest, 0, sizeof(digest));
        time_in_4_bytes[3] = (uint8_t)epoch;
        time_in_4_bytes[2] = (uint8_t)(epoch >> 8);
        time_in_4_bytes[1] = (uint8_t)(epoch >> 16);
        time_in_4_bytes[0] = (uint8_t)(epoch >> 24);
        hmac_sha256(secret, 256, time_in_4_bytes, 4, digest, SHA256_DIGEST_SIZE);
        fnv_hash = fnv_hasher(digest);
        fnv_hash2 = (fnv_hash>>24) ^ (fnv_hash & MASK_24);
        snprintf(final_fnv, 7, "%06x", fnv_hash2);
        printf("hrrm %s, %s \n", final_fnv, hash);
        if(strncmp(final_fnv,hash,6))
                return 1;
        return 0;
}

int verify_key(const char *key, const char *hash, const char *secret_folder, int skew)
{
        uint8_t digest[SHA256_DIGEST_SIZE];
        uint32_t epoch = (uint32_t) time(0);
        char secret_path[DOMAIN_LENGTH] = {0};
        unsigned char secret [256] = {0};
        int i, tmp;
        FILE *file_secret;
        memset(digest, 0, sizeof(digest));
        strncat(secret_path, secret_folder, DOMAIN_LENGTH);
        strncat(secret_path, "/secrets/", DOMAIN_LENGTH);
        strncat(secret_path, key, DOMAIN_LENGTH);
        if(!(file_secret = fopen(secret_path, "r"))) {
                return -1;
        }
        if(fread(secret, 256,1, file_secret) != 1) {
                fclose(file_secret);
                return -2;
        }
        fclose(file_secret);
        epoch = epoch - (epoch %60);
        for(i = 0; i < skew; i++) {
                tmp = epoch - (60*i);
                if(!please_verify_key(tmp, secret, hash))
                        return 0;
                tmp = epoch + (60*i);
                if(!please_verify_key(tmp, secret, hash))
                        return 0;
        }
        return 1;
}
