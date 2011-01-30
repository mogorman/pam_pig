/*
 * This is a simple pig (personal identification guarantee)
 * it allows for local two factor authenication.
 */

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

#include "mongoose.h"

//#include <nettle/sha.h>
//#include <nettle/hmac.h>
#include "hmac_sha2.h"

#include <ctype.h>

#define FNV_PRIME_32 16777619
#define FNV_BASIS_32 2166136261
#define MASK_24 (((uint32_t)1<<24)-1)  /* i.e., (u_int32_t)0xffffff */

#define DOMAIN_LENGTH 255
const char *secret_folder = "/etc/pig/secrets/";

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

int verify_key(uint32_t epoch, unsigned char *secret, const char *hash) {
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
        if(strncmp(final_fnv,hash,6))
                return 1;
        return 0;
}

int please_verify_key(const char *key, const char *hash) {
        uint8_t digest[SHA256_DIGEST_SIZE];
        uint32_t epoch = (uint32_t) time(0);
        char secret_path[DOMAIN_LENGTH] = {0};
        unsigned char secret [256] = {0};
        FILE *file_secret;
        memset(digest, 0, sizeof(digest));
        strncat(secret_path, secret_folder, DOMAIN_LENGTH);
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
        if(verify_key(epoch, secret, hash)) {
                epoch = epoch - 60;
                if(verify_key(epoch, secret, hash)) {
                        epoch = epoch + 120;
                        if(verify_key(epoch, secret, hash)) {
                                return 1;
                        }
                }
        }
        return 0;
}

static void *event_handler(enum mg_event event,
                           struct mg_connection *conn,
                           const struct mg_request_info *request_info) {
        void *processed = "yes";
        char * res = "HTTP/1.1 401 NOT AUTHORIZED\r\n";
        char *key, *hash, *tmp;
        if (event == MG_NEW_REQUEST) {
                tmp = strdup(request_info->uri);
                strsep(&tmp, "/");
                if(tmp && (tmp[0] != '\0')) {
                        strsep(&tmp, "/");
                        if(tmp && (tmp[0] != '\0')) {
                                key = strsep(&tmp,"/");
                                if(key && (key[0] != '\0')) {
                                        hash =strsep(&tmp, "/");
                                        if (hash && (hash[0] != '\0')) {
                                                if((strlen(hash) == 6) && (strlen(key) == 20)) {
                                                        if(!please_verify_key(key,hash)) {
                                                                res = "HTTP/1.1 200 OK\r\n";
                                                        }
                                                }
                                        }
                                }
                        }
                }
                /* if(tmp) */
                /*   free(tmp); */
                mg_printf(conn, res);
                return processed;
        } else {
                processed = NULL;
        }

        return processed;
}

static const char *options[] = {
        "document_root", "html",
        "listening_ports", "127.0.0.1:4240",
        "num_threads", "5",
        NULL
};

int main(void) {
        struct mg_context *ctx;

        // Initialize random number generator. It will be used later on for
        // the session identifier creation.
        srand((unsigned) time(0));

        // Setup and start Mongoose
        ctx = mg_start(&event_handler, options);
        assert(ctx != NULL);

        // Wait until enter is pressed, then exit
        printf("PigPen started on ports %s\n",
               mg_get_option(ctx, "listening_ports"));
//  getchar();
        while (1) {
                sleep(1);
        }
        mg_stop(ctx);
        printf("%s\n", "PigPen closed.");

        return EXIT_SUCCESS;
}
