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
#include "pig.h"

#include <ctype.h>


const char *secret_folder = "/etc/pig/";


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
                                                if((strlen(hash) == 6) && (strlen(key) <= 255)) {
                                                        if(!verify_key(key,hash, secret_folder, 3)) {
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
