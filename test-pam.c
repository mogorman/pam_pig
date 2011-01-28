/*
 You need to add the following (or equivalent) to the
  /etc/pam.d/check_user file:
  # check authorization
  auth       required     pam_unix.so
  account    required     pam_unix.so
 */

#ifdef MACOSX
#include <pam/pam_appl.h>
#include <pam/pam_misc.h>
#else
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#endif
#include <stdio.h>


static int conversation(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr);

int authenticate(const char *service,const char *user, const char *passwd);


static struct pam_conv conv = {
    misc_conv,
    NULL
};

int main(int argc, char *argv[])
{
    pam_handle_t *pamh=NULL;
    int ret = 0;
    const char *user="mog";
    const char *password = "tester";

    if(argc == 2) {
        user = argv[1];
    }

    if(argc > 2) {
        fprintf(stderr, "Usage: check_user [username]\n");
        exit(1);
    }
    ret = authenticate("check_user", user, password);
    switch (ret) {
    case PAM_SUCCESS:
            printf("yay!\n");
            break;
    default:
            printf("fail\n");
            break;
    }
    return 0;
}

static int conversation(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr) {
    /* return the supplied password back to PAM */
    *resp = calloc(num_msg, sizeof(struct pam_response));
    (*resp)[0].resp = strdup((char *) appdata_ptr);
    (*resp)[0].resp_retcode = 0;

    /* do not accept empty passwords */
    return ((*resp)[0].resp ? PAM_SUCCESS : PAM_CONV_ERR);
}

int authenticate(const char *service,const char *user, const char *passwd) {
    struct pam_conv conv = { conversation, passwd };
    pam_handle_t *pamh = NULL;
    int ret;

    ret = pam_start(service, user, &conv, &pamh);
    if (ret != PAM_SUCCESS) {
        return ret;
    }

    ret = pam_authenticate(pamh, PAM_SILENT);
    if (ret != PAM_SUCCESS) {
        return ret;
    }

    ret = pam_end(pamh, 0);
    if (ret != PAM_SUCCESS) {
        return ret;
    }
    return PAM_SUCCESS;
}
