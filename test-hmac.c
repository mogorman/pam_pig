/*
 You need to add the following (or equivalent) to the
  /etc/pam.d/check_user file:
  # check authorization
  auth       required     pam_unix.so
  account    required     pam_unix.so
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hmac_sha2.h"


int main(int argc, char *argv[])
{
        hmac_sha256(key, key_size, message,
                    message_size, hmac, SHA256_DIGEST_SIZE);
        return 0;
}
