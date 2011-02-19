#ifndef _PIG_H
#define _PIG_H

#include "hmac_sha2.h"

int verify_key(const char *id, const char *hash, const char *folder, int skew);

#endif
