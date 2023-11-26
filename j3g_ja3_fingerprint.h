#ifndef jg3_ja3_fingerprint_h
#define jg3_ja3_fingerprint_h

#include <openssl/md5.h>
#include "j3g_tls_parse.h"

#define J3G_JA3_MD5_HEXSTRING_LEN (MD5_DIGEST_LENGTH * 2)
#define J3G_JA3_FULLSTR_MAX_LEN 1024

enum j3g_ja3_error {
    J3G_JA3E_NOMEM = -3,
    J3G_JA3E_INVTLS_DATA = -2,
    J3G_JA3E_INVARGS = -1,
    J3G_JA3E_OK = 0
};

struct j3g_ja3 {
    /* hex string representation of md5 (nullbyte terminated) */
    unsigned char md5[J3G_JA3_MD5_HEXSTRING_LEN + 1];
    /* assuming the maximum length of the ja3 full string is not greater than 1023 char. */
    char full_string[J3G_JA3_FULLSTR_MAX_LEN];
    size_t full_string_len;
};

int     j3g_ja3_fingerprint(struct j3g_ja3 *ja3, const struct j3g_tls_client_hello *hello);

#endif /* jg3_ja3_fingerprint_h */
