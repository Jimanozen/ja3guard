#ifndef j3g_tls_parse_h
#define j3g_tls_parse_h

#include <stdint.h>

/* #define TLS_MAX_FRAGMENT_SIZE 16384U */
#define J3G_TLS_HANDSHAKE 0x16
#define J3G_TLS_HDSHK_CLIENT_HELLO 0x01

/*
 * 1 byte: Content Type
 * 2 bytes: TLS Version
 * 2 bytes: Length
 */
#define J3G_TLSPLAIN_MIN 5u

/*
 * 1 byte: Handshake Type
 * 3 bytes: Length
 */
#define J3G_TLSHANDSHAKE_MIN 4u

/*
 * 2 bytes: Version
 * 32 bytes: Random
 * 1 bytes: Session ID Length
 * 2 bytes: Cipher Suites Length
 * 1 bytes: Compression Methods Length
 * 2 bytes: Extensions Length
 */
#define J3G_TLSHANDSHK_CLIENT_HELLO_MIN 40

enum j3g_tls_error {
    J3G_TLSE_INVVERSION = -7,
    J3G_TLSE_INVSIZE    = -6,
    J3G_TLSE_INVFRAG    = -5,
    J3G_TLSE_INVHDSHK   = -4,
    J3G_TLSE_INVHELLO   = -3,
    J3G_TLSE_INVARGS    = -2,
    J3G_TLSE_NOMEM      = -1,
    J3G_TLSE_OK         = 0
};

enum j3g_tls_versions {
    J3G_TLSV1_0 = 0x0301,
    J3G_TLSV1_1 = 0x0302,
    J3G_TLSV1_2 = 0x0303,
    J3G_TLSV1_3 = 0x0304
};

struct j3g_tls_handshake {
    const unsigned char *body;
    uint32_t    length;
    uint8_t     msg_type;
};

struct j3g_tls_record {
    const unsigned char *fragment;
    uint16_t protocol_version;
    uint16_t length;
    uint8_t  type;
};

struct j3g_tls_client_random {
    uint32_t    gmt_unix_time;
    uint8_t     random_bytes[28];
};

struct j3g_tls_extension {
    unsigned char   *data;
    uint16_t     type;
    uint16_t     length;
};

/*
 * structure members have been re-arranged to avoid padding
 * */
struct j3g_tls_client_hello {
    struct j3g_tls_client_random    client_random;
    const unsigned char *cipher_suites_ptr;
    const unsigned char *compression_methods_ptr;
    const unsigned char *extensions_ptr;
    uint8_t     session_id[32];
    uint32_t    extensions_length;
    uint16_t    cipher_suite_length;
    uint16_t    client_version;
    uint8_t     compression_methods_length;
    uint8_t     session_id_length;
};

int j3g_tls_is_grease(const uint16_t value);
int j3g_tls_traverse_record(struct j3g_tls_record *record, const unsigned char *data, size_t size);
int j3g_tls_traverse_handshake(struct j3g_tls_handshake *handshake, const struct j3g_tls_record *record);
int j3g_tls_traverse_client_hello(struct j3g_tls_client_hello *hello, const struct j3g_tls_handshake *handshake);

#endif /* j3g_tls_parse_h */
