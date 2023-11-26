#ifndef j3g_config_h
#define j3g_config_h

#include <stdint.h>

enum j3g_config_error {
    J3G_CONFE_NOMEM = -3,
    J3G_CONFE_ERR = -2,
    J3G_CONFE_INVARGS = -1,
    J3G_CONFE_OK = 0
};

struct j3g_config_custom_headers {
    char *key;
    char *value;
};

struct j3g_config {
    struct {
        char *listen_addr;
        char *tls_cert_file;
        char *tls_key_file;
        char *tls_version;
        int workers;
        uint16_t listen_port;
    } ja3;
    
    struct {
        char *tls_version;
        char *servername;
        char *tls_auth_cert_file;
        char *tls_auth_key_file;
        char *tls_ca_file;
        char *ip_addr;
        int use_tls;
        uint16_t port;
    } endpoint;
    
    struct {
        //char **custom_headers; /* array of string has NULL for the last elem */
        struct j3g_config_custom_headers *custom_headers;
        size_t custom_headers_len;
        uint8_t x_ja3_hash: 1;
        uint8_t x_ja3_text: 1;
        uint8_t x_real_ip_rewrite: 1;
    } http;
};

extern struct j3g_config j3g_global_config;

int     j3g_config_parse(const char *path, char *errmsg, int err_size);
void    j3g_config_free(void);

#endif /* j3g_config_h */
