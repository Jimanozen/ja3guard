#ifndef j3g_http_parse_h
#define j3g_http_parse_h

#include <sys/queue.h>

enum j3g_http_error {
    J3G_HTTPE_NOMEM     = -3,
    J3G_HTTPE_INVHTTP   = -2,
    J3G_HTTPE_INVARGS   = -1,
    J3G_HTTPE_OK        = 0
};

struct j3g_http_headers {
    TAILQ_ENTRY(j3g_http_headers) entries;
    char    *value;
    size_t   key_len;
    size_t   len;
};

struct j3g_http {
    TAILQ_HEAD(tailq_head, j3g_http_headers) headers;
    char    *body;
    char    *raw;
    char    *req_line;
    size_t   body_len;
    size_t   header_len;
    size_t   req_line_len;
    size_t   raw_size;
};

void    j3g_http_cleanup(struct j3g_http *http);
int     j3g_http_headers_remove_key(struct j3g_http *http, const char *key);
int     j3g_http_headers_insert(struct j3g_http *http, const char *key, const char *value);
int     j3g_http_parser(struct j3g_http *http, const char *raw_http, size_t raw_http_size);
int     j3g_http_build_request(struct j3g_http *http, char *out, size_t out_size);
int     j3g_http_xforwardedfor_add(struct j3g_http *http, const char *ip);
size_t  j3g_http_total_size(struct j3g_http *http);
struct j3g_http_headers *   j3g_http_headers_find_key(struct j3g_http *http, const char *key);

#endif /* j3g_http_parse_h */
