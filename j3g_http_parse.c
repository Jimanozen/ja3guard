#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/queue.h>

#include "j3g_http_parse.h"

/*
 * check if 'method' is a valid HTTP method.
 * returns 1 if method is valid otherwise returns 0
 */
static int
_j3g_http_is_valid_method(const char *method)
{
    int i;
    const char *http_method[9] = {
        "GET", "POST", "HEAD", "PUT", "OPTIONS",
        "PATCH", "DELETE",  "CONNECT", "TRACE"
    };
    
    if (method == NULL)
        return 0;

    for (i = 0; i < 9; i++) {
        if (strcmp(method, http_method[i]) == 0)
            return 1;
    }
        
    return 0;
}

/*
 * check if 'version' is a valid HTTP version "HTTP/1.1".
 * returns 1 if version is correct otherwise returns 0
 */
static int
_j3g_http_is_valid_version(const char *version)
{
    if (version == NULL)
        return 0;
    
    return (strcmp(version, "HTTP/1.1") == 0);
}

/*
 * check if 'path' is a valid HTTP path (if the string start with '/').
 * returns 1 if path is valid otherwise returns 0
 */
static int
_j3g_http_is_valid_path(const char *path)
{
    if (path == NULL)
        return 0;
    
    return (path[0] == '/');
}

/*
 * check if 'data' is an HTTP/1.1 request.
 * returns 1 if data is an HTTP/1.1 request otherwise returns 0
 */
static int
_j3g_is_http_request(const char *data, size_t data_size)
{
    char *crnl;
    char *reqline;
    char *method;
    char *path;
    char *http_version;
    size_t reqline_len;
    int ret;
    
    if (data == NULL || data_size == 0)
        return 0;
    
    crnl = memmem(data, data_size, "\r\n", 2);
    
    if (crnl == NULL)
        return 0;
    
    reqline_len = (size_t)crnl - (size_t)data;
    
    reqline = strndup(data, reqline_len);
    
    method = strsep(&reqline, " ");
    path = strsep(&reqline, " ");
    http_version = strsep(&reqline, " ");
 
    ret = (_j3g_http_is_valid_method(method) &&
           _j3g_http_is_valid_path(path) &&
           _j3g_http_is_valid_version(http_version));
    
    free(method);
    
    return ret;
}

/*
 * parsing the request line of the HTTP/1.1 request.
 * returns a j3g_http_error enumeration.
 */
static int
_j3g_http_parse_reqline(struct j3g_http *http)
{
    char *ptr;
    size_t reqline_len;
    
    if (http == NULL || http->raw == NULL || http->raw_size == 0)
        return J3G_HTTPE_INVARGS;
    
    ptr = memmem(http->raw, http->raw_size, "\r\n", 2);

    if (ptr == NULL)
        return J3G_HTTPE_INVHTTP;
    
    ptr += 2; /* passing CRL-LN */
    
    reqline_len = (size_t)ptr - (size_t)http->raw;
    
    http->req_line = (char *)http->raw;
    http->req_line_len = reqline_len;
    
    return J3G_HTTPE_OK;
}

/*
 * parsing the headers data of the HTTP/1.1 request.
 * returns a j3g_http_error enumeration.
 *
 * This function duplicate all header 'key: value\r\n' and append them inside headers queue.
 * If an error occured, the error code is returned and all allocated memory are automatically free'd
 */
static int
_j3g_http_parse_headers(struct j3g_http *http)
{
    char *colon;
    char *crnl;
    char *ptr;
    char *header_start;
    char *header_end;
    size_t count;
    size_t header_len;
    
    if (http == NULL || http->raw == NULL || http->raw_size == 0)
        return J3G_HTTPE_INVARGS;
    
    if (http->req_line == NULL || http->req_line_len == 0)
        return J3G_HTTPE_INVARGS;
    
    header_start = &http->req_line[http->req_line_len];
    
    header_end = memmem(header_start, http->raw_size - http->req_line_len, "\r\n\r\n", 4);
    
    if (header_end == NULL)
        return J3G_HTTPE_INVHTTP;

    header_end += 2; /* pointing to the end of the CR-NL */
    
    header_len = (size_t)header_end - (size_t)header_start;
    http->header_len = header_len;
    
    count = 0;
    ptr = header_start;
    
    while (count != header_len) {
        struct j3g_http_headers *hdr_s;
        size_t curr_hdr_len = 0;
        
        crnl = memmem(ptr, header_len, "\r\n", 2);

        if (crnl == NULL)
            return J3G_HTTPE_INVHTTP;

        crnl += 2; /* pointing to the end of CR-NL */
        curr_hdr_len = (size_t)crnl - (size_t)ptr;
        
        hdr_s = malloc(sizeof(struct j3g_http_headers));
        
        if (hdr_s == NULL) {
            j3g_http_cleanup(http);
            
            return J3G_HTTPE_NOMEM;
        }

        hdr_s->value = strndup(ptr, curr_hdr_len);
        
        if (hdr_s->value == NULL) {
            free(hdr_s);
            j3g_http_cleanup(http);
            
            return J3G_HTTPE_NOMEM;
        }
        
        hdr_s->len = curr_hdr_len;
    
        colon = memmem(hdr_s->value, hdr_s->len, ": ", 2);
        
        if (colon == NULL) {
            free(hdr_s->value);
            free(hdr_s);
            j3g_http_cleanup(http);
            
            return J3G_HTTPE_INVHTTP;
        }
        
        hdr_s->key_len = (size_t)colon - (size_t)hdr_s->value;
        
        ptr += curr_hdr_len;
        count += curr_hdr_len;
        
        TAILQ_INSERT_TAIL(&http->headers, hdr_s, entries);
    }

    return J3G_HTTPE_OK;
}

/* parse the HTTP/1.1 request body */
static int
_j3g_http_parse_body(struct j3g_http *http)
{
    if (http == NULL)
        return J3G_HTTPE_INVARGS;
    
    http->body_len = (http->raw_size - (http->req_line_len + http->header_len));
    http->body = &http->raw[http->req_line_len + http->header_len];
    
    return J3G_HTTPE_OK;
}

/*
 * Write all headers data in headers queue into 'out'.
 * this function change the pointer 'out' for pointing to the end of writted headers.
 * returns a j3g_http_error enumeration.
 */
static int
_j3g_http_write_header(struct j3g_http *http, char **out, size_t *out_size)
{
    struct j3g_http_headers *current_element;
    char *ptr;
    
    if (http == NULL || *out == NULL || *out_size == 0)
        return J3G_HTTPE_INVARGS;
    
    ptr = *out;
    
    TAILQ_FOREACH(current_element, &http->headers, entries) {
        if (current_element->len > *out_size)
            return J3G_HTTPE_NOMEM;
        
        (void)memcpy(ptr, current_element->value, current_element->len);
        
        ptr += current_element->len;
        *out_size -= current_element->len;
    }
    
    *out = ptr;
    
    return J3G_HTTPE_OK;
}

/*
 * cleanup and free all data inside 'http'
 */
void
j3g_http_cleanup(struct j3g_http *http)
{
    if (http == NULL)
        return;
    
    while (!TAILQ_EMPTY(&http->headers)) {
        struct j3g_http_headers *elem = TAILQ_FIRST(&http->headers);
        
        TAILQ_REMOVE(&http->headers, elem, entries);
        free(elem->value);
        free(elem);
    }
    
    (void)memset(http, 0, sizeof(struct j3g_http));
}

/*
 * Search the 'key' corresponding to a key header inside the headers queue.
 * 'key' string need to be ended with colon ':'.
 * returns the pointer to the corresponding node where the key is found otherwise returns NULL
 */
struct j3g_http_headers *
j3g_http_headers_find_key(struct j3g_http *http, const char *key)
{
    struct j3g_http_headers *current_element;
    
    if (http == NULL)
        return NULL;
    
    TAILQ_FOREACH(current_element, &http->headers, entries) {
        if (strncasecmp(key, current_element->value, strlen(key)) == 0)
            return current_element;
    }
    
    return NULL;
}

/*
 * Remove the header data with the header key 'key'.
 * 'key' need to be ended with colon ':'
 * if a header with key 'key' is found in the headers queue then the node is removed and free'd
 *
 * returns 1 if the key is found and removed otherwise returns 0
 */
int
j3g_http_headers_remove_key(struct j3g_http *http, const char *key)
{
    struct j3g_http_headers *hdr_s;
    
    if (http == NULL || key == NULL)
        return 0;
    
    hdr_s = j3g_http_headers_find_key(http, key);
    
    if (hdr_s == NULL)
        return 0;
    
    http->header_len -= hdr_s->len;
    
    TAILQ_REMOVE(&http->headers, hdr_s, entries);
    free(hdr_s->value);
    free(hdr_s);
    
    return 1;
}

/*
 * Insert a new header inside the headers queue.
 * 'key' need to be ended with colon ':'.
 * 'key' and 'value' are duplicated so user can free'd key and value after calling this function.
 * if the specified 'key' exist then the existing header node is modified with the new value.
 * returs a j3g_http_error enumeration.
 */
int
j3g_http_headers_insert(struct j3g_http *http, const char *key, const char *value)
{
    struct j3g_http_headers *hdr_s;
    char *header;
    char *ptr;
    size_t key_len;
    size_t value_len;
    size_t header_len;
    
    if (http == NULL || key == NULL || value == NULL)
        return J3G_HTTPE_INVARGS;
    
    key_len = strlen(key);
    value_len = strlen(value);
    header_len = key_len + strlen(" ") + value_len + strlen("\r\n");
    
    header = malloc(header_len + 1);
    
    if (header == NULL)
        return J3G_HTTPE_NOMEM;
    
    ptr = header;

    ptr = stpcpy(ptr, key);
    ptr = stpcpy(ptr, " ");
    ptr = stpcpy(ptr, value);
    (void)stpcpy(ptr, "\r\n");
    
    hdr_s = j3g_http_headers_find_key(http, key);
    
    /* if a header with the followed key already exist in the headers queue then
     * just replace the current value of the header node with the new value.
     * and returns J3G_HTTPE_OK
     */
    if (hdr_s) {
        free(hdr_s->value);
        http->header_len -= hdr_s->len;
        
        hdr_s->value = header;
        hdr_s->len = header_len;
        hdr_s->key_len = key_len;
        
        http->header_len += header_len;
        
        return J3G_HTTPE_OK;
    }
    
     /* otherwise the followed key doesn't exist in the headers queue allocate a new header node */
    hdr_s = malloc(sizeof(struct j3g_http_headers));
    
    if (hdr_s == NULL) {
        free(header);
        
        return J3G_HTTPE_NOMEM;
    }
        
    hdr_s->value = header;
    hdr_s->len = header_len;
    hdr_s->key_len = key_len;
    
    http->header_len += header_len;
    
    TAILQ_INSERT_TAIL(&http->headers, hdr_s, entries);
    
    return J3G_HTTPE_OK;
}

/* 
 * calcul the total size of the HTTP/1.1 request.
 * returns the size of the HTTP/1.1 request.
 */
size_t
j3g_http_total_size(struct j3g_http *http)
{
    if (http)
        return (http->req_line_len + http->header_len + http->body_len);
    
    return 0;
}

/*
 * Parsing the raw HTTP/1.1 data.
 * this function is also an initializator for j3g_http struct.
 * 'raw_http' is not duplicated then the user MUST NOT free or modify the 'raw_http' after calling this function.
 * returs a j3g_http_error.
 */
int
j3g_http_parser(struct j3g_http *http, const char *raw_http, size_t raw_http_size)
{
    int ret;
    
    if (http == NULL || raw_http == NULL || raw_http_size == 0)
        return J3G_HTTPE_INVARGS;
    
    if (_j3g_is_http_request(raw_http, raw_http_size) == 0)
        return J3G_HTTPE_INVHTTP;

    TAILQ_INIT(&http->headers);
    
    http->raw = (char *)raw_http;
    http->raw_size = raw_http_size;
    
    ret = _j3g_http_parse_reqline(http);
    
    if (ret != J3G_HTTPE_OK)
        return ret;
    
    ret = _j3g_http_parse_headers(http);
    
    if (ret != J3G_HTTPE_OK)
        return ret;
    
    ret = _j3g_http_parse_body(http);
    
    return ret;
}

/*
 * Write the HTTP/1.1 request of 'http' j3g_http into 'out'
 * returns a j3g_http_error enumeration.
 */
int
j3g_http_build_request(struct j3g_http *http, char *out, size_t out_size)
{
    char *ptr;
    int ret;
    
    if (http == NULL || out == NULL || out_size == 0)
        return J3G_HTTPE_NOMEM;
    
    ptr = out;
    
    if (http->req_line_len > out_size)
        return J3G_HTTPE_NOMEM;
    
    (void)memcpy(ptr, http->req_line, http->req_line_len);
    
    ptr += http->req_line_len;
    out_size -= http->req_line_len;
    
    if (http->header_len > out_size)
        return J3G_HTTPE_NOMEM;
    
    ret = _j3g_http_write_header(http, &ptr, &out_size);
    
    if (ret != J3G_HTTPE_OK)
        return ret;
    
    if (http->body_len > out_size)
        return J3G_HTTPE_NOMEM;
    
    (void)memcpy(ptr, http->body, http->body_len);
    
    return J3G_HTTPE_OK;
}

/*
 * Append the header "X-Forwarded-For" with value ip.
 * if the header already set, adding ip at the end of the "ip list"
 * otherwise a new header is created.
 * retuns a j3g_http_error enumeration.
 */
int
j3g_http_xforwardedfor_add(struct j3g_http *http, const char *ip)
{
    struct j3g_http_headers *hdr_s;
    size_t ip_len;
    size_t buf_len;
    size_t value_len;
    char *buf;
    char *ptr;
    char *value_ptr;
    int ret;
    
    if (http == NULL || ip == NULL)
        return J3G_HTTPE_INVARGS;
    
    hdr_s = j3g_http_headers_find_key(http, "X-Forwarded-For:");
    
    /*
     * if the header doesn't exist, juste create it and return
     */
    if (hdr_s == NULL)
        return j3g_http_headers_insert(http, "X-Forwarded-For:", ip);
    
    /* otherwise append 'ip' to the end of the ip list. */

    ip_len = strlen(ip);
    buf_len = hdr_s->len + strlen(", ") + ip_len - strlen("\r\n");
    
    buf = malloc(buf_len + 1);
    
    if (buf == NULL)
        return J3G_HTTPE_NOMEM;
    
    ptr = buf;
    
    value_ptr = &hdr_s->value[hdr_s->key_len + 2]; /* 2 = ': ' */
    value_len = hdr_s->len - hdr_s->key_len - strlen(": ") - strlen("\r\n");
    
    ptr = stpncpy(ptr, value_ptr, value_len);
    ptr = stpncpy(ptr, ", ", 2);
    (void)stpncpy(ptr, ip, ip_len);
    
    ret = j3g_http_headers_insert(http, "X-Forwarded-For:", buf);
    
    free(buf);
    
    return ret;
}
