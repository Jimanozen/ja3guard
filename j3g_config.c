#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <toml.h>

#include "j3g_config.h"

struct j3g_config j3g_global_config;

/*
 * Parse the '[ja3guard] table inside config'
 * returns j3g_config_error and if an error occurred as string error are set inside 'errmsg'
 */
int
_j3g_read_table_ja3(toml_table_t *table_ja3, char *errmsg, int err_size)
{
    toml_datum_t value;
    int error;
    
    error = (errmsg != NULL && err_size > 0);
    
    value = toml_string_in(table_ja3, "listen_addr");
    if (!value.ok) {
        if (error)
            (void)strncpy(errmsg, "Missing the key 'listen_addr' in table [ja3guard]", err_size);
        
        return J3G_CONFE_ERR;
    }
    j3g_global_config.ja3.listen_addr = value.u.s;
 
    value = toml_string_in(table_ja3, "tls_cert_file");
    if (!value.ok) {
        if (error)
            (void)strncpy(errmsg, "Missing the key 'tls_cert_file' in table [ja3guard]", err_size);
        
        return J3G_CONFE_ERR;
    }
    j3g_global_config.ja3.tls_cert_file = value.u.s;
    
    value = toml_string_in(table_ja3, "tls_key_file");
    if (!value.ok) {
        if (error)
            (void)strncpy(errmsg, "Missing the key 'tls_key_file' in table [ja3guard]", err_size);
        
        return J3G_CONFE_ERR;
    }
    j3g_global_config.ja3.tls_key_file = value.u.s;
    
    value = toml_string_in(table_ja3, "tls_version");
    if (value.ok) {
        j3g_global_config.ja3.tls_version = value.u.s;
    } else {
        j3g_global_config.ja3.tls_version = strdup("secure");
    }
    
    value = toml_int_in(table_ja3, "listen_port");
    if (value.ok) {
        j3g_global_config.ja3.listen_port = value.u.i;
    } else {
        j3g_global_config.ja3.listen_port = 443;
    }
    
    value = toml_int_in(table_ja3, "workers");
    if (value.ok) {
        j3g_global_config.ja3.workers = value.u.b;
    } else {
        j3g_global_config.ja3.workers = 5;
    }
    
    return J3G_CONFE_OK;
}

/*
 * Parse the '[endpoint] table inside config'
 * returns j3g_config_error and if an error occurred as string error are set inside 'errmsg'
 */
int
_j3g_read_table_endpoint(toml_table_t *table_endpoint, char *errmsg, int err_size)
{
    toml_datum_t value;
    int error;
    
    error = (errmsg != NULL && err_size > 0);
    
    value = toml_string_in(table_endpoint, "servername");
    if (!value.ok) {
        if (error)
            (void)strncpy(errmsg, "Missing the key 'servername' in table [endpoint]", err_size);
        
        return J3G_CONFE_ERR;
    }
    j3g_global_config.endpoint.servername = value.u.s;
    
    value = toml_string_in(table_endpoint, "ip_addr");
    if (!value.ok) {
        if (error)
            (void)strncpy(errmsg, "Missing the key 'ip_addr' in table [endpoint]", err_size);
        
        return J3G_CONFE_ERR;
    }
    j3g_global_config.endpoint.ip_addr = value.u.s;
    
    value = toml_int_in(table_endpoint, "port");
    if (!value.ok) {
        if (error)
            (void)strncpy(errmsg, "Missing the key 'port' in table [endpoint]", err_size);
        
        return J3G_CONFE_ERR;
    }
    j3g_global_config.endpoint.port = value.u.i;
    
    value = toml_bool_in(table_endpoint, "use_tls");
    if (!value.ok) {
        if (error)
            (void)strncpy(errmsg, "Missing the key 'use_tls' in table [endpoint]", err_size);
        
        return J3G_CONFE_ERR;
    }
    j3g_global_config.endpoint.use_tls = value.u.b;
 
    /*
     * Parse the following config only if user want to use tls with endpoint
     */
    if (j3g_global_config.endpoint.use_tls) {
        value = toml_string_in(table_endpoint, "tls_auth_cert_file");
        if (value.ok) {
            j3g_global_config.endpoint.tls_auth_cert_file = value.u.s;
        } else {
            j3g_global_config.endpoint.tls_auth_cert_file = NULL;
        }

        value = toml_string_in(table_endpoint, "tls_auth_key_file");
        if (value.ok) {
            j3g_global_config.endpoint.tls_auth_key_file = value.u.s;
        } else {
            j3g_global_config.endpoint.tls_auth_key_file = NULL;
        }
        
        value = toml_string_in(table_endpoint, "tls_version");
        if (value.ok) {
            j3g_global_config.endpoint.tls_version = value.u.s;
        } else {
            j3g_global_config.endpoint.tls_version = "secure";
        }
        
        value = toml_string_in(table_endpoint, "tls_ca_file");
        if (!value.ok) {
            if (error)
                (void)strncpy(errmsg, "Missing the key 'tls_ca_file' in table [endpoint]", err_size);
            
            return J3G_CONFE_ERR;
        }
        j3g_global_config.endpoint.tls_ca_file = value.u.s;
    }
    
    return J3G_CONFE_OK;
}

/*
 * Parse the '[http] table inside config'
 * returns j3g_config_error and if an error occurred as string error are set inside 'errmsg'
 */
int
_j3g_read_table_http(toml_table_t *table_http, char *errmsg, int err_size)
{
    toml_datum_t key;
    toml_datum_t value;
    toml_array_t *array_headers;
    toml_array_t *header;
    int array_headers_len;
    int header_len;
    int i;
    int error;
    
    error = (errmsg != NULL && err_size > 0);
    
    value = toml_bool_in(table_http, "x_ja3_hash");
    if (value.ok) {
        j3g_global_config.http.x_ja3_hash = value.u.b;
    } else {
        j3g_global_config.http.x_ja3_hash = 1;
    }
    
    value = toml_bool_in(table_http, "x_ja3_text");
    if (value.ok) {
        j3g_global_config.http.x_ja3_text = value.u.b;
    } else {
        j3g_global_config.http.x_ja3_text = 1;
    }
    
    value = toml_bool_in(table_http, "x_real_ip_rewrite");
    if (value.ok) {
        j3g_global_config.http.x_real_ip_rewrite = value.u.b;
    } else {
        j3g_global_config.http.x_real_ip_rewrite = 0;
    }
    
    array_headers = toml_array_in(table_http, "custom_headers");
    if (array_headers == NULL)
        return J3G_CONFE_OK;
    
    array_headers_len = toml_array_nelem(array_headers);
    
    j3g_global_config.http.custom_headers = malloc(array_headers_len + sizeof(struct j3g_config_custom_headers));
    if (j3g_global_config.http.custom_headers == NULL)
        return J3G_CONFE_NOMEM;

    j3g_global_config.http.custom_headers_len = array_headers_len;

    for (i = 0; i < array_headers_len; i++) {
        header = toml_array_at(array_headers, i);
        if (header == NULL) {
            (void)strncpy(errmsg, "Invalid field inside array 'custom_headers'", err_size);

            return J3G_CONFE_ERR;
        }

        header_len = toml_array_nelem(header);
        if (header_len < 2) {
            (void)strncpy(errmsg, "custom_headers field need to be 2 string", err_size);

            return J3G_CONFE_ERR;
        }

        key = toml_string_at(header, 0);
        value = toml_string_at(header, 1);
        if (!key.ok || !value.ok) {
            if (error)
                (void) strncpy(errmsg, "Invalid string inside array field of 'custom_headers'", err_size);

            return J3G_CONFE_ERR;
        }

        if (memmem(key.u.s, strlen(key.u.s)+1, ":\0", 2) == NULL) {
            if (error)
                (void) strncpy(errmsg, "header key need to be ended with ':'", err_size);

            return J3G_CONFE_ERR;
        }

        j3g_global_config.http.custom_headers[i].key = key.u.s;
        j3g_global_config.http.custom_headers[i].value = value.u.s;
    }
    
    return J3G_CONFE_OK;
}

/*
 * Free all field of the global j3g_config and set all field with 0
 */
void
j3g_config_free(void)
{
    int i;
    
    free(j3g_global_config.ja3.listen_addr);
    free(j3g_global_config.ja3.tls_cert_file);
    free(j3g_global_config.ja3.tls_key_file);
    free(j3g_global_config.ja3.tls_version);
    
    free(j3g_global_config.endpoint.ip_addr);
    free(j3g_global_config.endpoint.servername);
    free(j3g_global_config.endpoint.tls_auth_cert_file);
    free(j3g_global_config.endpoint.tls_auth_key_file);
    free(j3g_global_config.endpoint.tls_ca_file);
    free(j3g_global_config.endpoint.tls_version);
    
    /*
     * the custom_headers array has NULL for the last element to determine the end of the array.
     */
    for (i = 0; i < j3g_global_config.http.custom_headers_len; i++) {
        free(j3g_global_config.http.custom_headers[i].key);
        free(j3g_global_config.http.custom_headers[i].value);
    }
    
    free(j3g_global_config.http.custom_headers);
    
    (void)memset(&j3g_global_config, 0, sizeof(struct j3g_config));
}

/*
 * Set default value
 * Because j3g_global_config is global object, by default all value are set to 0
 */
void
_j3g_config_set_default(void)
{
    j3g_global_config.ja3.tls_version = "default";
    j3g_global_config.http.x_ja3_hash = 1;
    j3g_global_config.http.x_ja3_text = 1;
}

/*
 * Parse the TOML configuration file at 'path'
 * returns j3g_config_error and if an error occurred as string error are set inside 'errmsg'
 */
int
j3g_config_parse(const char *path, char *errmsg, int err_size)
{
    FILE* fp;
    toml_table_t *conf;
    toml_table_t *table_ja3;
    toml_table_t *table_endpoint;
    toml_table_t *table_http;
    int ret;
    
    if (path == NULL)
        return J3G_CONFE_INVARGS;

    _j3g_config_set_default();

    fp = fopen(path, "r");
    
    if (fp == NULL) {
        if (errmsg && err_size > 0)
            (void)strncpy(errmsg, strerror(errno), err_size);
        
        return J3G_CONFE_ERR;
    }

    conf = toml_parse_file(fp, errmsg, err_size);
    fclose(fp);
    
    if (conf == NULL)
        return J3G_CONFE_ERR;
    
    table_ja3 = toml_table_in(conf, "ja3guard");
    if (table_ja3 == NULL) {
        if (errmsg && err_size > 0)
            (void)strncpy(errmsg, "Missing '[ja3guard]' table inside config file.", err_size);
        
        return J3G_CONFE_ERR;
    }
    
    table_endpoint = toml_table_in(conf, "endpoint");
    if (table_endpoint == NULL) {
        if (errmsg && err_size > 0)
            (void)strncpy(errmsg, "Missing '[endpoint]' table inside config file.", err_size);
        
        return J3G_CONFE_ERR;
    }
    
    table_http = toml_table_in(conf, "http");
    if (table_http) {
        ret = _j3g_read_table_http(table_http, errmsg, err_size);
        if (ret != J3G_CONFE_OK)
            goto end;
    }
    
    ret = _j3g_read_table_ja3(table_ja3, errmsg, err_size);
    if (ret != J3G_CONFE_OK)
        goto end;
    
    ret = _j3g_read_table_endpoint(table_endpoint, errmsg, err_size);
    if (ret != J3G_CONFE_OK)
        goto end;
    
end:
    toml_free(conf);
    
    return ret;
}
