#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>

#include "j3g_ja3_fingerprint.h"

#define J3G_JA3_UINT16_STRLEN 5UL

#define J3G_JA3_EXT_SUPP_GROUPS  0x0A
#define J3G_JA3_EXT_EC_POINT_FMT 0x0B

struct j3g_ja3_extensions {
    const unsigned char *ec_points_format;
    const unsigned char *supported_groups;
};

/*
 * Write the hex string representation of md5 data inside md5_raw
 * returns a j3g_ja3_error enum
 */
static int
_j3g_ja3_md5_hex(struct j3g_ja3 *ja3, const unsigned char *md5_raw)
{
    int i;
    
    if (ja3 == NULL)
        return J3G_JA3E_INVARGS;
    
    for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
        /* flawfinder: ignore */
        (void)sprintf((char *)&ja3->md5[i << 1], "%02x", md5_raw[i]);
    }
    
    return J3G_JA3E_OK;
}

/*
 * Write the string representation of 16 bits 'num' inside 'numstr'
 * returns the len of character write into numstr.
 */
static int
_j3g_uint16_to_str(char *numstr, uint16_t num)
{
    int ret;
    
    if (numstr == NULL)
        return 0;
    
    ret = snprintf(numstr, J3G_JA3_UINT16_STRLEN + 1, "%u", num);
    
    return ret;
}

/*
 * Append the EC Points Formats inside the ja3 full_string filed.
 * return a j3g_ja3_error enum
 */
static int
_j3g_ja3_append_ec_points_format(struct j3g_ja3 *ja3,
                                 const struct j3g_tls_client_hello *hello,
                                 struct j3g_ja3_extensions *ext_s)
{
    const unsigned char *p_ec_points_format;
    size_t *p_fullstr_len;
    uint16_t ec_points_format_size;
    uint16_t ec_points_format_len;
    uint16_t i;
    
    if (ja3 == NULL || ext_s == NULL || hello == NULL)
        return J3G_JA3E_INVARGS;
    
    if (ext_s->ec_points_format == NULL)
        return J3G_JA3E_INVARGS;
    
    p_fullstr_len = &ja3->full_string_len;
    p_ec_points_format = ext_s->ec_points_format;
    
    ec_points_format_size = *(uint16_t *)p_ec_points_format;
    ec_points_format_size = ntohs(ec_points_format_size);
    p_ec_points_format += sizeof(uint16_t);
    
    /* assuming the size of this extension is invalid */
    if (ec_points_format_size >= hello->extensions_length)
        return J3G_JA3E_INVTLS_DATA;
        
    ec_points_format_len = *(uint8_t *)p_ec_points_format;
    p_ec_points_format += sizeof(uint8_t);

    /* assuming the len (nb elements) of this extension is invalid */
    if (ec_points_format_len >= ec_points_format_size)
        return J3G_JA3E_INVTLS_DATA;
    
    for (i = 0; i < ec_points_format_len; i++) {
        uint16_t ec_point;
        
        if ((ja3->full_string_len + 2) > J3G_JA3_FULLSTR_MAX_LEN)
            return J3G_JA3E_NOMEM;
        
        ec_point = *(uint8_t *)p_ec_points_format;
        
        ja3->full_string[ja3->full_string_len] = ec_point + '0';
        *p_fullstr_len += sizeof(uint8_t);
        
        ja3->full_string[*p_fullstr_len] = '-';
        *p_fullstr_len += 1;
        
        p_ec_points_format += sizeof(uint8_t);
    }
    
    return J3G_JA3E_OK;
}

/*
 * Append the Supported Groups (EllipticCurves) inside the ja3 full_string filed.
 * return a j3g_ja3_error enum
 */
static int
_j3g_ja3_append_supported_groups(struct j3g_ja3 *ja3,
                                 const struct j3g_tls_client_hello *hello,
                                 struct j3g_ja3_extensions *ext_s)
{
    const unsigned char *p_supported_groups;
    size_t *p_fullstr_len;
    uint16_t supported_groups_size;
    uint16_t supp_groups_length;
    uint16_t i;
    int ret;
    
    if (ja3 == NULL || ext_s == NULL || hello == NULL)
        return J3G_JA3E_INVARGS;
    
    if (ext_s->supported_groups == NULL)
        return J3G_JA3E_INVARGS;
    
    p_fullstr_len = &ja3->full_string_len;
    p_supported_groups = ext_s->supported_groups;
    
    /* assuming the size of this extension is invalid */
    supported_groups_size = *(uint16_t *)p_supported_groups;
    supported_groups_size = ntohs(supported_groups_size);
    p_supported_groups += sizeof(uint16_t);
    
    if (supported_groups_size >= hello->extensions_length)
        return J3G_JA3E_INVTLS_DATA;
        
    supp_groups_length = *(uint16_t *)p_supported_groups;
    supp_groups_length = ntohs(supp_groups_length);
    p_supported_groups += sizeof(uint16_t);

    /* assuming the len (nb elements) of this extension is invalid */
    if (supp_groups_length >= supported_groups_size)
        return J3G_JA3E_INVTLS_DATA;
    
    for (i = 0; i < (supp_groups_length / 2); i++) {
        uint16_t group;
        
        if ((ja3->full_string_len + J3G_JA3_UINT16_STRLEN + 1) > J3G_JA3_FULLSTR_MAX_LEN)
            return J3G_JA3E_NOMEM;
        
        group = *(uint16_t *)p_supported_groups;
        group = ntohs(group);
        
        if (!j3g_tls_is_grease(group)) {
            ret = _j3g_uint16_to_str(&ja3->full_string[*p_fullstr_len], group);
            *p_fullstr_len += ret;
            
            ja3->full_string[*p_fullstr_len] = '-';
            *p_fullstr_len += 1;
        }
        
        p_supported_groups += sizeof(uint16_t);
    }
    
    return J3G_JA3E_OK;
}

/*
 * Append all Extensions ID inside the ja3 full_string filed.
 * return a j3g_ja3_error enum
 */
static int
_j3g_ja3_append_extensions(struct j3g_ja3 *ja3,
                           const struct j3g_tls_client_hello *hello,
                           struct j3g_ja3_extensions *ext_s)
{
    const unsigned char *p_extensions;
    size_t *p_fullstr_len;
    uint16_t remain_bytes;
    int ret;
    
    if (ja3 == NULL || hello == NULL || ext_s == NULL)
        return J3G_JA3E_INVARGS;
    
    p_fullstr_len = &ja3->full_string_len;
    p_extensions = hello->extensions_ptr;
    remain_bytes = hello->extensions_length;
    
    while (remain_bytes != 0) {
        uint16_t ext_id;
        uint16_t ext_len;
        
        if ((*p_fullstr_len + J3G_JA3_UINT16_STRLEN + 1) > J3G_JA3_FULLSTR_MAX_LEN)
            return J3G_JA3E_NOMEM;
        
        ext_id = *(uint16_t *)p_extensions;
        ext_id = ntohs(ext_id);
        p_extensions += sizeof(uint16_t);
        remain_bytes -= sizeof(uint16_t);
        
        if (!j3g_tls_is_grease(ext_id)) {
            ret = _j3g_uint16_to_str(&ja3->full_string[*p_fullstr_len], ext_id);
            *p_fullstr_len += ret;
            
            ja3->full_string[*p_fullstr_len] = '-';
            *p_fullstr_len += 1;
            
            if (ext_id == J3G_JA3_EXT_SUPP_GROUPS)
                ext_s->supported_groups = p_extensions;
                
            if (ext_id == J3G_JA3_EXT_EC_POINT_FMT)
                ext_s->ec_points_format = p_extensions;
        }
        
        ext_len = *(uint16_t *)p_extensions;
        ext_len = ntohs(ext_len);
        p_extensions += (ext_len + sizeof(uint16_t));
        remain_bytes -= (ext_len + sizeof(uint16_t));
    }
    
    return J3G_JA3E_OK;
}

/*
 * Append the Cipher Suites inside the ja3 full_string filed.
 * return a j3g_ja3_error enum
 */
static int
_j3g_ja3_append_cipher_suites(struct j3g_ja3 *ja3, const struct j3g_tls_client_hello *hello)
{

    const unsigned char *p_cipher_suites;
    size_t *p_fullstr_len;
    uint16_t cipher_suites_len;
    uint16_t i;
    int ret;
    
    if (ja3 == NULL || hello == NULL)
        return J3G_JA3E_INVARGS;
    
    if (hello->cipher_suite_length == 0 || hello->cipher_suites_ptr == NULL)
        return J3G_JA3E_INVARGS;
    
    p_fullstr_len = &ja3->full_string_len;
    
    cipher_suites_len = hello->cipher_suite_length / 2;
    p_cipher_suites = hello->cipher_suites_ptr;
    
    for (i = 0; i < cipher_suites_len; i++) {
        uint16_t cipher;
        
        if ((*p_fullstr_len + J3G_JA3_UINT16_STRLEN + 1) > J3G_JA3_FULLSTR_MAX_LEN)
            return J3G_JA3E_NOMEM;
        
        cipher = *(uint16_t *)p_cipher_suites;
        cipher = ntohs(cipher);
        
        if (!j3g_tls_is_grease(cipher)) {
            ret = _j3g_uint16_to_str(&ja3->full_string[*p_fullstr_len], cipher);
            *p_fullstr_len += ret;
            
            ja3->full_string[*p_fullstr_len] = '-';
            *p_fullstr_len += 1;
        }
        
        p_cipher_suites += sizeof(uint16_t);
    }
    
    ja3->full_string[ja3->full_string_len - 1] = ',';
    
    return J3G_JA3E_OK;
}

/*
 * Append the Client TLS version (handshake) inside the ja3 full_string filed.
 * return a j3g_ja3_error enum
 */
static int
_j3g_ja3_append_version(struct j3g_ja3 *ja3, const struct j3g_tls_client_hello *hello)
{
    int ret;
    uint16_t tls_version;
    
    if (ja3 == NULL || hello == NULL)
        return J3G_JA3E_INVARGS;
    
    tls_version = ntohs(hello->client_version);
    
    ret = _j3g_uint16_to_str(ja3->full_string, tls_version);
    ja3->full_string_len += ret;
    
    ja3->full_string[ja3->full_string_len] = ',';
    ja3->full_string_len += 1;
    
    return J3G_JA3E_OK;
}

/*
 * Create the ja3 full_string and MD5 fingerprint of the TLS client hello handshake.
 * and set the ja3 full_string and its fingerprint inside the 'ja3' j3g_ja3 struct.
 * return a j3g_ja3_error enum
 */
int
j3g_ja3_fingerprint(struct j3g_ja3 *ja3, const struct j3g_tls_client_hello *hello)
{
    struct j3g_ja3_extensions ja3_ext;
    int ret;
    /* flawfinder: ignore */
    unsigned char md5_raw[MD5_DIGEST_LENGTH];
    
    if (ja3 == NULL || hello == NULL)
        return J3G_JA3E_INVARGS;
 
    ja3_ext.ec_points_format = NULL;
    ja3_ext.supported_groups = NULL;
    
    (void)memset(ja3, 0, sizeof(struct j3g_ja3));
    
    ret = _j3g_ja3_append_version(ja3, hello);
    
    if (ret != 0)
        return ret;
    
    ret = _j3g_ja3_append_cipher_suites(ja3, hello);
    if (ret != 0)
        return ret;
    
    ret = _j3g_ja3_append_extensions(ja3, hello, &ja3_ext);
    
    if (ret != 0)
        return ret;
    
    ja3->full_string[ja3->full_string_len - 1] = ',';
    
    ret = _j3g_ja3_append_supported_groups(ja3, hello, &ja3_ext);

    if (ret != 0)
        return ret;
    
    ja3->full_string[ja3->full_string_len - 1] = ',';
    
    ret = _j3g_ja3_append_ec_points_format(ja3, hello, &ja3_ext);

    if (ret != 0)
        return ret;
    
    ja3->full_string[ja3->full_string_len - 1] = '\0';
    ja3->full_string_len -= 1;
    
    (void)MD5((const unsigned char *)ja3->full_string, ja3->full_string_len, md5_raw);
    
    (void)_j3g_ja3_md5_hex(ja3, md5_raw);

    return J3G_JA3E_OK;
}
