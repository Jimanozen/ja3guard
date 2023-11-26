#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "j3g_tls_parse.h"

/*
 * Check if 'version' is a valid TLS version
 * returns 1 if is valid otherwise returns 0.
 */
static int
__j3g_tls_check_version(uint16_t version)
{
    uint16_t check;
    
    check = 0;
    
    if ((version == J3G_TLSV1_0) || (version == J3G_TLSV1_1) ||
        (version == J3G_TLSV1_2) || (version == J3G_TLSV1_3)) {
        
        check = 1;
    }
    
    return check;
}

/*
 * Check if the 'value' is a GREASE (Generate Random Extensions And Sustain Extensibility)
 * RFC: https://www.rfc-editor.org/rfc/rfc8701
 * returns 1 if the value match GREASE otherwise returns 0.
 */
int
j3g_tls_is_grease(const uint16_t value)
{
    int check;
    
    check = 0;
    
    if (((value & 0x0f0f) == 0x0a0a) && ((value & 0xff) == (value >> 8)))
        check = 1;
    
    return check;
}

/*
 * Parse the TLS 'TLSPlaintext' pointed by 'data' and stores value into 'record'.
 * RFC SECTION: https://www.rfc-editor.org/rfc/rfc5246#section-6.2.1
 * returns a j3g_tls_error enum.
 */
int
j3g_tls_traverse_record(struct j3g_tls_record *record,
                        const unsigned char *data,
                        size_t size)
{
	const unsigned char *ptr;
    uint16_t version;
    uint16_t length;

	if (record == NULL || data == NULL)
        return J3G_TLSE_INVARGS;

    if (size < J3G_TLSPLAIN_MIN)
        return J3G_TLSE_INVSIZE;
    
	ptr = data;

    record->type = ptr[0];
    
	if (record->type != J3G_TLS_HANDSHAKE)
        return J3G_TLSE_INVHDSHK;
    
    ptr += sizeof(uint8_t);
    
    version = ntohs(*(uint16_t *)ptr);

    record->protocol_version = version;
    
    if (!__j3g_tls_check_version(version))
        return J3G_TLSE_INVVERSION;
    
    ptr += sizeof(uint16_t);
    
    length = ntohs(*(uint16_t *)ptr);
    
    record->length = length;

	ptr += sizeof(uint16_t);
    
    record->fragment = ptr;
    
    return J3G_TLSE_OK;
}

/*
 * Parse the TLS 'Handshake' inside 'record' and stores value into 'handshake'.
 * RFC SECTION: https://www.rfc-editor.org/rfc/rfc5246#section-7.4
 * returns a j3g_tls_error enum.
 */
int
j3g_tls_traverse_handshake(struct j3g_tls_handshake *handshake,
                           const struct j3g_tls_record *record)
{
    uint32_t length;
    const unsigned char *ptr;
    /* flawfinder: ignore */
    unsigned char handshake_length[4];

    if (handshake == NULL || record == NULL)
        return J3G_TLSE_INVARGS;
    
    if (record->fragment == NULL)
        return J3G_TLSE_INVFRAG;
    
    if (record->length < J3G_TLSHANDSHAKE_MIN)
        return J3G_TLSE_INVSIZE;
    
    ptr = record->fragment;
    
    handshake->msg_type = ptr[0];
    
    ptr += sizeof(uint8_t);
    
    /*
     * the size of the handshake is stored on 3 bytes,
     * add a 0 to the least significant byte to be able
     * to use it as an uint32_t
     * */
    handshake_length[0] = 0;
    handshake_length[1] = *ptr++;
    handshake_length[2] = *ptr++;
    handshake_length[3] = *ptr++;
    
    length = ntohl(*(uint32_t *)&handshake_length);
    
    handshake->length = length;
    handshake->body = ptr;
    
    return J3G_TLSE_OK;
}

/*
 * Parse the TLS 'Client Hello' inside 'handshake' and stores value into 'hello'.
 * RFC SECTION: https://www.rfc-editor.org/rfc/rfc5246#section-7.4.1.2
 * returns a j3g_tls_error enum.
 */
int
j3g_tls_traverse_client_hello(struct j3g_tls_client_hello *hello, const struct j3g_tls_handshake *handshake)
{
    const unsigned char *ptr;
    uint8_t compression_methods_length;
    uint8_t session_id_length;
    uint16_t cipher_suite_length;
    uint16_t extensions_length;
    uint32_t remaining_bytes;
    
    if (hello == NULL || handshake == NULL)
        return J3G_TLSE_INVARGS;

    if (handshake->msg_type != J3G_TLS_HDSHK_CLIENT_HELLO)
        return J3G_TLSE_INVHDSHK;
    
    remaining_bytes = handshake->length;
    
    if (remaining_bytes < J3G_TLSHANDSHK_CLIENT_HELLO_MIN)
        return J3G_TLSE_INVSIZE;
    
    ptr = handshake->body;
    
    if (ptr == NULL)
        return J3G_TLSE_INVHDSHK;

    /*
     * parsing Client Version
     */
	hello->client_version = ntohs(*(uint16_t *)ptr);
	ptr += sizeof(uint16_t);
    remaining_bytes -= sizeof(uint16_t);

    /*
     * parsing Client Random
     */
	hello->client_random.gmt_unix_time = *(uint32_t *)ptr;
	ptr += sizeof(uint32_t);
	/* flawfinder: ignore */
	(void)memcpy(hello->client_random.random_bytes, ptr, 28);
	ptr += 28;
    remaining_bytes -= (sizeof(uint32_t) + 28);
    
    /*
     * parsing Session ID
     */
    session_id_length = ptr[0];
    hello->session_id_length = session_id_length;
    ptr += sizeof(uint8_t);
    remaining_bytes -= sizeof(uint8_t);
    
    /* 
     * Assuming bad length entry
     */
    if ((hello->session_id_length > sizeof(hello->session_id)) ||
        (hello->session_id_length > (remaining_bytes - 5))) {
        
        return J3G_TLSE_INVSIZE;
    }

	/* flawfinder: ignore */
	(void)memcpy(hello->session_id, ptr, hello->session_id_length);
	ptr += hello->session_id_length;
    remaining_bytes -= hello->session_id_length;
    
    /*
     * parsing Cipher Suites
     */
	cipher_suite_length = ntohs(*(uint16_t *)ptr);
    hello->cipher_suite_length = cipher_suite_length;
	ptr += sizeof(uint16_t);
    remaining_bytes -= sizeof(uint16_t);
    
    /*
     * Assuming bad length entry
     */
    if (cipher_suite_length > (remaining_bytes - 3))
        return J3G_TLSE_INVSIZE;
    
    hello->cipher_suites_ptr = ptr;
    ptr += cipher_suite_length;
    remaining_bytes -= cipher_suite_length;

    /*
     * parsing Compression Methods
     */
	compression_methods_length = ptr[0];
    hello->compression_methods_length = compression_methods_length;
    ptr += sizeof(uint8_t);
    remaining_bytes -= sizeof(uint8_t);
    
    /* 
     * Assuming bad length entry
     */
    if (compression_methods_length > (remaining_bytes - 2))
        return J3G_TLSE_INVSIZE;
    
    hello->compression_methods_ptr = ptr;
    ptr += compression_methods_length;
    remaining_bytes -= compression_methods_length;

    /*
     * parsing Extensions
     */
	extensions_length = ntohs(*(uint16_t *)ptr);
    hello->extensions_length = extensions_length;
	ptr += sizeof(uint16_t);
    remaining_bytes -= sizeof(uint16_t);
    
    if (extensions_length > remaining_bytes)
        return J3G_TLSE_INVSIZE;
    
    hello->extensions_ptr = ptr;
    
	return J3G_TLSE_OK;
}
