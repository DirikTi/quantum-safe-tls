#include "ssl_error.h"
#include <openssl/err.h>
#include <openssl/aes.h>

void handle_ssl_ctx_error(int8_t error_code) {
    const char *error_msg = "Unknown SSL error";

    switch (error_code) {
        case SSL_CREATE_CTX_ERROR:
            error_msg = SSL_CREATE_CTX_MSG;
            break;
        case SSL_INVALID_CERTS_ERROR:
            error_msg = SSL_INVALID_CERTS_MSG;
            break;
        case SSL_INVALID_PRIVATE_ERROR:
            error_msg = SSL_INVALID_PRIVATE_MSG;
            break;
        case SSL_CHECK_PRIVATE_ERROR:
            error_msg = SSL_CHECK_PRIVATE_MSG;
            break;
        case SSL_PROTOCOL_ERROR:
            error_msg = SSL_PROTOCOL_MSG;
            break;
        case SSL_CIPHER_ERROR:
            error_msg = SSL_CIPHER_MSG;
            break;
        case SSL_MISSING_CERT_ERROR:
            error_msg = SSL_MISSING_CERT_MSG;
            break;
        case SSL_MISSING_KEY_ERROR:
            error_msg = SSL_MISSING_KEY_MSG;
            break;
        case SSL_KEM_ERROR:
            error_msg = SSL_KEM_MSG;
            break;
    }

    fprintf(stderr, "[SSL ERROR] %s\n", error_msg);

    exit(EXIT_FAILURE);
}
