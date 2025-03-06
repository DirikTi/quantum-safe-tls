#ifndef SSL_ERROR_H_
#define SSL_ERROR_H_

#include <stdlib.h>

/* Bootstrap SSL_CTX error codes and messages */
#define SSL_CREATE_CTX_ERROR (int8_t)-1
#define SSL_CREATE_CTX_MSG "Failed to create SSL context"

#define SSL_INVALID_CERTS_ERROR (int8_t)-2
#define SSL_INVALID_CERTS_MSG "Invalid or missing TLS certificate file"

#define SSL_INVALID_PRIVATE_ERROR (int8_t)-3
#define SSL_INVALID_PRIVATE_MSG "Invalid or missing TLS private key file"

#define SSL_CHECK_PRIVATE_ERROR (int8_t)-4
#define SSL_CHECK_PRIVATE_MSG "TLS private key does not match the certificate"

#define SSL_PROTOCOL_ERROR (int8_t)-5
#define SSL_PROTOCOL_MSG "Failed to set the minimum TLS protocol version"

#define SSL_CIPHER_ERROR (int8_t)-6
#define SSL_CIPHER_MSG "Failed to set the TLS cipher list"

#define SSL_MISSING_CERT_ERROR (int8_t)-7
#define SSL_MISSING_CERT_MSG "SSL certificates are missing"

#define SSL_MISSING_KEY_ERROR (int8_t)-8
#define SSL_MISSING_KEY_MSG "SSL private keys are missing"

#define SSL_KEM_ERROR (int8_t)-9
#define SSL_KEM_MSG "Failed to set KEM"


void handle_ssl_ctx_error(int8_t ssl_ctx_error_code);

#endif // SSL_ERROR_H_