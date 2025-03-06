#ifndef TLS_H_
#define TLS_H_

#include <openssl/ssl.h>
#include <oqs/oqs.h>

typedef struct {
    uint32_t connection_timeout;
    int max_connections;
    uint32_t max_handshake_attempts;
    bool session_resumption_enable;
    bool ocsp_stapling_enable;
    
    SSL_CTX *ssl_context;
    int server_fd;

} TLS_CTX;

#endif // TLS_H