#ifndef TLS_H_
#define TLS_H_

#include <openssl/ssl.h>
#include <oqs/oqs.h>

#define IP_NAME_LENGTH 127

typedef struct {
    uint32_t connection_timeout;
    int max_connections;
    uint32_t max_handshake_attempts;
    bool session_resumption_enable;
    bool ocsp_stapling_enable;
    
    SSL_CTX *ssl_context;
    int server_fd;
    int epoll_fd;

} TLS_CTX;

typedef struct {
    uint8_t ip_address[4];
    char name[IP_NAME_LENGTH];
} IP_v4;

void cleanup_TLS(TLS_CTX *tls_ctx);
int set_nonblocking(int socketfd);

#endif // TLS_H