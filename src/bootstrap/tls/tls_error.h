#ifndef TLS_ERROR_H_
#define TLS_ERROR_H_

/* Bootstrap TLS server error codes and messages */
#define TLS_CONTEXT_CREATE_SOCKET_ERROR (int8_t)-1
#define TLS_CONTEXT_CREATE_SOCKET_MSG "Failed to create socket"

#define TLS_CONTEXT_BIND_ERROR (int8_t)-2
#define TLS_CONTEXT_BIND_MSG "Failed to bind socket to the specified address and port"

#define TLS_CONTEXT_LISTEN_ERROR (int8_t)-3
#define TLS_CONTEXT_LISTEN_MSG "Failed to listen on the socket"

#define TLS_CONTEXT_CREATE_CTX_ERROR (int8_t)-4
#define TLS_CONTEXT_CREATE_CTX_MSG "Failed to create tls_context"

void handle_tls_bootstrap_error(int8_t tls_bootstrap_error_code);

#endif // TLS_ERROR_H