#include <stdint.h> 
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include "config.h"
#include "utils.h"
#include "tls_error.h"
#include "tls.h"

static void get_server_fd(TLS_CTX *tls_ctx)
{
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        handle_tls_bootstrap_error(TLS_CONTEXT_CREATE_SOCKET_ERROR);
    }

    tls_ctx->server_fd = server_fd;
}

static void set_reuseaddr(int server_fd)
{
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
}

static void set_timeout(int server_fd, int send_timeout_usec, int receive_timeout_usec)
{
    struct timeval send_timeval;
    send_timeval.tv_sec = send_timeout_usec / 1000;
    send_timeval.tv_usec = (send_timeout_usec % 1000) * 1000;

    struct timeval receive_timeval;
    receive_timeval.tv_sec = receive_timeout_usec / 1000;
    receive_timeval.tv_usec = (receive_timeout_usec % 1000) * 1000;

    setsockopt(server_fd, SOL_SOCKET, SO_SNDTIMEO, &send_timeval, sizeof(send_timeval));
    setsockopt(server_fd, SOL_SOCKET, SO_RCVTIMEO, &receive_timeval, sizeof(receive_timeval));
}

static void set_socket_keepalive_config(int server_fd, int keepalive, int keepidle, int keepintvl, int keepcnt)
{
    setsockopt(server_fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));

    if (keepalive == 1) {
        setsockopt(server_fd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
        setsockopt(server_fd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));
        setsockopt(server_fd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt));
    }
}

int set_nonblocking(int socketfd)
{
    int flags = fcntl(socketfd, F_GETFL, 0);

    return fcntl(socketfd, F_SETFL, flags | O_NONBLOCK);
}

void get_new_tls_context(TLS_CTX *tls_ctx, SSL_CTX *ssl_ctx, Config *config)
{
    if (tls_ctx == NULL) {
        handle_tls_bootstrap_error(TLS_CONTEXT_CREATE_CTX_ERROR);
    }

    tls_ctx->ssl_context = ssl_ctx;

    tls_ctx->connection_timeout = config->connection_timeout;
    tls_ctx->max_connections = config->max_connections;
    tls_ctx->max_handshake_attempts = config->max_handshake_attempts;
    tls_ctx->session_resumption_enable = config->ssl_session_resumption_enable;
    tls_ctx->ocsp_stapling_enable = config->ocsp_stapling_enable;

    get_server_fd(tls_ctx);
    set_reuseaddr(tls_ctx->server_fd);

    set_timeout(
        tls_ctx->server_fd, 
        config->send_timeout, 
        config->receive_timeout
    );

    if (config->keepalive_enable) {
        set_socket_keepalive_config(
            tls_ctx->server_fd,
            1, 
            config->keepalive_idle, 
            config->keepalive_interval, 
            config->keepalive_count
        );
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(config->port);

    /* Socket Bind */
    if (bind(tls_ctx->server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(tls_ctx->server_fd);
        handle_tls_bootstrap_error(TLS_CONTEXT_BIND_ERROR);
    }

    /* Socket Listen */
    if (listen(tls_ctx->server_fd, SOMAXCONN) < 0) {
        close(tls_ctx->server_fd);
        handle_tls_bootstrap_error(TLS_CONTEXT_LISTEN_ERROR);
    }
}
