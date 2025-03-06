#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include "logging.h"
#include "tls.h"

typedef struct {
        SSL *ssl;
        int client_fd;
} ClientEpollData;

void cleanup_TLS(TLS_CTX *tls_ctx) {
    close(tls_ctx->server_fd);
    free(tls_ctx);   
}

#define MAX_EVENTS 100

int set_nonblocking(int socketfd)
{
    int flags = fcntl(socketfd, F_GETFL, 0);

    return fcntl(socketfd, F_SETFL, flags | O_NONBLOCK);
}

static void handle_new_connection(TLS_CTX *tls_ctx, int epoll_fd)
{
    struct sockaddr_in client_addr;
    socklen_t client_size = sizeof(client_addr);

    int client_fd = accept(tls_ctx->server_fd, (struct sockaddr *)&client_addr, &client_size);
    if (client_fd < 0) {
        printf_error("Not Accepted Client Connection");
        return;
    }

    SSL *ssl = SSL_new(tls_ctx->ssl_context);
    if (!ssl) {
        fprintf(stderr, "ERROR: Failed to create SSL structure\n");
        close(client_fd);
        return;
    }
    
    SSL_set_fd(ssl, client_fd);

    int ret = SSL_accept(ssl);
    if (ret <= 0) {
        int ssl_error = SSL_get_error(ssl, ret);
        /* The connection need more time */
        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
            return;       
        
        fprintf(stderr, "SSL accept failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(client_fd);
        return;
    }

    // set_nonblocking(client_fd);
}

int run_server(TLS_CTX *tls_ctx)
{
    set_nonblocking(tls_ctx->server_fd);

    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        handle_log_critical_error("Failed to create epoll instance", "Module:tls Method:run_server", NULL, NULL);
        // handle_tls_error("Failed to create epoll instance");
    }

    struct epoll_event event = {0};
    event.events = EPOLLIN | EPOLLET;
    event.data.fd = tls_ctx->server_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, tls_ctx->server_fd, &event) < 0) {
        handle_log_critical_error("Epoll add server socket failed", "Module:tls Method:run_server", NULL, NULL);
        // handle_tls_error("Epoll add server socket failed");
    }

    struct epoll_event events[MAX_EVENTS];

    while (1) {
        int event_count = epoll_wait(epoll_fd, events, MAX_EVENTS, tls_ctx->connection_timeout);

        if (event_count == 0) {
            /* Epoll timeout reached, no events detected */
            continue;
        }

        for (int i = 0; i < event_count; i++) {
            if (events[i].data.fd == tls_ctx->server_fd) {
                handle_new_connection(tls_ctx, epoll_fd);
            } else {
                ClientEpollData *client_epoll_data = (ClientEpollData *)events[i].data.ptr;
                if (!client_epoll_data) {
                    /* Epoll timeout reached, no events detected */
                    continue;
                }
                /*
                uint8_t result_client = handle_client_data(client_epoll_data);

                if (result_client == FALSE) {
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_epoll_data->client_fd, NULL);
                }
                */
            }
        }
    }

    cleanup_TLS(tls_ctx);
}
