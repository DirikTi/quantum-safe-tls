#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <errno.h>
#include <sys/epoll.h>
#include <string.h>
#include "logging.h"
#include "../tls_auth/tls_ipv4.h"
#include "tls.h"

typedef struct {
    SSL *ssl;
    int client_fd;
} ClientEpollData;

#define MAX_EVENTS 100
#define MAX_PAYLOAD_SIZE 1024

static void handle_new_connection(TLS_CTX *tls_ctx)
{
    struct sockaddr_in client_addr;
    socklen_t client_size = sizeof(client_addr);

    int client_fd = accept(tls_ctx->server_fd, (struct sockaddr *)&client_addr, &client_size);
    if (client_fd < 0) {
        printf_error("Not Accepted Client Connection");
        return;
    }

    getpeername(client_fd, (struct sockaddr *)&client_addr, &client_size);
    uint8_t ip_bytes[4];

    memcpy(ip_bytes, &client_addr.sin_addr.s_addr, 4);
    if (is_ip_in_list(ip_bytes) < 0) {
        close(client_fd);
        return;
    }

    SSL *ssl = SSL_new(tls_ctx->ssl_context);
    if (!ssl) {
        close(client_fd);
        return;
    }
    
    SSL_set_fd(ssl, client_fd);

    int ret = SSL_accept(ssl);
    if (ret <= 0) {
        int ssl_error = SSL_get_error(ssl, ret);
        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) return;
        fprintf(stderr, "SSL accept failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(client_fd);
        return;
    }

    set_nonblocking(client_fd);

    ClientEpollData *client_epoll_data = malloc(sizeof(ClientEpollData));

    if (!client_epoll_data) {
        /* Memory Allocation Failed */
        SSL_free(ssl);
        close(client_fd);
        return;
    }

    client_epoll_data->client_fd = client_fd;
    client_epoll_data->ssl = ssl;

    struct epoll_event event = {0};
    event.events = EPOLLIN | EPOLLET;
    event.data.ptr = client_epoll_data;

    if (epoll_ctl(tls_ctx->epoll_fd, EPOLL_CTL_ADD, client_fd, &event) < 0) {
        /* Epoll add client failed */
        handle_log_critical_error("Epoll add client failed", "Module:tls Method:handle_new_connection", NULL, NULL);
        SSL_free(ssl);
        close(client_fd);
    }
}

static uint8_t handle_client_data(ClientEpollData *client_epoll_data)
{
    char buffer[MAX_PAYLOAD_SIZE] = {0};
    int bytes_read = SSL_read(client_epoll_data->ssl, buffer, sizeof(buffer) - 1);

    if (bytes_read <= 0) {
        int err = SSL_get_error(client_epoll_data->ssl, bytes_read);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            return 1;
        }
        
        SSL_shutdown(client_epoll_data->ssl);
        SSL_free(client_epoll_data->ssl);
        close(client_epoll_data->client_fd);
        free(client_epoll_data);

        return 0;
    }

    // REMOVED METHOD
    // process_data(client_epoll_data->ssl, buffer);
    return 1;
}

int run_server(TLS_CTX *tls_ctx)
{
    load_ip_v4_list();

    set_nonblocking(tls_ctx->server_fd);

    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        handle_log_critical_error("Failed to create epoll instance", "Module:tls Method:run_server", NULL, NULL);
    }

    struct epoll_event event = {0};
    event.events = EPOLLIN | EPOLLET;
    event.data.fd = tls_ctx->server_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, tls_ctx->server_fd, &event) < 0) {
        handle_log_critical_error("Epoll add server socket failed", "Module:tls Method:run_server", NULL, NULL);
    }

    tls_ctx->epoll_fd = epoll_fd;

    struct epoll_event events[MAX_EVENTS];
    
    while (1) {
        int event_count = epoll_wait(tls_ctx->epoll_fd, events, MAX_EVENTS, tls_ctx->connection_timeout);

        if (event_count == 0) {
            /* Epoll timeout reached, no events detected */
            continue;
        }

        for (int i = 0; i < event_count; i++) {
            if (events[i].data.fd == tls_ctx->server_fd) {
                handle_new_connection(tls_ctx);
            } else {
                ClientEpollData *client_epoll_data = (ClientEpollData *)events[i].data.ptr;
                if (!client_epoll_data) {
                    /* Epoll timeout reached, no events detected */
                    continue;
                }

                if (handle_client_data(client_epoll_data) == 0) {
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_epoll_data->client_fd, NULL);
                }
            }
        }
    }

    close(tls_ctx->server_fd);
    cleanup_TLS(tls_ctx);
}
