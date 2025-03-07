#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tls.h>
#include <fcntl.h>

void cleanup_TLS(TLS_CTX *tls_ctx)
{
    free(tls_ctx->ssl_context);
    free(tls_ctx);
}

inline int set_nonblocking(int socketfd)
{
    int flags = fcntl(socketfd, F_GETFL, 0);

    return fcntl(socketfd, F_SETFL, flags | O_NONBLOCK);
}