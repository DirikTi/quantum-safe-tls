#include <stdio.h>
#include <stdlib.h>
#include "tls_error.h"

void handle_tls_bootstrap_error(int8_t tls_bootstrap_error_code)
{
    const char *error_msg = "Unknown TLS bootstrap error";

    switch (tls_bootstrap_error_code) {
        case TLS_CONTEXT_CREATE_SOCKET_ERROR:
            error_msg = TLS_CONTEXT_CREATE_SOCKET_MSG;
            break;
        case TLS_CONTEXT_BIND_ERROR:
            error_msg = TLS_CONTEXT_BIND_MSG;
            break;
        case TLS_CONTEXT_LISTEN_ERROR:
            error_msg = TLS_CONTEXT_LISTEN_MSG;
            break;
        case TLS_CONTEXT_CREATE_CTX_ERROR:
            error_msg = TLS_CONTEXT_CREATE_CTX_MSG;
            break;
    }

    fprintf(stderr, "TLS Bootstrap Error: %s\n", error_msg);
    exit(EXIT_FAILURE);
}
