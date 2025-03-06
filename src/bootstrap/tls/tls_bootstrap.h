#ifndef TLS_BOOTSTRAP_H_
#define TLS_BOOTSTRAP_H_

#include <openssl/ssl.h>
#include "tls.h"

void get_new_tls_context(TLS_CTX *tls_ctx ,SSL_CTX *ssl_ctx, Config *config);

#endif // TLS_BOOTSTRAP_H