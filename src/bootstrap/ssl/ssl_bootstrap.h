#ifndef SSL_BOOTSTRAP_H_
#define SSL_BOOTSTRAP_H_

#include <openssl/ssl.h>
#include "config.h"

SSL_CTX *initialize_ssl_ctx(Config *config);

#endif // SSL_BOOTSTRAP_H