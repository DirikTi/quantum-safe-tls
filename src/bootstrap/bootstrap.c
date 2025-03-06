#include <dlfcn.h>
#include <openssl/ssl.h>
#include "utils.h"
#include "config.h"
#include "logging.h"
#include "tls.h"
#include "ssl/ssl_bootstrap.h"

#define DL_SSL_CTX_PATH "./lib/libssl_ctx.so"
#define DL_CONFIG_PATH "./lib/libconfig.so"
#define DL_TLS_CTX_PATH "./lib/libtls_ctx.so"

static Config *boostrap_config()
{
    Config *config = (Config*)malloc(sizeof(Config));

    void *handle = dlopen(DL_CONFIG_PATH, RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "libconfig.so dlopen error: %s\n", dlerror());
        exit(EXIT_FAILURE);
    }
    
    void (*read_config_file)(Config *);
    read_config_file = (void (*)(Config *))dlsym(handle, "read_config_file");
    if (!read_config_file) {
        fprintf(stderr, "libconfig dlsym error: %s\n", dlerror());
        exit(EXIT_FAILURE);
    }
    
    read_config_file(config);

    if (dlclose(handle) != 0)
        fprintf(stderr, "dlclose error: %s\n", dlerror());

    return config;
}

static TLS_CTX *bootstrap_tls(SSL_CTX *ssl_ctx, Config *config)
{
    void *handle = dlopen(DL_TLS_CTX_PATH, RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "libtls_ctx dlopen error: %s\n", dlerror());
        exit(EXIT_FAILURE);
    }

    void(*get_new_tls_context)(TLS_CTX *, SSL_CTX *, Config *);
    *(void **)(&get_new_tls_context) = dlsym(handle, "get_new_tls_context");
    if (!get_new_tls_context) {
        fprintf(stderr, "dlsym error: %s\n", dlerror());
        exit(EXIT_FAILURE);
    }
    
    TLS_CTX *tls_ctx = (TLS_CTX*)malloc(sizeof(TLS_CTX));
    if (!tls_ctx) {
        fprintf(stderr, "malloc failed for TLS_CTX\n");
        exit(EXIT_FAILURE);
    }

    get_new_tls_context(tls_ctx, ssl_ctx, config);

    
    if (dlclose(handle) != 0)
        fprintf(stderr, "dlclose error: %s\n", dlerror());
    
    return tls_ctx;
}

static void cleanup_bootsrapt(Config *config)
{
    free(config);
}

TLS_CTX *bootstrap()
{
    Config *config = boostrap_config();
    
    initialize_logger(config->logs);
    printf_info("Bootstraping... SSL");
    
    SSL_CTX *ssl_ctx = initialize_ssl_ctx(config);

    TLS_CTX *tls_ctx = bootstrap_tls(ssl_ctx, config);

    cleanup_bootsrapt(config);
    return tls_ctx;
}