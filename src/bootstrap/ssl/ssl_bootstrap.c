#include <openssl/ssl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include "config.h"
#include "tls.h"
#include "ssl_error.h"
#include "oqs/oqs.h"

#define CERT_FILE_PATH "./certs/server_cert.pem"
#define KEY_FILE_PATH "./certs/server_key.pem"

#define CIPHER_LIST "TLS_AES_256_GCM_SHA384"
#define KEM_LIST "kyber768"

static SSL_CTX *create_ssl_context(void)
{
    const SSL_METHOD *ssl_method = TLS_server_method();
    SSL_CTX *ssl_ctx = SSL_CTX_new(ssl_method);

    if (!ssl_ctx) {
        handle_ssl_ctx_error(SSL_CREATE_CTX_ERROR);
        return NULL;
    }

    return ssl_ctx;
}

static int8_t set_ssl_files(SSL_CTX *ssl_ctx)
{
    if (SSL_CTX_use_certificate_file(ssl_ctx, CERT_FILE_PATH, SSL_FILETYPE_PEM) <= 0)
        return SSL_INVALID_CERTS_ERROR;
    
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, KEY_FILE_PATH, SSL_FILETYPE_PEM) <= 0)
        return SSL_INVALID_PRIVATE_ERROR;

    return SSL_CTX_check_private_key(ssl_ctx) ? 1 : SSL_CHECK_PRIVATE_ERROR;
}

static void set_session_config(SSL_CTX *ssl_ctx, Config *config)
{
    /* Session Cache Config */
    if (config->ssl_session_cache_enable) {
        SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_SERVER);
        SSL_CTX_sess_set_cache_size(ssl_ctx, config->ssl_session_cache_size);
        SSL_CTX_set_timeout(ssl_ctx, config->ssl_session_cache_timeout);
        
    } else {
        SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_OFF);
    }

    /* Session Resumption (TLS Ticket) Config */
    if (config->ssl_session_resumption_enable && !config->ssl_session_cache_enable) {
        SSL_CTX_clear_options(ssl_ctx, SSL_OP_NO_TICKET);
        printf("Entered Has Ticket");
    } else {
        /* Session off resumption */
        printf("Entered NO TICKET");
        SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_TICKET);
    }
}

static int configure_ssl_ctx(SSL_CTX *ssl_ctx)
{
    int8_t ret;

    ret = SSL_CTX_set_ecdh_auto(ssl_ctx, 1);
    if (ret == 0) {
        return SSL_PROTOCOL_ERROR; 
    }

    ret = set_ssl_files(ssl_ctx);
    if (ret < 0) {
        return ret;
    }

    ret = SSL_CTX_set1_groups_list(ssl_ctx, KEM_LIST);
    if (ret == 0) {
        return SSL_KEM_ERROR;
    }

    ret = SSL_CTX_set_ciphersuites(ssl_ctx, CIPHER_LIST);
    if (ret == 0) {
         return SSL_CIPHER_ERROR;
    }

    return (int8_t)1;
}

SSL_CTX *initialize_ssl_ctx(Config *config)
{
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    if (access(CERT_FILE_PATH, F_OK) != 0) handle_ssl_ctx_error(SSL_MISSING_CERT_ERROR);
    if (access(KEY_FILE_PATH, F_OK) != 0) handle_ssl_ctx_error(SSL_MISSING_KEY_ERROR);

    SSL_CTX *ssl_ctx = create_ssl_context();
    if (!ssl_ctx) {
        return NULL;
    }

    int8_t ret = configure_ssl_ctx(ssl_ctx);
    if (ret < 0) {
        SSL_CTX_free(ssl_ctx);
        handle_ssl_ctx_error(ret);
        return NULL;
    }

    set_session_config(ssl_ctx, config);

    return ssl_ctx;
}
