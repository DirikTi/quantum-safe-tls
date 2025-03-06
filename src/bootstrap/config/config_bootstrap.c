#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include<unistd.h>
#include "config_bootstrap.h"
#include "config_convert.h"
#include "utils.h"

void process_config(Config *config, const char *key, const char *value)
{
    if (strcmp(key, CONFIG_KEY_MAX_CONNECTIONS) == 0) {
        convert_to_int(value, key, &config->max_connections);
    }
    else if (strcmp(key, CONFIG_KEY_MAX_PRIORITY_CONNECTIONS) == 0) {
        convert_to_int(value, key, &config->max_priorty_connections);
    }
    else if (strcmp(key, CONFIG_KEY_PORT) == 0) {
        convert_to_int(value, key, &config->port);
    }
    else if (strcmp(key, CONFIG_KEY_SSL_SESSION_CACHE_ENABLE) == 0) {
        convert_to_bool(value, key, &config->ssl_session_cache_enable);
    }
    else if (strcmp(key, CONFIG_KEY_SSL_SESSION_RES_ENABLE) == 0) {
        convert_to_bool(value, key, &config->ssl_session_resumption_enable);
    }
    else if (strcmp(key, CONFIG_KEY_SSL_SESSION_CACHE_SIZE) == 0) {
        convert_to_uint32(value, key, &config->ssl_session_cache_size);
    }
    else if (strcmp(key, CONFIG_KEY_SSL_SESSION_CACHE_TIMEOUT) == 0) {
        convert_to_uint32(value, key, &config->ssl_session_cache_timeout);
    }
    else if (strcmp(key, CONFIG_KEY_CONNECTION_TIMEOUT) == 0) {
        convert_to_uint32(value, key, &config->connection_timeout);
    }
    else if (strcmp(key, CONFIG_KEY_HANDSHAKE_TIMEOUT) == 0) {
        convert_to_uint32(value, key, &config->handshake_timeout);
    }
    else if (strcmp(key, CONFIG_KEY_MAX_HANDSHAKE_ATTEMPTS) == 0) {
        convert_to_uint32(value, key, &config->max_handshake_attempts);
    }
    else if (strcmp(key, CONFIG_KEY_HTTP_2_ENABLE) == 0) {
        convert_to_bool(value, key, &config->http2_enable);
    }
    else if (strcmp(key, CONFIG_KEY_OCSP_STAPLING_ENABLE) == 0) {
        convert_to_bool(value, key, &config->ocsp_stapling_enable);
    }
    else if (strcmp(key, CONFIG_KEY_KEEPALIVE_ENABLE) == 0) {
        convert_to_bool(value, key, &config->keepalive_enable);
    }
    else if (strcmp(key, CONFIG_KEY_KEEPALIVE_IDLE) == 0) {
        convert_to_uint32(value, key, &config->keepalive_idle);
    }
    else if (strcmp(key, CONFIG_KEY_KEEPALIVE_INTERVAL) == 0) {
        convert_to_uint32(value, key, &config->keepalive_interval);
    }
    else if (strcmp(key, CONFIG_KEY_KEEPALIVE_COUNT) == 0) {
        convert_to_uint32(value, key, &config->keepalive_count);
    }
    else if (strcmp(key, CONFIG_KEY_LOG_COMMAND) == 0) {
        convert_to_logs(value, key, &config->logs);
    }
    else if (strcmp(key, CONFIG_KEY_LOG_WARNING) == 0) {
        convert_to_logs(value, key, &config->logs);
    }
    else if (strcmp(key, CONFIG_KEY_LOG_ERROR) == 0) {
        convert_to_logs(value, key, &config->logs);
    }
    else {
        printf("Warning: Undefined variable '%s' in config\n", key);
    }
}


static void get_config_default_values(Config *config)
{
    /* TLS Config */
    config->max_connections = DEFAULT_MAX_CONNECTION;
    config->port = DEFAULT_PORT;
    config->http2_enable = DEFAULT_HTTP_2_ENABLE;
    config->max_handshake_attempts = DEFAULT_MAX_HANDSHAKE_ATTEMPTS;
    config->handshake_timeout = DEFAULT_HANDSHAKE_TIMEOUT;
    config->connection_timeout = DEFUALT_CONNECTION_TIMEOUT;

    /* TLS Event Config */
    config->max_priorty_connections = DEFAULT_MAX_PRIORTY_CONNECTION;

    config->keepalive_enable = DEFAULT_KEEPALIVE_ENABLE;
    config->keepalive_idle = DEFAULT_KEEPALIVE_IDLE;
    config->keepalive_interval = DEFAULT_KEEPALIVE_INTERVAL;
    config->keepalive_count = DEFAULT_KEEPALIVE_COUNT;

    /* OPENSSL */
    config->ssl_session_resumption_enable = DEFAULT_SSL_SESSION_RES_ENABLE;
    config->ssl_session_cache_enable = DEFAULT_SSL_SESSION_CACHE_ENABLE;
    config->ssl_session_cache_size = DEFAULT_SSL_SESSION_CACHE_SIZE;
    config->ssl_session_cache_timeout = DEFAULT_SSL_SESSION_CACHE_TIMEOUT;
    config->ocsp_stapling_enable = DEFAULT_OCSP_STAPLING_ENABLE;

    /* Logs */
    config->logs = DEFAULT_LOGS;
}

static void write_config_file(Config *config)
{
    FILE *config_file = fopen(CONFIG_FILE_PATH, "w");

    if (config_file == NULL) {
        printf("Error: Could not open the config file for writing.\n");
        return;
    }

    // Config file descriptions und defaults values
    fprintf(config_file, "; %s \n", CONFIG_FILE_MAX_CONNECTION);
    fprintf(config_file, "%s=%d\n\n" ,CONFIG_KEY_MAX_CONNECTIONS ,config->max_connections);
    
    fprintf(config_file, "; %s \n", CONFIG_FILE_MAX_PRIORITY_CONNECTION);
    fprintf(config_file, "%s=%d\n\n" ,CONFIG_KEY_MAX_PRIORITY_CONNECTIONS ,config->max_priorty_connections);
    
    fprintf(config_file, "; %s \n", CONFIG_FILE_CONNECTION_TIMEOUT);
    fprintf(config_file, "%s=%d\n\n", CONFIG_KEY_CONNECTION_TIMEOUT ,config->connection_timeout);
    
    fprintf(config_file, "; %s \n", CONFIG_FILE_PORT);
    fprintf(config_file, "%s=%d\n\n", CONFIG_KEY_PORT, config->port);
    
    fprintf(config_file, "; %s \n", CONFIG_FILE_SSL_SESSION_RES_ENABLE);
    fprintf(config_file, "%s=%s\n\n", CONFIG_KEY_SSL_SESSION_RES_ENABLE, convert_to_string_from_bool(config->ssl_session_resumption_enable));
    
    fprintf(config_file, "; %s \n", CONFIG_FILE_SSL_SESSION_CACHE_ENABLE);
    fprintf(config_file, "%s=%s\n\n", CONFIG_KEY_SSL_SESSION_CACHE_ENABLE, convert_to_string_from_bool(config->ssl_session_cache_enable));

    fprintf(config_file, "; %s \n", CONFIG_FILE_SSL_SESSION_CACHE_SIZE);
    fprintf(config_file, "%s=%d\n\n", CONFIG_KEY_SSL_SESSION_CACHE_SIZE, config->ssl_session_cache_size);

    fprintf(config_file, "; %s \n", CONFIG_FILE_SSL_SESSION_CACHE_TIMEOUT);
    fprintf(config_file, "%s=%d\n\n", CONFIG_KEY_SSL_SESSION_CACHE_TIMEOUT, config->ssl_session_cache_timeout);
    
    fprintf(config_file, "; %s \n", CONFIG_FILE_HTTP_2_ENABLE);
    fprintf(config_file, "%s=%s\n\n", CONFIG_KEY_HTTP_2_ENABLE, convert_to_string_from_bool(config->http2_enable));
    
    fprintf(config_file, "; %s \n", CONFIG_FILE_OCSP_STAPLING_ENABLE);
    fprintf(config_file, "%s=%s\n\n", CONFIG_KEY_OCSP_STAPLING_ENABLE, convert_to_string_from_bool(config->ocsp_stapling_enable));

    fprintf(config_file, "; %s\n", CONFIG_FILE_KEEPALIVE_ENABLE);
    fprintf(config_file, "%s=%s\n\n", CONFIG_KEY_KEEPALIVE_ENABLE, convert_to_string_from_bool(config->keepalive_enable));

    fprintf(config_file, "; %s\n", CONFIG_FILE_KEEPALIVE_IDLE);
    fprintf(config_file, "%s=%d\n\n", CONFIG_KEY_KEEPALIVE_IDLE, config->keepalive_idle);

    fprintf(config_file, "; %s\n", CONFIG_FILE_KEEPALIVE_INTERVAL);
    fprintf(config_file, "%s=%d\n\n", CONFIG_KEY_KEEPALIVE_INTERVAL, config->keepalive_interval);

    fprintf(config_file, "; %s\n", CONFIG_FILE_KEEPALIVE_COUNT);
    fprintf(config_file, "%s=%d\n\n", CONFIG_KEY_KEEPALIVE_COUNT, config->keepalive_count);
    
    fprintf(config_file, "; %s \n", CONFIG_FILE_MAX_HANDSHAKE_ATTEMPTS);
    fprintf(config_file, "%s=%u\n\n", CONFIG_KEY_MAX_HANDSHAKE_ATTEMPTS, config->max_handshake_attempts);
    
    fprintf(config_file, "; %s \n", CONFIG_FILE_HANDSHAKE_TIMEOUT);
    fprintf(config_file, "%s=%u\n\n", CONFIG_KEY_HANDSHAKE_TIMEOUT, config->handshake_timeout);
    
    // Logging Levels
    fprintf(config_file, "; %s \n", CONFIG_FILE_LOG_COMMAND);
    fprintf(config_file, "%s=%d\n\n", CONFIG_KEY_LOG_COMMAND, (config->logs & LOG_COMMAND) ? 1 : 0);
    
    fprintf(config_file, "; %s \n", CONFIG_FILE_LOG_WARNING);
    fprintf(config_file, "%s=%d\n\n", CONFIG_KEY_LOG_WARNING, (config->logs & LOG_WARNING) ? 1 : 0);
    
    fprintf(config_file, "; %s \n", CONFIG_FILE_LOG_ERROR);
    fprintf(config_file, "%s=%d\n\n", CONFIG_KEY_LOG_ERROR, (config->logs & LOG_ERROR) ? 1 : 0);

    fclose(config_file);
}

void read_config_file(Config *config)
{
    get_config_default_values(config);

    FILE *config_file = fopen(CONFIG_FILE_PATH, "r");
    if (config_file == NULL) {
        write_config_file(config);
        return;
    }

    char line[256];
    char key[50];
    char value[50];

    while (fgets(line, sizeof(line), config_file) != NULL) {
        if (line[0] == ';' || line[0] == '\n') continue;

        if (sscanf(line, " %49[^=]=%49s", key, value) == 2) {
            trim(key);
            trim(value);

            process_config(config, key, value);
        }
    }

    fclose(config_file);

}