#ifndef CONFIG_BOOTSTRAP_H_
#define CONFIG_BOOTSTRAP_H_

#include <stdint.h>
#include <stdbool.h>
#include <config.h>

#define CONFIG_FILE_PATH "./config.ini"

/* Maximum allowed connections to the server */
#define CONFIG_FILE_MAX_CONNECTION "Maximum number of simultaneous connections allowed by the server."
#define DEFAULT_MAX_CONNECTION 100
#define CONFIG_KEY_MAX_CONNECTIONS "max_connections"

/* Maximum priority connections */
#define CONFIG_FILE_MAX_PRIORITY_CONNECTION "Maximum number of priority connections allowed."
#define DEFAULT_MAX_PRIORTY_CONNECTION  10
#define CONFIG_KEY_MAX_PRIORITY_CONNECTIONS "max_priorty_connections"

/* TLS Connection timeout */
#define CONFIG_FILE_CONNECTION_TIMEOUT "TLS Connection timeout."
#define DEFUALT_CONNECTION_TIMEOUT 3000
#define CONFIG_KEY_CONNECTION_TIMEOUT "connection_timeout"

/* Server listening port */
#define CONFIG_FILE_PORT "Port number on which the server listens for incoming connections."
#define DEFAULT_PORT 4380
#define CONFIG_KEY_PORT "port"

/* HTTP/2 support */
#define CONFIG_FILE_HTTP_2_ENABLE "Enable or disable HTTP/2 support (true/false)."
#define DEFAULT_HTTP_2_ENABLE false
#define CONFIG_KEY_HTTP_2_ENABLE  "http2_enable"

/* Session resumption */
#define CONFIG_FILE_SSL_SESSION_RES_ENABLE "Enable or disable TLS session resumption (true/false)."
#define DEFAULT_SSL_SESSION_RES_ENABLE false
#define CONFIG_KEY_SSL_SESSION_RES_ENABLE "ssl_session_resumption_enable"

/* OpenSSL session cache enable */
#define CONFIG_FILE_SSL_SESSION_CACHE_ENABLE "Enable or disable OpenSSL session cache (true/false)."
#define DEFAULT_SSL_SESSION_CACHE_ENABLE false
#define CONFIG_KEY_SSL_SESSION_CACHE_ENABLE "enable_openssl_cache"

/* OpenSSL session cache size */
#define CONFIG_FILE_SSL_SESSION_CACHE_SIZE "Define the OpenSSL session cache size."
#define DEFAULT_SSL_SESSION_CACHE_SIZE 1024U
#define CONFIG_KEY_SSL_SESSION_CACHE_SIZE "ssl_session_cache_size"

/* OpenSSL session cache timeout */
#define CONFIG_FILE_SSL_SESSION_CACHE_TIMEOUT "Define the OpenSSL session cache timeout (seconds)."
#define DEFAULT_SSL_SESSION_CACHE_TIMEOUT 300U
#define CONFIG_KEY_SSL_SESSION_CACHE_TIMEOUT "ssl_session_cache_timeout"


/* OCSP stapling */
#define CONFIG_FILE_OCSP_STAPLING_ENABLE "Enable or disable OCSP stapling (true/false)."
#define DEFAULT_OCSP_STAPLING_ENABLE false
#define CONFIG_KEY_OCSP_STAPLING_ENABLE "ocsp_stapling_enable"

/* Keepalive */
#define CONFIG_FILE_KEEPALIVE_ENABLE "Enable or disable TCP keepalive (true/false)."
#define DEFAULT_KEEPALIVE_ENABLE true
#define CONFIG_KEY_KEEPALIVE_ENABLE "keepalive_enable"

#define CONFIG_FILE_KEEPALIVE_IDLE "Time (in seconds) before the first keepalive probe is sent."
#define DEFAULT_KEEPALIVE_IDLE 60
#define CONFIG_KEY_KEEPALIVE_IDLE "keepalive_idle"

#define CONFIG_FILE_KEEPALIVE_INTERVAL "Interval (in seconds) between successive keepalive probes."
#define DEFAULT_KEEPALIVE_INTERVAL 30
#define CONFIG_KEY_KEEPALIVE_INTERVAL "keepalive_interval"

#define CONFIG_FILE_KEEPALIVE_COUNT "Number of keepalive probes before considering connection dead."
#define DEFAULT_KEEPALIVE_COUNT 5
#define CONFIG_KEY_KEEPALIVE_COUNT "keepalive_count"

/* Maximum handshake attempts */
#define CONFIG_FILE_MAX_HANDSHAKE_ATTEMPTS "Maximum number of handshake attempts before connection is dropped."
#define DEFAULT_MAX_HANDSHAKE_ATTEMPTS 50U
#define CONFIG_KEY_MAX_HANDSHAKE_ATTEMPTS "max_handshake_attempts"

/* Handshake timeout */
#define CONFIG_FILE_HANDSHAKE_TIMEOUT "Timeout (in milliseconds) for a TLS handshake attempt."
#define DEFAULT_HANDSHAKE_TIMEOUT 1000U
#define CONFIG_KEY_HANDSHAKE_TIMEOUT "handshake_timeout"

/* Logging Levels */
#define CONFIG_FILE_LOG_COMMAND "Log command execution (1: enabled, 0: disabled)."
#define LOG_COMMAND (1U)
#define CONFIG_KEY_LOG_COMMAND "log_command"

#define CONFIG_FILE_LOG_WARNING "Log warnings (1: enabled, 0: disabled)."
#define LOG_WARNING (1U << 1)
#define CONFIG_KEY_LOG_WARNING "log_warning"

#define CONFIG_FILE_LOG_ERROR "Log errors (1: enabled, 0: disabled)."
#define LOG_ERROR (1U << 2)
#define CONFIG_KEY_LOG_ERROR "log_error"

#define CONFIG_FILE_LOG_COMMAND_BATCH "Log batch command executions (1: enabled, 0: disabled)."
#define LOG_COMMAND_BATCH (1U << 3)
#define CONFIG_KEY_LOG_COMMAND_BATCH "log_command_batch"

#define CONFIG_FILE_LOG_CRITICAL_ERROR "Log critical errors (1: enabled, 0: disabled)."
#define LOG_CRITICAL_ERROR (1U << 4)
#define CONFIG_KEY_LOG_CRITICAL_ERROR "log_critical_error"

#define CONFIG_FILE_LOG_AUTH "Log authentication attempts (1: enabled, 0: disabled)."
#define LOG_AUTH (1U << 5)

/* Default log settings */
#define CONFIG_FILE_DEFAULT_LOGS "Default logging level (bitwise OR of enabled log types)."
#define DEFAULT_LOGS (LOG_COMMAND | LOG_ERROR | LOG_WARNING | LOG_COMMAND_BATCH)

/* Function Declarations */
void read_config_file(Config *config);

#endif // CONFIG_BOOTSTRAP_H