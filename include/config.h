#ifndef CONFIG_H_
#define CONFIG_H_

#include <stdbool.h>
#include <stdlib.h>

typedef struct {
    int max_connections;
    int max_priorty_connections;
    int port;

    uint32_t connection_timeout;
    uint32_t handshake_timeout;

    uint32_t max_handshake_attempts;
    
    bool keepalive_enable;
    uint32_t keepalive_idle;     // TCP_KEEPIDLE
    uint32_t keepalive_interval; // TCP_KEEPINTVL
    uint32_t keepalive_count;    // TCP_KEEPCNT

    uint32_t send_timeout;
    uint32_t receive_timeout;
    
    bool ssl_session_resumption_enable;
    bool ssl_session_cache_enable;
    uint32_t ssl_session_cache_size;
    uint32_t ssl_session_cache_timeout;
    bool ocsp_stapling_enable;

    bool http2_enable;

    // bool enable_hardware_acceleration; // SIMD/AVX2/NEON 
    // bool enable_aes_ni;
    
    /* REVERSED | REVERSED | REVERSED | REVERSED | LOG_COMMAND_BATCH | LOG_ERROR | LOG_WARNING | LOG_INFO */
    uint8_t logs;
} Config;

#endif
