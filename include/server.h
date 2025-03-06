#ifndef SERVER_H_
#define SERVER_H_

#include "utils.h"
#include <openssl/ssl.h>

#define MAX_EVENTS 10
#define MAX_PAYLOAD_SIZE 2048
#define LOGIN_BUFFER_SIZE (USERNAME_STR_MAX_LEN + PASSWORD_STR_MAX_LEN + 1)
#define TOKEN_SIZE 32
#define COMMAND_BUFFER_SIZE 2100

/* Payload Types */
#define LOGIN_PAYLOAD_TYPE 'L'
#define COMMAND_PAYLOAD_TYPE 'S'

typedef struct {
        char username[USERNAME_STR_MAX_LEN];
        char password[PASSWORD_STR_MAX_LEN];
} LoginPayload;

void initialize_tls(int port, uint32_t connection_timeout, int max_connections);
void run_server(int port, uint32_t connection_timeout);

#endif // SERVER_H_