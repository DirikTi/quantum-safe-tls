#ifndef LOGGER_H_
#define LOGGER_H_

#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include "utils.h"

#define LOG_COMMANDS_FILE "log/command_log.txt"
#define LOG_ERRORS_FILE "log/error_log.txt"
#define LOG_CRITICAL_FILE "log/critical_log.txt"
#define LOG_AUTH_FILE "log/auth_log.txt"

#define MAX_BATCH_SIZE 3000
#define BATCH_SIZE 2000
#define LOG_FLUSH_INTERVAL 5
#define LOG_QUEUE_SIZE 1000

#define LOG_AUTH (1U << 5)
#define LOG_CRITICAL_ERROR (1U << 4)
#define LOG_COMMAND_BATCH (1U << 3)
#define LOG_ERROR (1U << 2)
#define LOG_WARNING (1U << 1)
#define LOG_COMMAND (1U)

typedef struct {
    uint8_t log_type;
    char message[
        50 + LOG_MESSAGE_STR_LEN + LOG_SOURCE_STR_LEN + USERNAME_STR_MAX_LEN
        + IP_STR_MAX_LEN + 20];     /* Log Message */
    FILE *log_file;                 // Which Log FILE
} Log_Entry;

void initialize_logger(uint8_t config_log);

void set_error_log(uint32_t new_error_log, uint32_t new_warning_log);
void set_log_command(uint32_t new_command_log);
void set_log_batch_command(uint32_t new_batch_command_log);

void handle_log_command(const char *command_message, const char *source, const char *username, const char *ip_address);
void handle_log_error(const char *error_message, const char *source, const char *username, const char *ip_address);
void handle_log_warning(const char *warning_message, const char *source, const char *username, const char *ip_address);
void handle_log_critical_error(const char *error_message, const char *source, const char *username, const char *ip_address);
void handle_log_auth_log(const char *auth_message, const char *source, const char *username, const char *ip_address);

char *create_message_format(
    const char message[LOG_MESSAGE_STR_LEN], 
    const char source[LOG_SOURCE_STR_LEN], 
    const char username[USERNAME_STR_MAX_LEN], 
    const char ip_address[IP_STR_MAX_LEN]
);

static void *log_worker(void *arg) __attribute__((unused));
void log_command_entry();
// static void enqueue_log(FILE *log_file, const char *prefix, const char *message);

void shutdown_logger();

#endif