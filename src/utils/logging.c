#include "logging.h"
#include "stdlib.h"
#include "config.h"
#include "utils.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>

static uint8_t command_log;
static uint8_t error_log;
static uint8_t warning_log;
static uint8_t batch_command_log;

static FILE *restrict command_log_file = NULL;
static FILE *restrict error_log_file = NULL;
static FILE *restrict critical_log_file = NULL;
static FILE *restrict auth_log_file = NULL;

static char *log_batch[MAX_BATCH_SIZE];
static int log_batch_count = 0;

static time_t last_batch_time = 0;
static const int BATCH_TIME_LIMIT = 5;

static Log_Entry log_queue[LOG_QUEUE_SIZE];
static atomic_int log_queue_head = 0;
static atomic_int log_queue_tail = 0;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t log_cond = PTHREAD_COND_INITIALIZER;
static pthread_t log_thread;
static atomic_bool log_thread_running = true;

const uint16_t buffer_message_size = 50 + LOG_MESSAGE_STR_LEN + LOG_SOURCE_STR_LEN + USERNAME_STR_MAX_LEN + IP_STR_MAX_LEN + 20;

static void create_log_folder()
{
    int check = mkdir("log", (int)0777);

    if (check == -1 && errno != EEXIST) {
        perror("mkdir hata verdi");
    }
}

/* Intilization Start */
void initialize_logger(uint8_t config_log) {
    println("Intilization Logger Module");
    
    create_log_folder();
    
    set_error_log(LOG_ERROR & config_log ,LOG_WARNING & config_log);
    set_log_command(LOG_COMMAND & config_log);
    set_log_batch_command(LOG_COMMAND_BATCH & config_log);

    critical_log_file = fopen(LOG_CRITICAL_FILE, "a");
    if (!critical_log_file) {
        printf_error("Critical Error log file could not be found: %s", LOG_CRITICAL_FILE);
    } else {
        printf_info("Configured critacal error log file");
    }

    auth_log_file = fopen(LOG_AUTH_FILE, "a");
    if (!auth_log_file) {
        printf_error("Auth log file could not be found: %s", LOG_AUTH_FILE);
    } else {
        printf_info("Configured auth log file");
    }

    pthread_create(&log_thread, NULL, log_worker, NULL);
}


void set_error_log(uint32_t new_error_log, uint32_t new_warning_log) {
        error_log = new_error_log;
        warning_log = new_warning_log;

        if ((new_error_log != LOG_ERROR && new_warning_log != LOG_WARNING)) {
            if (error_log_file) fclose(error_log_file);
        } else {
            error_log_file = fopen(LOG_ERRORS_FILE, "a");
            if (!error_log_file) {
                printf_error("Error log file could not be found: %s", LOG_ERRORS_FILE);
                error_log &= 0b0;
                warning_log &= 0b0; 
            } else {
                printf_info("Configured error log file");
            }
        }
}

void set_log_command(uint32_t new_command_log) {
    command_log = new_command_log;

    if (command_log != LOG_COMMAND) {
        if (command_log_file) fclose(command_log_file);
    } else {
        command_log_file = fopen(LOG_COMMANDS_FILE, "a");
        if (!command_log_file) {
            printf_error("Command log file could not be found: %s", LOG_ERRORS_FILE);
            command_log &= 0b0;
        }
    }
}

void set_log_batch_command(uint32_t new_batch_command_log) {
    batch_command_log = new_batch_command_log;
}


/* Log Thread */
static void *log_worker(void *arg) {
    while (log_thread_running == 1) {
        pthread_mutex_lock(&log_mutex);
        
        while (log_queue_head == log_queue_tail && log_thread_running) {
            pthread_cond_wait(&log_cond, &log_mutex);
        }

        if (!log_thread_running) {
            pthread_mutex_unlock(&log_mutex);
            break;
        }

        Log_Entry entry = log_queue[log_queue_tail++ % LOG_QUEUE_SIZE];
        pthread_mutex_unlock(&log_mutex);

        if (entry.log_type == LOG_COMMAND && batch_command_log == LOG_COMMAND_BATCH) {
            if (log_batch_count < MAX_BATCH_SIZE) {
                log_batch[log_batch_count++] = strdup(entry.message);
            }

            if (log_batch_count >= BATCH_SIZE || (difftime(time(NULL), last_batch_time) >= BATCH_TIME_LIMIT)) {
                log_command_entry();
                last_batch_time = time(NULL);
            }
        } else {
            if (entry.log_file) {
                fprintf(entry.log_file, "%s\n", entry.message);
                fflush(entry.log_file);
            }
        }
    }

    (void)arg;
    return NULL;
}

void log_command_entry() {
        char filename[256];
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        snprintf(filename, sizeof(filename), "log/commands/command_logs_%04d-%02d-%02d.bin", 
                t->tm_year + 1900, t->tm_mon + 1, t->tm_mday);

        FILE *log_file = fopen(filename, "ab");
        if (log_file) {
            for (int i = 0; i < log_batch_count; i++) {
                size_t message_len = strlen(log_batch[i]) + 1;
                fwrite(log_batch[i], 1, message_len, log_file);
                free(log_batch[i]);
            }

            log_batch_count = 0;
            fflush(log_file);
            fclose(log_file);
        }
}

static void enqueue_log(FILE *log_file, uint8_t log_type, const char *message) {
    pthread_mutex_lock(&log_mutex);

    unsigned int index = log_queue_head % LOG_QUEUE_SIZE;

    if ((log_queue_head - log_queue_tail + LOG_QUEUE_SIZE) % LOG_QUEUE_SIZE < LOG_QUEUE_SIZE) {
        strncpy(log_queue[index].message, message, buffer_message_size - 1);
        log_queue[index].log_type = log_type;
        log_queue[index].log_file = log_file;
        log_queue_head++;

        pthread_cond_signal(&log_cond);
    }

    pthread_mutex_unlock(&log_mutex);
}

/* To Log files methods */
void handle_log_command(const char *command_message, const char *source, const char *username, const char *ip_address) {
    char *formatted_message = create_message_format(command_message, source, username, ip_address);
    if (formatted_message && command_log && command_log_file) {
        enqueue_log(command_log_file, LOG_COMMAND, formatted_message);
    }
    free(formatted_message);
}

void handle_log_error(const char *error_message, const char *source, const char *username, const char *ip_address) {
    char *formatted_message = create_message_format(error_message, source, username, ip_address);
    if (formatted_message && error_log && error_log_file) {
        enqueue_log(error_log_file, LOG_ERROR, formatted_message);
    }
    free(formatted_message);
}

void handle_log_warning(const char *warning_message, const char *source, const char *username, const char *ip_address) {
    char *formatted_message = create_message_format(warning_message, source, username, ip_address);
    if (formatted_message && warning_log && error_log_file) {
        enqueue_log(error_log_file, LOG_WARNING, formatted_message);
    }
    free(formatted_message);
}

void handle_log_critical_error(const char *error_message, const char *source, const char *username, const char *ip_address) {
    char *formatted_message = create_message_format(error_message, source, username, ip_address);
    if (formatted_message && critical_log_file) {
        enqueue_log(critical_log_file, LOG_CRITICAL_ERROR, formatted_message);
    }
    free(formatted_message);
}

void handle_log_auth_log(const char *auth_message, const char *source, const char *username, const char *ip_address) {
    char *formatted_message = create_message_format(auth_message, source, username, ip_address);
    if (formatted_message && auth_log_file) {
        enqueue_log(auth_log_file, LOG_AUTH, formatted_message);
    }
    free(formatted_message);
}

// Format Message
char *create_message_format(
    const char message[LOG_MESSAGE_STR_LEN], 
    const char source[LOG_SOURCE_STR_LEN], 
    const char username[USERNAME_STR_MAX_LEN], 
    const char ip_address[IP_STR_MAX_LEN]
)
{
    char time_str[20];
    time_to_str(time_str);

    char truncated_message[LOG_MESSAGE_STR_LEN + 1];
    char truncated_source[LOG_SOURCE_STR_LEN + 1];
    char truncated_username[USERNAME_STR_MAX_LEN + 1];
    char truncated_ip[IP_STR_MAX_LEN + 1];

    strncpy(truncated_message, message, LOG_MESSAGE_STR_LEN);
    truncated_message[LOG_MESSAGE_STR_LEN] = '\0';

    strncpy(truncated_source, source, LOG_SOURCE_STR_LEN);
    truncated_source[LOG_SOURCE_STR_LEN] = '\0';

    strncpy(truncated_username, username, USERNAME_STR_MAX_LEN);
    truncated_username[USERNAME_STR_MAX_LEN] = '\0';

    strncpy(truncated_ip, ip_address, IP_STR_MAX_LEN);
    truncated_ip[IP_STR_MAX_LEN] = '\0';

    size_t formatted_len = 50 + LOG_MESSAGE_STR_LEN + LOG_SOURCE_STR_LEN + USERNAME_STR_MAX_LEN
        + IP_STR_MAX_LEN + sizeof(time_str);
    
    char *formatted_message = malloc(formatted_len + 1);
    if (!formatted_message) {
        printf("Memory allocation failed for log the message! Message size: %zu\n", formatted_len);
        return NULL;
    }

    snprintf(formatted_message, formatted_len + 1, "[%s] [%s] [%s] [%s] [%s]", 
        time_str, truncated_message, truncated_source, truncated_username, truncated_ip);

    return formatted_message;
}

void shutdown_logger()
{
    log_thread_running = 0;
    pthread_cond_signal(&log_cond);
    pthread_join(log_thread, NULL);

    if (command_log_file) fclose(command_log_file);
    if (error_log_file) fclose(error_log_file);
    if (critical_log_file) fclose(critical_log_file);
    if (auth_log_file) fclose(auth_log_file);
}