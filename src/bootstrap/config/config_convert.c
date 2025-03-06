#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <ctype.h>
#include <utils.h>

#define TRUE_VALUE "TRUE"
#define FALSE_VALUE "FALSE"

/* Error handling function */
static void handle_config_error(const char *value, const char *key, const char *type) {
    printf("Error: Invalid value '%s' for key '%s' of type '%s'.\n", value, key, type);
}

/* Boolean convert */
void convert_to_bool(const char *value, const char *key, bool *variable)
{
    upper_case(value);
    
    if (strcmp(value, TRUE_VALUE ) == 0) {
        *variable = true;
    } else if (strcmp(value, FALSE_VALUE) == 0) {
        *variable = false;
    } else {
        handle_config_error(value, key, "TRUE/FALSE");
    }
}

/* Integer convert */
void convert_to_int(const char *value, const char *key, int *variable) {
    int result = atoi(value);
    if (result == 0 && strcmp(value, "0") != 0) {
        handle_config_error(value, key, "int");
    }
    *variable = result;
}

/* uint32_t convert */
void convert_to_uint32(const char *value, const char *key, uint32_t *variable) {
    uint32_t result = (uint32_t)atoi(value);
    if (result == 0 && strcmp(value, "0") != 0) {
        handle_config_error(value, key, "int");
    }
    *variable = result;
}

/* String copy */
void convert_to_string(const char *value, const char *key, char **variable) {
    *variable = malloc(256 * sizeof(char));

    if (!*variable) {
        handle_config_error(value, key, "string");
        return;
    }
    strcpy(*variable, value);
}

/* Convert Logs */
void convert_to_logs(const char *value, const char *key, uint8_t *logs)
{
    uint8_t log_value = (uint8_t)atoi(value);
    if (log_value == 1 || log_value == 0) {
        if (strcmp(key, "log_command") == 0) {
            *logs |= log_value;
        }
        else if (strcmp(key, "log_warning") == 0) {
            *logs |= (log_value << 1);
        }
        else if (strcmp(key, "log_error") == 0) {
            *logs |= (log_value << 2);
        }
    }
    else if (log_value != 0) {
        handle_config_error(value, key, "logs");
    }
}

char *convert_to_string_from_bool(bool value)
{
    if (value == TRUE)
        return "true";
    return "false";
}
