#ifndef CONFIG_CONVERT_H_
#define CONFIG_CONVERT_H_

#include <stdlib.h>

void convert_to_bool(const char *value, const char *key, bool *variable);
void convert_to_int(const char *value, const char *key, int *variable);
void convert_to_uint32(const char *value, const char *key, uint32_t *variable);
void convert_to_string(const char *value, const char *key, char **variable);
void convert_to_logs(const char *value, const char *key, uint8_t *logs);

char *convert_to_string_from_bool(bool value);

#endif // CONFIG_CONVERT_H