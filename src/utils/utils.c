#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>

void trim(char *str)
{
    char *end;

    while (isspace((unsigned char)*str)) str++;

    if (*str != 0) {
        end = str + strlen(str) - 1;
        while (end > str && isspace((unsigned char)*end)) end--;

        *(end + 1) = '\0';
    }
}

void time_to_str(char *time_str)
{
    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    strftime(time_str, 20, "%Y-%m-%d %H:%M:%S", t);
}

int64_t get_time_ms()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000LL) + (tv.tv_usec / 1000);
}

void upper_case(char *value)
{
    if (value == NULL) return;

    while (*value) {
        *value = toupper((unsigned char)*value);
        value++;
    }
}
