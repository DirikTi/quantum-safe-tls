#ifndef UTILS_H_
#define UTILS_H_

#define RED_PRINT     "\033[31m"
#define GREEN_PRINT   "\033[32m"
#define YELLOW_PRINT  "\033[33m"
#define BLUE_PRINT    "\033[34m"
#define WHITE_PRINT   "\033[37m"
#define RESET_PRINT   "\033[0m"

#define println(msg, ...)           printf(WHITE_PRINT msg RESET_PRINT "\n", ##__VA_ARGS__)
#define printf_info(msg, ...)       printf(GREEN_PRINT "[INFO] " msg RESET_PRINT "\n", ##__VA_ARGS__)
#define printf_warning(msg, ...)    printf(YELLOW_PRINT "[WARNING] " msg RESET_PRINT "\n", ##__VA_ARGS__)
#define printf_error(msg, ...)      printf(RED_PRINT "[ERROR] " msg RESET_PRINT "\n", ##__VA_ARGS__)

/* String Lengths */
#define USERNAME_STR_MAX_LEN    127
#define PASSWORD_STR_MAX_LEN    127
#define IP_STR_MAX_LEN          45
#define LOG_MESSAGE_STR_LEN     512
#define LOG_SOURCE_STR_LEN      256
#define TIME_STR_MAX_LEN        20

#define TRUE ((uint8_t)1U)
#define FALSE ((uint8_t)0U)

void trim(char *str);
void time_to_str(char *time_str);
void get_time_ms();
char *upper_case(const char *value);

#endif