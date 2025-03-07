#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>

#define ERROR_IS_NOT_VALID_IPV4 -2

#define IP_NAME_LENGTH 127
#define SECURITY_FOLDER "security"
#define IP_LIST_FILE_PATH "security/ip_list_v4.txt"
#define LOCAL_IP (uint8_t[4]){0x7f, 0x0, 0x0, 0x01}
#define MAX_IP_COUNT 10

typedef struct {
    char name[IP_NAME_LENGTH];
    uint8_t ip_address[4];
} IP_v4;

static IP_v4 IP_v4_list[MAX_IP_COUNT];
static size_t ip_v4_list_size = 0;

static void create_security_folder() {
    struct stat st = {0};
    if (stat(SECURITY_FOLDER, &st) == -1) {
        mkdir(SECURITY_FOLDER, 0700);
    }
}

inline static int is_valid_ip_v4(const char *ip_address, uint8_t parsed_ip[4]) {
    if (!ip_address || strlen(ip_address) < 7 || strlen(ip_address) > 15) {
        return -1;
    }

    int segments = 0;
    char copy[16];
    strncpy(copy, ip_address, 15);
    copy[15] = '\0';

    char *token = strtok(copy, ".");
    while (token) {
        if (strlen(token) > 3) return -1;
        for (int i = 0; token[i]; i++) {
            if (!isdigit(token[i])) return -1;
        }
        int num = atoi(token);
        if (num < 0 || num > 255) return -1;

        parsed_ip[segments++] = (uint8_t)num;
        
        token = strtok(NULL, ".");
    }

    return (segments == 4) ? 1 : -1;
}

static int find_ip_v4_by_name(const char *ip_address_name) {
    for (size_t i = 0; i < ip_v4_list_size; i++) {
        if (strcmp(IP_v4_list[i].name, ip_address_name) == 0) {
            return i;
        }
    }
    return -1;
}

int add_ip_v4_address(const char *ip_address_name, const char *ip_address) {
    uint8_t parsed_ip[4];
    if (is_valid_ip_v4(ip_address, parsed_ip) == -1) {
        return ERROR_IS_NOT_VALID_IPV4;
    }
    
    int index = find_ip_v4_by_name(ip_address_name);
    if (index != -1) {
        memcpy(IP_v4_list[index].ip_address, parsed_ip, 4);
    } else {
        if (ip_v4_list_size >= MAX_IP_COUNT) return -1;
        strncpy(IP_v4_list[ip_v4_list_size].name, ip_address_name, IP_NAME_LENGTH - 1);
        memcpy(IP_v4_list[ip_v4_list_size].ip_address, parsed_ip, 4);
        ip_v4_list_size++;
    }

    FILE *file = fopen(IP_LIST_FILE_PATH, "w");
    if (!file) return -1;
    for (size_t i = 0; i < ip_v4_list_size; i++) {
        fprintf(file, "%s;%u.%u.%u.%u\n", 
                IP_v4_list[i].name, 
                IP_v4_list[i].ip_address[0], 
                IP_v4_list[i].ip_address[1], 
                IP_v4_list[i].ip_address[2], 
                IP_v4_list[i].ip_address[3]);
    }
    fclose(file);
    return 1;
}

int remove_ip_v4_address_by_name(const char *ip_address_name) {
    int index = find_ip_v4_by_name(ip_address_name);
    if (index == -1) return -1;
    
    IP_v4_list[index] = IP_v4_list[--ip_v4_list_size];
    FILE *file = fopen(IP_LIST_FILE_PATH, "w");
    if (!file) return -1;
    for (size_t i = 0; i < ip_v4_list_size; i++) {
        fprintf(file, "%s;%u.%u.%u.%u\n", 
                IP_v4_list[i].name, 
                IP_v4_list[i].ip_address[0], 
                IP_v4_list[i].ip_address[1], 
                IP_v4_list[i].ip_address[2], 
                IP_v4_list[i].ip_address[3]);
    }
    fclose(file);
    return 1;
}

int is_ip_in_list(const uint8_t ip_bytes[4])
{
    if (memcmp(LOCAL_IP, ip_bytes, 4) == 0) return 0; 

    size_t i = 0;
    while (i < ip_v4_list_size) {
        if (memcmp(IP_v4_list[i++].ip_address, ip_bytes, 4) == 0) return 0;
    } 

    return -1;
}

void load_ip_v4_list(void) {
    create_security_folder();
    FILE *file = fopen(IP_LIST_FILE_PATH, "r");
    if (!file) {
        file = fopen(IP_LIST_FILE_PATH, "w+");
        return;
    }
    
    char line[IP_NAME_LENGTH + 16 + 2];
    while (fgets(line, sizeof(line), file) && ip_v4_list_size < MAX_IP_COUNT) {
        line[strcspn(line, "\n")] = '\0';
        char *delimiter = strchr(line, ';');
        if (!delimiter) continue;
        *delimiter = '\0';

        char *ip_str = delimiter + 1;
        uint8_t parsed_ip[4];
        if (is_valid_ip_v4(ip_str, parsed_ip) == 1) {
            strncpy(IP_v4_list[ip_v4_list_size].name, line, IP_NAME_LENGTH - 1);
            memcpy(IP_v4_list[ip_v4_list_size].ip_address, parsed_ip, 4);
            ip_v4_list_size++;
        }
    }
    fclose(file);
}
