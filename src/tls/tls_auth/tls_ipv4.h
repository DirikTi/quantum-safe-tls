#ifndef TLS_SECURITY_H_
#define TLS_SECURITY_H_

#define IP_NAME_LENGTH 127
#define IP_ADDRESS_LENGTH 16

#define ERROR_IS_NOT_VALID_IPV4 -2

void load_ip_v4_list(void);
int remove_ip_v4_address_by_name(const char *ip_address_name);
int add_ip_v4_address(const char *ip_address_name, const char *ip_address);
int is_ip_in_list(const uint8_t ip[4]);

#endif // SERVER_SECURITY_H