# Compiler and Debug Flags
CC = gcc
DEV_MODE = true
# Directories
SRC_DIR = src
BUILD_DIR = build
OBJ_DIR = $(BUILD_DIR)/obj
LIB_DIR = $(BUILD_DIR)/lib
BIN_DIR = $(BUILD_DIR)/bin

# Flags for debug -g -O0 -Wall -Wextra
CFLAGS += -Wno-unused-variable -Wno-unused-function -Wno-deprecated-declarations -g -O0 -Wall -Wextra
# CFLAGS += -Wall -Wextra -Werrors

CFLAGS += -I/usr/local/src/openssl/include -Iinclude
LDFLAGS = -L/usr/local/lib -lssl -lcrypto -loqs -luring

CFLAGS += $(IOURING_CFLAGS)
LDFLAGS += $(IOURING_LDFLAGS)

# Main
rwildcard = $(wildcard $(1)/*.c) $(foreach d,$(wildcard $(1)/*),$(call rwildcard,$d))

MAIN_SRC = $(wildcard src/*.c src/utils/*.c src/server/*.c src/bootstrap/config/*.c src/bootstrap/*.c src/bootstrap/ssl/*.c ) \
           $(call rwildcard,src/tls)

MAIN_OBJ = $(patsubst src/%, $(OBJ_DIR)/%, $(MAIN_SRC:.c=.o))
MAIN_BIN = $(BIN_DIR)/oqs_tls

# -------------------------- SHARED LIBRARY --------------------------
# libssl_ctx
# SSL_SRC = $(wildcard src/bootstrap/ssl/*.c src/bootstrap/ssl/file/*.c)
# SSL_OBJ = $(patsubst src/%, $(OBJ_DIR)/%, $(SSL_SRC:.c=.o))
# SSL_LIB = $(LIB_DIR)/libssl_ctx.so

# libconfig
CONFIG_SRC = $(wildcard src/utils/utils.c src/bootstrap/config/*.c)
CONFIG_OBJ = $(patsubst src/%, $(OBJ_DIR)/%, $(CONFIG_SRC:.c=.o))
CONFIG_LIB = $(LIB_DIR)/libconfig.so

# libtls_ctx
TLS_SRC = $(wildcard src/utils/utils.c src/bootstrap/tls/*.c)
TLS_OBJ = $(patsubst src/%, $(OBJ_DIR)/%, $(TLS_SRC:.c=.o))
TLS_LIB = $(LIB_DIR)/libtls_ctx.so
# -------------------------- SHARED LIBRARY --------------------------

# Target executable
all: $(MAIN_BIN) $(CONFIG_LIB) $(TLS_LIB)

# Tüm obj dosyalarını oluştur
$(OBJ_DIR)/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# Shared library oluştur
# $(SSL_LIB): $(SSL_OBJ)
#	@mkdir -p $(LIB_DIR)
#	$(CC) -shared -o $@ $^ $(LDFLAGS)

$(CONFIG_LIB): $(CONFIG_OBJ)
	@mkdir -p $(LIB_DIR)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

$(TLS_LIB): $(TLS_OBJ)
	@mkdir -p $(LIB_DIR)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# Main binary oluştur
$(MAIN_BIN): $(MAIN_OBJ)
	@mkdir -p $(BIN_DIR)
	$(CC) -o $@ $^ $(LDFLAGS)

rebuild:
	rm -rf $(OBJ_DIR) $(BIN_DIR) $(LIB_DIR) && $(MAKE) setup && ./$(MAIN_BIN)

run: $(MAIN_BIN) $(CONFIG_LIB) $(TLS_LIB)
	./$(MAIN_BIN)

install:
	$(MAKE) $(MAIN_BIN)  $(CONFIG_LIB) $(TLS_LIB)
	
# Debug
dev: $(MAIN_BIN) $(CONFIG_LIB) $(TLS_LIB)
	lldb ./$(MAIN_BIN)

# Clean
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR) $(LIB_DIR)

.PHONY: all clean rebuild test
