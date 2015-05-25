CC=gcc
CFLAGS=-Wall -Wextra -O3 -g
LDFLAGS=-lcurl -lpcre -lpthread -lssh -ldl -lcrypto
SRC_DIR=src

SRC_OBJECTS =	$(SRC_DIR)/kadimus_common.o \
		$(SRC_DIR)/kadimus_mem.o \
		$(SRC_DIR)/kadimus_request.o \
		$(SRC_DIR)/kadimus_str.o \
		$(SRC_DIR)/kadimus_xpl.o \
		$(SRC_DIR)/kadimus_regex.o \
		$(SRC_DIR)/kadimus_socket.o \
		$(SRC_DIR)/kadimus_io.o \
		$(SRC_DIR)/kadimus.o \

.PHONY = kadimus

kadimus: $(SRC_OBJECTS)
	@$(CC) -o kadimus $(SRC_OBJECTS) $(LDFLAGS) $(CFLAGS)
	@echo [+] Ok
clean:
	rm $(SRC_OBJECTS)
	rm kadimus

