CC=gcc
CFLAGS=-Wall -Wextra -O3
LDFLAGS=-lcurl -lpcre -lpthread -lssh -ldl -lcrypto
SRC_DIR=src
OBJ_DIR=bin

OBJS =		$(OBJ_DIR)/kadimus_common.o \
		$(OBJ_DIR)/kadimus_mem.o \
		$(OBJ_DIR)/kadimus_request.o \
		$(OBJ_DIR)/kadimus_str.o \
		$(OBJ_DIR)/kadimus_xpl.o \
		$(OBJ_DIR)/kadimus_regex.o \
		$(OBJ_DIR)/kadimus_socket.o \
		$(OBJ_DIR)/kadimus_io.o \
		$(OBJ_DIR)/kadimus.o

kadimus: $(OBJS)
	$(CC) -o kadimus $(OBJS) $(LDFLAGS) $(CFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<


clean:
	rm -f $(OBJS) kadimus

