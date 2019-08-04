override CFLAGS+=-Wall -Wextra -O2 -Isrc
override LDFLAGS+=-lcurl -lpcre -lpthread -lssh -ldl -lcrypto

SOURCES := $(wildcard src/*.c) $(wildcard src/*/*.c)
OBJS := $(addprefix bin/,$(SOURCES:src/%.c=%.o))

SUBFOLDERS := $(wildcard src/*/.)
FOLDERS := $(addprefix bin/,$(SUBFOLDERS:src/%/.=%))

all: $(FOLDERS) kadimus

kadimus: $(OBJS)
	@$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^
	@echo "  CC $@"

$(FOLDERS):
	@mkdir $@
	@echo "  MKDIR $@"

bin/%.o: src/%.c src/%.h
	@$(CC) $(CFLAGS) -c -o $@ $<
	@echo "  CC $@"

.PHONY: clean
clean:
	rm -f bin/*/*.o bin/*.o kadimus
