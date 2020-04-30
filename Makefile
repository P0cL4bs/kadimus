override CFLAGS+=-Wall -Wextra -O2 -Isrc
override LDFLAGS+=-lcurl -lpcre -lpthread -lssh -ldl -lcrypto

SOURCES := $(wildcard src/*/*.c) $(wildcard src/*.c)
OBJS := $(addprefix bin/,$(SOURCES:src/%.c=%.o))

SUBFOLDERS := $(wildcard src/*/.)
FOLDERS := $(addprefix bin/,$(SUBFOLDERS:src/%/.=%))

all: $(FOLDERS) kadimus

kadimus: $(OBJS)
	@echo "  CC $@"
	@$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

$(FOLDERS):
	@echo "  MKDIR $@"
	@mkdir $@

bin/%.o: src/%.c src/%.h
	@echo "  CC $@"
	@$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -f bin/*/*.o bin/*.o kadimus
