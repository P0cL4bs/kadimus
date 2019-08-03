override CFLAGS+=-Wall -Wextra -O2 -Isrc
override LDFLAGS+=-lcurl -lpcre -lpthread -lssh -ldl -lcrypto

SOURCES := $(wildcard src/*.c) $(wildcard src/*/*.c)
OBJS := $(addprefix bin/,$(SOURCES:src/%.c=%.o))

SUBFOLDERS := $(wildcard src/*/.)
FOLDERS := $(addprefix bin/,$(SUBFOLDERS:src/%/.=%/))

kadimus: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

$(OBJS): $(FOLDERS)

bin/%/:
	@mkdir $@

bin/%.o: src/%.c src/%.h
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -f bin/*/*.o bin/*.o kadimus
