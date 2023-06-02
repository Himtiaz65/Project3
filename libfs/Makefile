# Target library
lib := libfs.a

# Source files
src := fs.c disk.c 

# Object files
objs := $(src:.c=.o)

# Include dependencies
deps := $(objs:.o=.d)
-include $(deps)

# Compiler options
CC := gcc
CFLAGS := -Wall -Werror -Wno-format
CFLAGS += -I.
CFLAGS += -MMD

# Default rule
all: $(lib)

# Rule for building the library
$(lib): $(objs)
	@echo "AR    $@"
	ar rcs $@ $^

# Rule for compiling objects
%.o: %.c
	@echo "CC    $@"
	$(CC) $(CFLAGS) -c -o $@ $<

# Cleaning rule
clean:
	@echo "CLEAN    libfs"
	rm -rf $(objs) $(deps) $(lib)

.PHONY: all clean
