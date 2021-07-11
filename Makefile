# Inspired by: https://spin.atomicobject.com/2016/08/26/makefile-c-projects/x
CC=gcc

INCLUDES=-I/usr/local/include/libvmi -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -I/usr/include/cairo -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -I/usr/include/pixman-1 -I/usr/include/uuid -I/usr/include/freetype2 -I/usr/include/libpng16

LIBS=-L/usr/lib -lvmi -lglib-2.0 -lX11 -lm -lcairo -ljson-c

#CFLAGS+= -Wextra -Werror
CFLAGS+= -Wno-missing-field-initializers
CFLAGS+= -Wno-missing-braces
CFLAGS+= -Wno-unused-result
CFLAGS+= -Wno-ignored-attributes
CFLAGS+= -g -Wall -O0 -std=gnu99
CFLAGS+= $(INCLUDES)

# Resulting binary
TARGET_EXEC ?= vmi-reconstruct-gui

# Set directory variables
BUILD_DIR ?= ./build
SRC_DIRS ?= ./src
MKDIR_P ?= 

# Define source files
SRCS := $(shell find $(SRC_DIRS) -name *.c)
OBJS := $(SRCS:%=$(BUILD_DIR)/%.o)

# Link object files
$(BUILD_DIR)/$(TARGET_EXEC): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LIBS) 

# Compile sources to object files
$(BUILD_DIR)/%.c.o: %.c
	$(shell mkdir -p $(dir $@))
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean

clean:
	$(RM) -r $(BUILD_DIR)

