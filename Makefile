CC=gcc
INCLUDES=-I/usr/local/include/libvmi -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -I/usr/include/cairo -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -I/usr/include/pixman-1 -I/usr/include/uuid -I/usr/include/freetype2 -I/usr/include/libpng16

LIBS=-L/usr/lib -lvmi -lglib-2.0 -lX11 -lm -lcairo

#CFLAGS+= -Wextra -Werror
CFLAGS+= -Wno-missing-field-initializers
CFLAGS+= -Wno-missing-braces
CFLAGS+= -Wno-unused-result
CFLAGS+= -Wno-ignored-attributes
CFLAGS+= -g -Wall -O0 -std=gnu99
CFLAGS+= $(INCLUDES)

vmi-reconstruct-gui: main.c
	 $(CC) $(CFLAGS) -o vmi-reconstruct-gui main.c gfx.c $(LIBS)

.PHONY: clean
clean :
	rm vmi-reconstruct-gui *.o
