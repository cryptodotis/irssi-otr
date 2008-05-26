SRCS=otr.c otrutil.c ui.c
HDRS=otr.h otrutil.h ui.h config.h
OBJS=$(SRCS:%.c=%.o)

INCLUDES=-I/usr/include/irssi/src -I/usr/include/irssi/src/core -I.
DEFINES=-DHAVE_CONFIG_H

CFLAGS=-Wall -g -fPIC ${INCLUDES} ${DEFINES} `pkg-config --cflags glib-2.0`
LDFLAGS=-shared -lotr

CC=gcc
LD=ld

.PHONY: deploy

deploy: libotr.so
	cp libotr.so ~/.irssi/modules/libotr.so

config.h:
	@echo Copy config.h from irssi here
	@exit 1

%.so:
	${LD} ${LDFLAGS} $^ -o $@

otr.o:	    otr.c	${HDRS}
otrutil.o:  otrutil.c	${HDRS}
ui.o:	    ui.c	ui.h

libotr.so: ${OBJS}

clean:
	rm *.o *.so
