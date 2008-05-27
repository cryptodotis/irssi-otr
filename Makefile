SRCS=otr.c otrutil.c ui.c
HDRS=otr.h otrutil.h ui.h mainwindows.h statusbar.h
OBJS=$(SRCS:%.c=%.o)

INCLUDES=-I/usr/include/irssi/ -I/usr/include/irssi/src -I/usr/include/irssi/src/core -I.
DEFINES=-DHAVE_CONFIG_H

CFLAGS=-Wall -g -fPIC ${INCLUDES} ${DEFINES} `pkg-config --cflags glib-2.0`
LDFLAGS=-shared -lotr

CC=gcc
LD=ld

.PHONY: deploy privheaders

%.so:
	${LD} ${LDFLAGS} $^ -o $@

deploy: libotr.so
	cp libotr.so ~/.irssi/modules/libotr.so

mainwindows.h:
	@echo "****" You need to copy over mainwindows.h and statusbar.h from your irssi source \(see irssi FS#535 for info\)
	@echo "****" Then you need to patch mainwindows.h with headers.patch
	@echo "****" Or you could just call "make privheaders IRSSI_SRC=path/to/irssi-source"
	@exit 1

privheaders:
	cp ${IRSSI_SRC}/src/fe-text/{mainwindows.h,statusbar.h} .
	patch -p0 < privheaders.patch

otr.o:	    otr.c	${HDRS}
otrutil.o:  otrutil.c	${HDRS}
ui.o:	    ui.c	ui.h

libotr.so: ${OBJS}

clean:
	rm *.o *.so
