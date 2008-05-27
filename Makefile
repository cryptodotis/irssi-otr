SRCS=otr.c otrutil.c ui.c
HDRS=otr.h otrutil.h ui.h mainwindows.h
OBJS=$(SRCS:%.c=%.o)

INCLUDES=-I/usr/include/irssi/ -I/usr/include/irssi/src -I/usr/include/irssi/src/core -I.
DEFINES=-DHAVE_CONFIG_H

CFLAGS=-Wall -g -fPIC ${INCLUDES} ${DEFINES} `pkg-config --cflags glib-2.0`
LDFLAGS=-shared -lotr

CC=gcc
LD=ld

.PHONY: deploy compile

compile: libotr.so

deploy: libotr.so
	cp libotr.so ~/.irssi/modules/libotr.so


%.so:
	${LD} ${LDFLAGS} $^ -o $@

mainwindows.h:
	@echo "**** Fetching headers from irssi svn..."
	@for hdr in mainwindows.h term.h statusbar.h; do \
		svn cat -r 4815 http://svn.irssi.org/repos/irssi/trunk/src/fe-text/$$hdr >$$hdr \
	 ;done
	patch -p0 mainwindows.h <privheaders.patch

otr.o:	    otr.c	${HDRS}
otrutil.o:  otrutil.c	${HDRS}
ui.o:	    ui.c	ui.h

libotr.so: ${OBJS}

clean:
	rm *.o *.so
