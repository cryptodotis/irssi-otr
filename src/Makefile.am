AM_CFLAGS = $(LIBOTR_CFLAGS) $(LIBGCRYPT_CFLAGS) $(PACKAGE_FLAGS)

IRSSI_DIST=$(includedir)/irssi
IRSSI_INCLUDE = -I$(IRSSI_DIST) \
				-I$(IRSSI_DIST)/src \
				-I$(IRSSI_DIST)/src/fe-common/core \
				-I$(IRSSI_DIST)/src/core \
				-I$(IRSSI_DIST)/src/fe-text \
				-I$(IRSSI_DIST)/src/irc \
				-I$(IRSSI_DIST)/src/irc/core \
				-I$(IRSSI_DIST)/src/irc/dcc \
				-I$(IRSSI_DIST)/src/irc/notifylist

INCLUDES = -I$(top_srcdir)/src $(IRSSI_INCLUDE)

plugindir = $(IRSSI_MODULE_DIR)
plugin_LTLIBRARIES = libotr.la

libotr_la_SOURCES = otr-formats.c otr-formats.h \
                 key.c key.h cmd.c cmd.h otr.c otr-ops.c \
                 utils.h utils.c otr.h module.c module.h irssi-otr.h

libotr_la_LDFLAGS = -avoid-version -module
libotr_la_LDFLAGS += $(LIBOTR_LIBS) $(LIBGCRYPT_LIBS) -lpthread

install-data-hook:
	chmod 644 $(DESTDIR)/$(plugindir)/libotr.so
	rm $(DESTDIR)/$(plugindir)/libotr.la

uninstall-hook:
	rm $(DESTDIR)/$(plugindir)/libotr.so
