AM_CFLAGS = $(LIBOTR_CFLAGS) $(LIBGCRYPT_CFLAGS) $(PACKAGE_FLAGS)

IRSSI_DIST=/usr/include/irssi
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

lib_LTLIBRARIES = otr.la

otr_la_SOURCES = key.c key.h cmd.c cmd.h otr.c otr-ops.c \
					utils.h utils.c otr.h module.c irssi_otr.h \
					otr-formats.c otr-formats.h
otr_la_LDFLAGS = -avoid-version -module
otr_la_LDFLAGS += $(LIBOTR_LIBS) $(LIBGCRYPT_LIBS)
