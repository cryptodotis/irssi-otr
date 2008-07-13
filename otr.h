/*
 * Off-the-Record Messaging (OTR) module for the irssi IRC client
 * Copyright (C) 2008  Uli Meis <a.sporto+bee@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#include <stdlib.h>

/* OTR */

#include <libotr/proto.h>
#include <libotr/context.h>
#include <libotr/message.h>
#include <libotr/privkey.h>

/* irssi */

#include <common.h>
#include <core/commands.h>
#include <core/modules.h>
#include <core/servers.h>
#include <core/signals.h>
#include <core/levels.h>
#include <core/queries.h>
#include <fe-common/core/printtext.h>
#include <fe-common/core/fe-windows.h>
#include <fe-common/core/module-formats.h>
#include <core/modules.h>

/* copied over, see FS#535 */
#include <fe-text/statusbar.h>

/* glib */

#include <glib.h>
#include <glib/gprintf.h>
#include <glib/gstdio.h>

/* own */

#include "io-config.h"
#include "otr-formats.h"

/* irssi module name */
#define MODULE_NAME "otr"

/* 
 * maybe this should be configurable?
 * I believe bitlbee has something >500.
 */
#define OTR_MAX_MSG_SIZE 400

/* otr protocol id */
#define PROTOCOLID "IRC"

#define KEYFILE "/otr/otr.key"
#define FPSFILE "/otr/otr.fp"

/* one for each OTR context (=communication pair) */
struct co_info {
	char *msgqueue;			/* holds partially reconstructed base64
					   messages */
	SERVER_REC *server;		/* irssi server object for this peer */
	int received_smp_init;		/* received SMP init msg */
	int smp_failed;			/* last SMP failed */
	char better_msg_two[256];	/* what the second line of the "better"
					   default query msg should like. Eat it
					   up when it comes in */
	int finished;			/* true after you've /otr finished */
};

/* these are returned by /otr contexts */

struct fplist_ {
	char *fp;
	enum { NOAUTH,AUTHSMP,AUTHMAN } authby;
	struct fplist_ *next;
};

struct ctxlist_ {
	char *username;
	char *accountname;
	enum { STUNENCRYPTED,STENCRYPTED,STFINISHED,STUNKNOWN } state;
	struct fplist_ *fplist;
	struct ctxlist_ *next;
};

/* used by the logging functions below */
extern int debug;

/* init stuff */

int otrlib_init();
void otrlib_deinit();
void otr_initops();

/* basic send/receive/status stuff */

char *otr_send(SERVER_REC *server,const char *msg,const char *to);
char *otr_receive(SERVER_REC *server,const char *msg,const char *from);
int otr_getstatus(char *mynick, char *nick, char *server);
ConnContext *otr_getcontext(const char *accname,const char *nick,int create,void *data);

/* user interaction */

void otr_trust(SERVER_REC *server, char *nick);
void otr_finish(SERVER_REC *server, char *nick,int inquery);
void otr_auth(SERVER_REC *server, char *nick, const char *secret);
void otr_authabort(SERVER_REC *server, char *nick);
struct ctxlist_ *otr_contexts();


/* key/fingerprint stuff */

void keygen_run(const char *accname);
void keygen_abort();
void key_load();
void fps_load();
void otr_writefps();

/* log stuff */

#define LOGMAX 1024

#define LVL_NOTICE  0
#define LVL_DEBUG   1

#define otr_logst(level,format,...) \
	otr_log(NULL,NULL,level,format, ## __VA_ARGS__)

#define otr_noticest(formatnum,...) \
	printformat(NULL,NULL,MSGLEVEL_MSGS, formatnum, ## __VA_ARGS__)

#define otr_notice(server,nick,formatnum,...) \
	printformat(server,nick,MSGLEVEL_MSGS, formatnum, ## __VA_ARGS__)

#define otr_debug(server,nick,formatnum,...) { \
	if (debug) \
		printformat(server,nick, \
			    MSGLEVEL_MSGS, formatnum, ## __VA_ARGS__); \
}

void otr_log(SERVER_REC *server, const char *to, 
	     int level, const char *format, ...);
