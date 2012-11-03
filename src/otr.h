/*
 * Off-the-Record Messaging (OTR) modules for IRC
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

#ifndef IRSSI_OTR_OTR_H
#define IRSSI_OTR_OTR_H

/* Libotr */
#include <libotr/proto.h>
#include <libotr/message.h>
#include <libotr/context.h>
#include <libotr/privkey.h>

#include "io-config.h"
#include "irssi_otr.h"
#include "utils.h"

/* irssi module name */
#define MODULE_NAME "otr"

#include "otr-formats.h"

/*
 * XXX: Maybe this should be configurable?
 */
#define OTR_MAX_MSG_SIZE              400

/* OTR protocol id */
#define OTR_PROTOCOL_ID               "IRC"

#define OTR_KEYFILE                   "/otr/otr.key"
#define OTR_TMP_KEYFILE               "/otr/otr.key.tmp"
#define OTR_FINGERPRINTS_FILE         "/otr/otr.fp"
#define OTR_INSTAG_FILE               "/otr/otr.instag"

/* some defaults */
#define OTR_DEFAULT_POLICY \
	"*@localhost opportunistic, *@im.* opportunistic, *serv@irc* never"

#define OTR_DEFAULT_POLICY_KNOWN      "* always"
#define OTR_DEFAULT_IGNORE            "xmlconsole[0-9]*"

/* used as a prefix for /me messages.
 * This makes it readable and sensible for
 * people not on IRC (i.e. in case of a gateway
 * like bitlbee)
 */
#define IRCACTIONMARK                 "/me "
#define IRCACTIONMARKLEN              4

/* user state */

typedef struct {
	OtrlUserState otr_state;
	GSList *plistunknown;
	GSList *plistknown;
} IOUSTATE;

/* one for each OTR context (=communication pair) */
struct co_info {
	char *msgqueue;                 /* holds partially reconstructed base64
	                                   messages */
	IRC_CTX *ircctx;                /* irssi server object for this peer */
	int received_smp_init;          /* received SMP init msg */
	int smp_failed;                 /* last SMP failed */
	char better_msg_two[256];       /* what the second line of the "better"
	                                   default query msg should like. Eat it
	                                   up when it comes in */
	int finished;                   /* true after you've /otr finished */
};

/* these are returned by /otr contexts */

struct fplist_ {
	char *fp;
	enum { NOAUTH, AUTHSMP, AUTHMAN } authby;
	struct fplist_ *next;
};

struct ctxlist_ {
	char *username;
	char *accountname;
	enum { STUNENCRYPTED, STENCRYPTED, STFINISHED, STUNKNOWN } state;
	struct fplist_ *fplist;
	struct ctxlist_ *next;
};

/* returned by otr_getstatus */
enum otr_status {
	IO_ST_PLAINTEXT,
	IO_ST_FINISHED,
	IO_ST_SMP_INCOMING,
	IO_ST_SMP_OUTGOING,
	IO_ST_SMP_FINALIZE,
	IO_ST_UNKNOWN,
	IO_ST_UNTRUSTED=32,
	IO_ST_TRUST_MANUAL=64,
	IO_ST_TRUST_SMP=128,
	IO_ST_SMP_ONGOING=
		IO_ST_SMP_INCOMING | IO_ST_SMP_OUTGOING | IO_ST_SMP_FINALIZE
};

/* given to otr_status_change */
enum statusbar_event {
	IO_STC_FINISHED,
	IO_STC_TRUST_MANUAL,
	IO_STC_TRUST_SMP,
	IO_STC_SMP_ABORT,
	IO_STC_SMP_STARTED,
	IO_STC_SMP_RESPONDED,
	IO_STC_SMP_INCOMING,
	IO_STC_SMP_FINALIZE,
	IO_STC_SMP_ABORTED,
	IO_STC_PEER_FINISHED,
	IO_STC_SMP_FAILED,
	IO_STC_SMP_SUCCESS,
	IO_STC_GONE_SECURE,
	IO_STC_GONE_INSECURE,
	IO_STC_CTX_UPDATE
};

/* policy list generated from /set otr_policy */

struct plistentry {
	GPatternSpec *namepat;
	OtrlPolicy policy;
};

/* there can be only one */
extern IOUSTATE ioustate_uniq;

extern OtrlMessageAppOps otr_ops;

extern int debug;

void irc_send_message(IRC_CTX *ircctx, const char *recipient, char *msg);
void otr_status_change(IRC_CTX *ircctx, const char *nick,
		enum statusbar_event event);

IRC_CTX *ircctx_by_peername(const char *peername, char *nick);

/* init stuff */

IOUSTATE *otr_init_user(char *user);
void otr_free_user(IOUSTATE *ioustate);

void otr_lib_init();
void otr_lib_uninit();

void otr_setpolicies(IOUSTATE *ioustate, const char *policies, int known);

/* basic send/receive/status stuff */

int otr_send(IRC_CTX *server, const char *msg, const char *to, char **otr_msg);
int otr_receive(IRC_CTX *server, const char *msg, const char *from,
		char **new_msg);

int otr_getstatus(IRC_CTX *ircctx, const char *nick);
ConnContext *otr_getcontext(const char *accname, const char *nick, int create,
		IRC_CTX *ircctx);

/* user interaction */

void otr_trust(IRC_CTX *server, char *nick, const char *peername);
void otr_finish(IRC_CTX *server, char *nick, const char *peername,
		int inquery);
void otr_auth(IRC_CTX *server, char *nick, const char *peername,
		const char *question, const char *secret);
void otr_authabort(IRC_CTX *server, char *nick, const char *peername);
void otr_abort_auth(ConnContext *co, IRC_CTX *ircctx, const char *nick);
struct ctxlist_ *otr_contexts(IOUSTATE *ioustate);
void otr_finishall(IOUSTATE *ioustate);

int otr_getstatus_format(IRC_CTX *ircctx, const char *nick);

#endif /* IRSSI_OTR_OTR_H */
