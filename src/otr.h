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

/*
 * Memory allocation zeroed. Really useful!
 */
#define zmalloc(x) calloc(1, x)

/* Irssi otr user state */
struct otr_user_state {
	OtrlUserState otr_state;
	GSList *policy_unknown_list;
	GSList *policy_known_list;
};

/*
 * Peer OTR internal context.
 */
struct otr_peer_context {
	OtrlSMPEvent smp_event;
	unsigned int ask_secret;
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
	IO_ST_PLAINTEXT        = 0,
	IO_ST_FINISHED         = 1,
	IO_ST_SMP_INCOMING     = 2,
	IO_ST_SMP_OUTGOING     = 3,
	IO_ST_SMP_FINALIZE     = 4,
	IO_ST_UNKNOWN          = 5,
	IO_ST_UNTRUSTED        = 6,
	IO_ST_TRUST_MANUAL     = 7,
	IO_ST_TRUST_SMP        = 8,
};

/* given to otr_status_change */
enum otr_status_event {
	OTR_STATUS_FINISHED,
	OTR_STATUS_TRUST_MANUAL,
	OTR_STATUS_TRUST_SMP,
	OTR_STATUS_SMP_ABORT,
	OTR_STATUS_SMP_STARTED,
	OTR_STATUS_SMP_RESPONDED,
	OTR_STATUS_SMP_INCOMING,
	OTR_STATUS_SMP_FINALIZE,
	OTR_STATUS_SMP_ABORTED,
	OTR_STATUS_PEER_FINISHED,
	OTR_STATUS_SMP_FAILED,
	OTR_STATUS_SMP_SUCCESS,
	OTR_STATUS_GONE_SECURE,
	OTR_STATUS_GONE_INSECURE,
	OTR_STATUS_CTX_UPDATE
};

/* policy list generated from /set otr_policy */

struct plistentry {
	GPatternSpec *namepat;
	OtrlPolicy policy;
};

/* there can be only one */
extern struct otr_user_state *user_state_global;

/* Libotr ops functions */
extern OtrlMessageAppOps otr_ops;

/* Active debug or not */
extern int debug;

void irssi_send_message(SERVER_REC *irssi, const char *recipient,
		const char *message);
void otr_status_change(SERVER_REC *irssi, const char *nick,
		enum otr_status_event event);

SERVER_REC *find_irssi_ctx_by_peername(const char *peername, char *nick);

/* init stuff */

struct otr_user_state *otr_init_user(const char *user);
void otr_free_user(struct otr_user_state *ustate);

void otr_lib_init();
void otr_lib_uninit();

void otr_setpolicies(struct otr_user_state *ustate, const char *policies,
		int known);

/* basic send/receive/status stuff */

int otr_send(SERVER_REC *irssi, const char *msg, const char *to,
		char **otr_msg);
int otr_receive(SERVER_REC *irssi, const char *msg,
		const char *from, char **new_msg);

int otr_getstatus(SERVER_REC *irssi, const char *nick);

/* user interaction */

void otr_trust(SERVER_REC *irssi, char *nick,
		const char *peername);
void otr_finish(SERVER_REC *irssi, char *nick,
		const char *peername, int inquery);
void otr_auth(SERVER_REC *irssi, char *nick, const char *peername,
		const char *question, const char *secret);
void otr_authabort(SERVER_REC *irssi, char *nick,
		const char *peername);
void otr_abort_auth(ConnContext *co, SERVER_REC *irssi,
		const char *nick);
struct ctxlist_ *otr_contexts(struct otr_user_state *ustate);
void otr_finishall(struct otr_user_state *ustate);

int otr_getstatus_format(SERVER_REC *irssi, const char *nick);
struct otr_peer_context *otr_create_peer_context(void);

#endif /* IRSSI_OTR_OTR_H */
