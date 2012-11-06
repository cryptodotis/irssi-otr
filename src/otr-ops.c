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

#include <assert.h>

#include "key.h"

static const char *otr_msg_event_txt[] = {
	"NONE",
	"ENCRYPTION_REQUIRED",
	"ENCRYPTION_ERROR",
	"CONNECTION_ENDED",
	"SETUP_ERROR",
	"MSG_REFLECTED",
	"MSG_RESENT",
	"RCVDMSG_NOT_IN_PRIVATE",
	"RCVDMSG_UNREADABLE",
	"RCVDMSG_MALFORMED",
	"LOG_HEARTBEAT_RCVD",
	"LOG_HEARTBEAT_SENT",
	"RCVDMSG_GENERAL_ERR",
	"RCVDMSG_UNENCRYPTED",
	"RCVDMSG_UNRECOGNIZED",
	"RCVDMSG_FOR_OTHER_INSTANCE"
};

OtrlPolicy IO_DEFAULT_OTR_POLICY =
	OTRL_POLICY_MANUAL | OTRL_POLICY_WHITESPACE_START_AKE;

/*
 * Return policy for given context based on the otr_policy /setting
 */
static OtrlPolicy ops_policy(void *opdata, ConnContext *context)
{
	int ret;
	struct irssi_otr_context *ioc = context->app_data;
	char *server = strchr(context->accountname, '@') + 1;
	OtrlPolicy op = IO_DEFAULT_OTR_POLICY;
	GSList *pl;
	char fullname[1024];
	IOUSTATE *ioustate = IRSSI_IO_US(ioc->irssi);

	ret = snprintf(fullname, sizeof(fullname), "%s@%s", context->username,
			server);
	if (ret < 0) {
		/* Return default policy */
		goto error;
	}

	/* Unknown policy */
	if (ioustate->plistunknown) {
		pl = ioustate->plistunknown;
		do {
			struct plistentry *ple = pl->data;

			if (g_pattern_match_string(ple->namepat, fullname)) {
				op = ple->policy;
			}
		} while ((pl = g_slist_next(pl)));
	}

	/* Known policy */
	if (ioustate->plistknown && context->fingerprint_root.next) {
		pl = ioustate->plistknown;

		do {
			struct plistentry *ple = pl->data;

			if (g_pattern_match_string(ple->namepat, fullname)) {
				op = ple->policy;
			}
		} while ((pl = g_slist_next(pl)));
	}

	if (ioc && context->msgstate == OTRL_MSGSTATE_FINISHED &&
			(op == OTRL_POLICY_OPPORTUNISTIC || op == OTRL_POLICY_ALWAYS)) {
		op = OTRL_POLICY_MANUAL | OTRL_POLICY_WHITESPACE_START_AKE;
	}

error:
	return op;
}

/*
 * Request for key generation.
 *
 * The lib actually expects us to be finished before the call returns. Since
 * this can take more than an hour on some systems there isn't even a point in
 * trying...
 */
static void ops_create_privkey(void *opdata, const char *accountname,
		const char *protocol)
{
	IRC_CTX *irssi __attribute__((unused)) = opdata;

	key_generation_run(IRSSI_IO_US(irssi), accountname);
}

/*
 * Inject OTR message.
 *
 * Deriving the server is currently a hack, need to derive the server from
 * accountname.
 */
static void ops_inject_msg(void *opdata, const char *accountname,
		const char *protocol, const char *recipient, const char *message)
{
	IRC_CTX *a_serv;
	char *msgcopy = g_strdup(message);

	/* OTR sometimes gives us multiple lines
	 * (e.g. the default query (a.k.a. "better") message) */
	g_strdelimit(msgcopy, "\n", ' ');
	a_serv = opdata;
	if (!a_serv) {
		char nick[256];
		a_serv = ircctx_by_peername(accountname, nick);
	}

	if (!a_serv) {
		otr_notice(a_serv, recipient, TXT_OPS_INJECT, accountname,
				recipient, message);
	} else {
		otr_logst(MSGLEVEL_CRAP, "%d: INJECT %s", time(NULL), msgcopy);
		irc_send_message(a_serv, recipient, msgcopy);
	}
	g_free(msgcopy);
}

/*
 * Gone secure.
 */
static void ops_secure(void *opdata, ConnContext *context)
{
	int ret;
	struct irssi_otr_context *ioc;
	char ownfp[OTRL_PRIVKEY_FPRINT_HUMAN_LEN];
	char peerfp[OTRL_PRIVKEY_FPRINT_HUMAN_LEN];

	assert(context);
	/* This should *really* not happened */
	assert(context->msgstate == OTRL_MSGSTATE_ENCRYPTED);

	ioc = context->app_data;

	IRSSI_NOTICE(ioc->irssi, context->username, "%9OTR%9: Gone %9secure%9");
	otr_status_change(ioc->irssi, context->username, IO_STC_GONE_SECURE);

	ret = otrl_context_is_fingerprint_trusted(context->active_fingerprint);
	if (ret) {
		/* Secure and trusted */
		goto end;
	}

	/* Not authenticated. Let's print out the fingerprints for comparison. */
	otrl_privkey_hash_to_human(peerfp,
			context->active_fingerprint->fingerprint);
	otrl_privkey_fingerprint(ioustate_uniq.otr_state, ownfp,
			context->accountname, OTR_PROTOCOL_ID);

	IRSSI_NOTICE(ioc->irssi, context->username, "%9OTR%9: Your peer is not "
			"authenticated. To make sure you're talking to the right guy you can "
			"either agree on a secret and use the authentication described in "
			"%9/otr auth%9, or, recommended, use %9/otr authq [QUESTION] SECRET%9 "
			"or use the traditional way and compare fingerprints "
			"over a secure line (e.g. telephone) and subsequently enter %9/otr "
			"trust%9.");

	IRSSI_NOTICE(ioc->irssi, context->username,
			"%9OTR%9: Your fingerprint is: %y%s\%n.\n"
			"%9OTR%9: %9%s's%9 fingerprint is: %r%s\%n", ownfp,
			context->username, peerfp);

end:
	return;
}

/*
 * Gone insecure.
 */
static void ops_insecure(void *opdata, ConnContext *context)
{
	struct irssi_otr_context *ioc = context->app_data;
	otr_notice(ioc->irssi, context->username, TXT_OPS_INSEC);
	otr_status_change(ioc->irssi, context->username, IO_STC_GONE_INSECURE);
}

/*
 * Still secure? Need to find out what that means...
 */
static void ops_still_secure(void *opdata, ConnContext *context, int is_reply)
{
	struct irssi_otr_context *ioc = context->app_data;
	otr_notice(ioc->irssi, context->username,
			is_reply ?  TXT_OPS_STILL_REPLY : TXT_OPS_STILL_NO_REPLY);
}

/*
 * Really critical with IRC. Unfortunately, we can't tell our peer which size
 * to use.
 */
static int ops_max_msg(void *opdata, ConnContext *context)
{
	return OTR_MAX_MSG_SIZE;
}

static void ops_handle_msg_event(void *opdata, OtrlMessageEvent msg_event,
		ConnContext *context, const char *message, gcry_error_t err)
{
	IRC_CTX *server = opdata;
	char *username = context->username;

	switch (msg_event) {
	case OTRL_MSGEVENT_NONE:
		break;
	case OTRL_MSGEVENT_ENCRYPTION_REQUIRED:
		IRSSI_WARN(server, username, "Encryption is required");
		break;
	case OTRL_MSGEVENT_ENCRYPTION_ERROR:
		break;
	case OTRL_MSGEVENT_CONNECTION_ENDED:
		break;
	case OTRL_MSGEVENT_SETUP_ERROR:
		break;
	case OTRL_MSGEVENT_MSG_REFLECTED:
		break;
	case OTRL_MSGEVENT_MSG_RESENT:
		break;
	case OTRL_MSGEVENT_RCVDMSG_NOT_IN_PRIVATE:
		break;
	case OTRL_MSGEVENT_RCVDMSG_UNREADABLE:
		break;
	case OTRL_MSGEVENT_RCVDMSG_MALFORMED:
		break;
	case OTRL_MSGEVENT_LOG_HEARTBEAT_RCVD:
		break;
	case OTRL_MSGEVENT_LOG_HEARTBEAT_SENT:
		break;
	case OTRL_MSGEVENT_RCVDMSG_GENERAL_ERR:
		break;
	case OTRL_MSGEVENT_RCVDMSG_UNENCRYPTED:
		IRSSI_WARN(server, username,
				"Following message was NOT encrypted: [%s]", message);
		break;
	case OTRL_MSGEVENT_RCVDMSG_UNRECOGNIZED:
		break;
	case OTRL_MSGEVENT_RCVDMSG_FOR_OTHER_INSTANCE:
		break;
	}

	otr_debug(server, username, TXT_OPS_HANDLE_MSG,
			otr_msg_event_txt[msg_event], message);
}

/*
 * A context changed. I believe this is not happening for the SMP expects.
 */
static void ops_up_ctx_list(void *opdata)
{
	otr_status_change(opdata, NULL, IO_STC_CTX_UPDATE);
}

/*
 * Save fingerprint changes.
 */
static void ops_write_fingerprints(void *data)
{
	IRC_CTX *irssi __attribute__((unused)) = data;

	key_write_fingerprints(IRSSI_IO_US(irssi));
}

static int ops_is_logged_in(void *opdata, const char *accountname,
		const char *protocol, const char *recipient)
{
	/*TODO register a handler for event 401 no such nick and set
	 * a variable offline=TRUE. Reset it to false in otr_receive and
	 * otr_send */
	return TRUE;
}

static void ops_create_instag(void *opdata, const char *accountname,
		const char *protocol)
{
	otrl_instag_generate(IRSSI_IO_US(irssi)->otr_state, "/dev/null",
			accountname, protocol);
	otr_writeinstags(IRSSI_IO_US(irssi));
}

static void ops_smp_event(void *opdata, OtrlSMPEvent smp_event,
		ConnContext *context, unsigned short progress_percent, char *question)
{
	IRC_CTX *irssi = (IRC_CTX *) opdata;
	const char *from = context->username;
	struct irssi_otr_context *ioc = context->app_data;

	ioc->received_smp_init =
		(smp_event == OTRL_SMPEVENT_ASK_FOR_SECRET) ||
		(smp_event == OTRL_SMPEVENT_ASK_FOR_ANSWER);

	switch (smp_event) {
	case OTRL_SMPEVENT_ASK_FOR_SECRET:
		otr_notice(irssi, from, TXT_AUTH_PEER, from);
		otr_status_change(irssi, from, IO_STC_SMP_INCOMING);
		break;
	case OTRL_SMPEVENT_ASK_FOR_ANSWER:
		otr_notice(irssi, from, TXT_AUTH_PEER_QA, from, question);
		otr_status_change(irssi, from, IO_STC_SMP_INCOMING);
		break;
	case OTRL_SMPEVENT_IN_PROGRESS:
		otr_notice(irssi, from, TXT_AUTH_PEER_REPLIED, from);
		otr_status_change(irssi, from, IO_STC_SMP_FINALIZE);
		break;
	case OTRL_SMPEVENT_SUCCESS:
		otr_notice(irssi, from, TXT_AUTH_SUCCESSFUL);
		otr_status_change(irssi, from, IO_STC_SMP_SUCCESS);
		break;
	case OTRL_SMPEVENT_ABORT:
		otr_abort_auth(context, irssi, from);
		otr_status_change(irssi, from, IO_STC_SMP_ABORTED);
		break;
	case OTRL_SMPEVENT_FAILURE:
	case OTRL_SMPEVENT_CHEATED:
	case OTRL_SMPEVENT_ERROR:
		otr_notice(irssi, from, TXT_AUTH_FAILED);
		otr_status_change(irssi, from, IO_STC_SMP_FAILED);
		break;
	default:
		otr_logst(MSGLEVEL_CRAP, "Received unknown SMP event");
		break;
	}
}

/*
 * Assign OTR message operations.
 */
OtrlMessageAppOps otr_ops = {
	ops_policy,
	ops_create_privkey,
	ops_is_logged_in,
	ops_inject_msg,
	ops_up_ctx_list,
	NULL, /* new_fingerprint */
	ops_write_fingerprints,
	ops_secure,
	ops_insecure,
	ops_still_secure,
	ops_max_msg,
	NULL, /* accoun_name */
	NULL, /* account_name_free */
	NULL, /* received_symkey */
	NULL, /* otr_error_message */
	NULL, /* otr_error_message_free */
	NULL, /* resent_msg_prefix */
	NULL, /* resent_msg_prefix_free */
	ops_smp_event,
	ops_handle_msg_event,
	ops_create_instag,
	NULL, /* convert_msg */
	NULL, /* convert_free */
	NULL, /* timer_control */
};
