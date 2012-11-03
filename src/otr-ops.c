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

#include "key.h"

OtrlPolicy IO_DEFAULT_OTR_POLICY =
	OTRL_POLICY_MANUAL | OTRL_POLICY_WHITESPACE_START_AKE;

/*
 * Return policy for given context based on the otr_policy /setting
 */
static OtrlPolicy ops_policy(void *opdata, ConnContext *context)
{
	int ret;
	struct co_info *coi = context->app_data;
	char *server = strchr(context->accountname, '@') + 1;
	OtrlPolicy op = IO_DEFAULT_OTR_POLICY;
	GSList *pl;
	char fullname[1024];
	IOUSTATE *ioustate = IRCCTX_IO_US(coi->ircctx);

	ret = snprintf(fullname, sizeof(fullname), "%s@%s", context->username,
			server);
	if (ret < 0) {
		perror("snprintf ops policy");
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

	if (coi && coi->finished &&
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
	IRC_CTX *ircctx __attribute__((unused)) = opdata;

	key_generation_run(IRCCTX_IO_US(ircctx), accountname);
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

#if 0
/*
 * OTR notification. Haven't seen one yet.
 */
static void ops_notify(void *opdata, OtrlNotifyLevel level, const char *accountname,
		const char *protocol, const char *username,
		const char *title, const char *primary,
		const char *secondary)
{
	ConnContext *co = otr_getcontext(accountname, username, FALSE, NULL);
	IRC_CTX *server = opdata;
	struct co_info *coi;
	if (co) {
		coi = co->app_data;
		server = coi->ircctx;
	} else
		otr_notice(server, username, TXT_OPS_NOTIFY_BUG);

	otr_notice(server, username, TXT_OPS_NOTIFY,
		   title, primary, secondary);
}
#endif /* disabled */

#if 0
#ifdef HAVE_GREGEX_H
/* This is kind of messy. */
const char *convert_otr_msg(const char *msg)
{
	GRegex *regex_bold = g_regex_new("</?i([ /][^>]*)?>", 0, 0, NULL);
	GRegex *regex_del = g_regex_new("</?b([ /][^>]*)?>", 0, 0, NULL);
	gchar *msgnohtml = g_regex_replace_literal(regex_del, msg, -1, 0, "", 0,
			NULL);

	msg = g_regex_replace_literal(regex_bold, msgnohtml, -1, 0, "*", 0, NULL);

	g_free(msgnohtml);
	g_regex_unref(regex_del);
	g_regex_unref(regex_bold);

	return msg;
}
#endif /* HAVE_GREGEX_H */

/*
 * OTR message. E.g. "following has been transmitted in clear: ...".
 * We're trying to kill the ugly HTML.
 */
static int ops_display_msg(void *opdata, const char *accountname,
		    const char *protocol, const char *username,
		    const char *msg)
{
	ConnContext *co = otr_getcontext(accountname, username, FALSE, opdata);
	IRC_CTX *server = opdata;
	struct co_info *coi;

	if (co) {
		coi = co->app_data;
		server = coi->ircctx;
	} else
		otr_notice(server, username, TXT_OPS_DISPLAY_BUG);

#ifdef HAVE_GREGEX_H
	msg = convert_otr_msg(msg);
	otr_notice(server, username, TXT_OPS_DISPLAY, msg);
	g_free((char*)msg);
#else
	otr_notice(server, username, TXT_OPS_DISPLAY, msg);
#endif

	return 0;
}
#endif /* disabled */

/*
 * Gone secure.
 */
static void ops_secure(void *opdata, ConnContext *context)
{
	struct co_info *coi = context->app_data;
	char * trust = context->active_fingerprint->trust ? : "";
	char ownfp[45], peerfp[45];

	otr_notice(coi->ircctx, context->username, TXT_OPS_SEC);
	otr_status_change(coi->ircctx, context->username, IO_STC_GONE_SECURE);

	//TODO: pull master context
	coi->finished = FALSE;

	if (*trust != '\0') {
		goto end;
	}

	/*
	 * Not authenticated. Let's print out the fingerprints for comparison.
	 */
	otrl_privkey_hash_to_human(peerfp,
			context->active_fingerprint->fingerprint);

	otr_notice(coi->ircctx, context->username, TXT_OPS_FPCOMP,
			otrl_privkey_fingerprint(IRCCTX_IO_US(coi->ircctx)->otr_state,
				ownfp, context->accountname, PROTOCOLID), context->username,
			peerfp);

end:
	return;
}

/*
 * Gone insecure.
 */
static void ops_insecure(void *opdata, ConnContext *context)
{
	struct co_info *coi = context->app_data;
	otr_notice(coi->ircctx, context->username, TXT_OPS_INSEC);
	otr_status_change(coi->ircctx, context->username, IO_STC_GONE_INSECURE);
}

/*
 * Still secure? Need to find out what that means...
 */
static void ops_still_secure(void *opdata, ConnContext *context, int is_reply)
{
	struct co_info *coi = context->app_data;
	otr_notice(coi->ircctx, context->username,
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
	IRC_CTX *ircctx __attribute__((unused)) = data;

	key_write_fingerprints(IRCCTX_IO_US(ircctx));
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
	otrl_instag_generate(IRCCTX_IO_US(ircctx)->otr_state, "/dev/null",
			accountname, protocol);
	otr_writeinstags(IRCCTX_IO_US(ircctx));
}

static void ops_smp_event(void *opdata, OtrlSMPEvent smp_event,
		ConnContext *context, unsigned short progress_percent, char *question)
{
	IRC_CTX *ircctx = (IRC_CTX *) opdata;
	const char *from = context->username;
	struct co_info *coi = context->app_data;

	coi->received_smp_init =
		(smp_event == OTRL_SMPEVENT_ASK_FOR_SECRET) ||
		(smp_event == OTRL_SMPEVENT_ASK_FOR_ANSWER);

	switch (smp_event) {
	case OTRL_SMPEVENT_ASK_FOR_SECRET:
		otr_notice(ircctx, from, TXT_AUTH_PEER, from);
		otr_status_change(ircctx, from, IO_STC_SMP_INCOMING);
		break;
	case OTRL_SMPEVENT_ASK_FOR_ANSWER:
		otr_notice(ircctx, from, TXT_AUTH_PEER_QA, from, question);
		otr_status_change(ircctx, from, IO_STC_SMP_INCOMING);
		break;
	case OTRL_SMPEVENT_IN_PROGRESS:
		otr_notice(ircctx, from, TXT_AUTH_PEER_REPLIED, from);
		otr_status_change(ircctx, from, IO_STC_SMP_FINALIZE);
		break;
	case OTRL_SMPEVENT_SUCCESS:
		otr_notice(ircctx, from, TXT_AUTH_SUCCESSFUL);
		otr_status_change(ircctx, from, IO_STC_SMP_SUCCESS);
		break;
	case OTRL_SMPEVENT_ABORT:
		otr_abort_auth(context, ircctx, from);
		otr_status_change(ircctx, from, IO_STC_SMP_ABORTED);
		break;
	case OTRL_SMPEVENT_FAILURE:
	case OTRL_SMPEVENT_CHEATED:
	case OTRL_SMPEVENT_ERROR:
		otr_notice(ircctx, from, TXT_AUTH_FAILED);
		coi->smp_failed = TRUE;
		otr_status_change(ircctx, from, IO_STC_SMP_FAILED);
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
