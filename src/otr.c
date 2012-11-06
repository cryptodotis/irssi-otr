/*
 * Off-the-Record Messaging (OTR) modules for IRC
 *
 * Copyright (C) 2008  Uli Meis <a.sporto+bee@gmail.com>
 *               2012  David Goulet <dgoulet@ev0ke.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301,USA
 */

#include "key.h"

#include <gcrypt.h>

static const char *statusbar_txt[] = {
	"FINISHED",
	"TRUST_MANUAL",
	"TRUST_SMP",
	"SMP_ABORT",
	"SMP_STARTED",
	"SMP_RESPONDED",
	"SMP_INCOMING",
	"SMP_FINALIZE",
	"SMP_ABORTED",
	"PEER_FINISHED",
	"SMP_FAILED",
	"SMP_SUCCESS",
	"GONE_SECURE",
	"GONE_INSECURE",
	"CTX_UPDATE"
};

IOUSTATE ioustate_uniq = { 0, 0, 0 };

#ifdef HAVE_GREGEX_H
GRegex *regex_policies;
#endif

IOUSTATE *otr_init_user(char *user)
{
	IOUSTATE *ioustate = IO_CREATE_US(user);

	ioustate->otr_state = otrl_userstate_create();

	instag_load(ioustate);

	/* Load keys and fingerprints. */
	key_load(ioustate);
	key_load_fingerprints(ioustate);

	return ioustate;
}

void otr_free_user(IOUSTATE *ioustate)
{
	key_generation_abort(ioustate, TRUE);

	if (ioustate->otr_state) {
		key_write_fingerprints(ioustate);
		otrl_userstate_free(ioustate->otr_state);
		ioustate->otr_state = NULL;
	}

	otr_setpolicies(ioustate, "", FALSE);
	otr_setpolicies(ioustate, "", TRUE);
}

/*
 * init otr lib.
 */
void otr_lib_init()
{
	OTRL_INIT;

#ifdef HAVE_GREGEX_H
	regex_policies = g_regex_new(
			"([^,]+) (never|manual|handlews|opportunistic|always)(,|$)",
			0, 0, NULL);
#endif
}

/*
 * deinit otr lib.
 */
void otr_lib_uninit()
{
#ifdef HAVE_GREGEX_H
	g_regex_unref(regex_policies);
#endif
}

/*
 * Free our app data.
 */
static void context_free_app_info(void *data)
{
	struct co_info *coi = data;
	if (coi->msgqueue) {
		g_free(coi->msgqueue);
	}
	if (coi->ircctx) {
		IRCCTX_FREE(coi->ircctx);
	}
}

/*
 * Add app data to context. See struct co_info for details.
 */
static void context_add_app_info(void *data, ConnContext *co)
{
	IRC_CTX *ircctx = IRCCTX_DUP(data);
	struct co_info *coi;

	coi = g_malloc0(sizeof(struct co_info));
	if (coi == NULL) {
		goto end;
	}

	co->app_data = coi;
	co->app_data_free = context_free_app_info;

	coi->ircctx = ircctx;
	snprintf(coi->better_msg_two, sizeof(coi->better_msg_two),
			formats[TXT_OTR_BETTER_TWO].def, co->accountname);

end:
	return;
}

/*
 * Get a context from a pair.
 */
static ConnContext *get_otrl_context(const char *accname, const char *nick,
		int create, IRC_CTX *irssi_ctx)
{
	ConnContext *ctx = otrl_context_find(IRCCTX_IO_US(irssi_ctx)->otr_state,
			nick, accname, OTR_PROTOCOL_ID, OTRL_INSTAG_BEST, create, NULL,
			context_add_app_info, irssi_ctx);

	return ctx;
}

/*
 * Hand the given message to OTR.
 *
 * Return 0 if the message was successfully handled or else a negative value.
 */
int otr_send(IRC_CTX *ircctx, const char *msg, const char *to, char **otr_msg)
{
	gcry_error_t err;
	char accname[256];

	IRCCTX_ACCNAME(accname, ircctx);

	otr_logst(MSGLEVEL_CRAP, "%d: sending msg", time(NULL));

	err = otrl_message_sending(IRCCTX_IO_US(ircctx)->otr_state, &otr_ops,
		ircctx, accname, OTR_PROTOCOL_ID, to, OTRL_INSTAG_BEST, msg, NULL, otr_msg,
		OTRL_FRAGMENT_SEND_ALL_BUT_LAST, NULL, context_add_app_info, ircctx);
	if (err) {
		otr_notice(ircctx, to, TXT_SEND_FAILED, msg);
		goto error;
	}

	otr_logst(MSGLEVEL_CRAP, "%d: sent", time(NULL));

	return 0;

error:
	return -1;
}

struct ctxlist_ *otr_contexts(IOUSTATE *ioustate)
{
	ConnContext *context;
	Fingerprint *fprint;
	struct ctxlist_ *ctxlist = NULL, *ctxhead = NULL;
	struct fplist_ *fplist, *fphead;
	char fp[41];
	char *trust;
	int i;

	for (context = ioustate->otr_state->context_root; context;
			context = context->next) {
		if (!ctxlist) {
			ctxhead = ctxlist = g_malloc0(sizeof(struct ctxlist_));
		} else {
			ctxlist = ctxlist->next = g_malloc0(sizeof(struct ctxlist_));
		}

		switch (context->msgstate) {
		case OTRL_MSGSTATE_PLAINTEXT:
			ctxlist->state = STUNENCRYPTED;
			break;
		case OTRL_MSGSTATE_ENCRYPTED:
			ctxlist->state = STENCRYPTED;
			break;
		case OTRL_MSGSTATE_FINISHED:
			ctxlist->state = STFINISHED;
			break;
		default:
			ctxlist->state = STUNKNOWN;
			break;
		}

		ctxlist->username = context->username;
		ctxlist->accountname = context->accountname;

		fplist = fphead = NULL;
		for (fprint = context->fingerprint_root.next; fprint;
				fprint = fprint->next) {
			if (!fplist) {
				fphead = fplist = g_malloc0(sizeof(struct fplist_));
			} else {
				fplist = fplist->next = g_malloc0(sizeof(struct fplist_));
			}

			trust = fprint->trust ? : "";

			for (i = 0; i < 20; ++i) {
				sprintf(fp + i * 2, "%02x", fprint->fingerprint[i]);
			}
			fplist->fp = g_strdup(fp);
			if (*trust == '\0') {
				fplist->authby = NOAUTH;
			} else if (strncmp(trust, "smp", strlen("smp")) == 0) {
				fplist->authby = AUTHSMP;
			} else {
				fplist->authby = AUTHMAN;
			}
		}

		ctxlist->fplist = fphead;
	}

	return ctxhead;
}

/*
 * Get the OTR status of this conversation.
 */
int otr_getstatus(IRC_CTX *ircctx, const char *nick)
{
	int ret, code = 0;
	ConnContext *ctx;
	char accname[128];
	struct co_info *coi;

	IRCCTX_ACCNAME(accname, ircctx);

	if (!(ctx = get_otrl_context(accname, nick, FALSE, ircctx))) {
		code = IO_ST_PLAINTEXT;
		goto end;
	}

	coi = ctx->app_data;

	switch (ctx->msgstate) {
	case OTRL_MSGSTATE_PLAINTEXT:
		code = IO_ST_PLAINTEXT;
		break;
	case OTRL_MSGSTATE_ENCRYPTED:
	{
		int ex = ctx->smstate->nextExpected;

		switch (ex) {
		case OTRL_SMP_EXPECT1:
			if (coi->received_smp_init) {
				code = IO_ST_SMP_INCOMING;
			}
			break;
		case OTRL_SMP_EXPECT2:
			code = IO_ST_SMP_OUTGOING;
			break;
		case OTRL_SMP_EXPECT3:
		case OTRL_SMP_EXPECT4:
			code = IO_ST_SMP_FINALIZE;
			break;
		}

		ret = otrl_context_is_fingerprint_trusted(ctx->active_fingerprint);
		if (ret) {
			code |= IO_ST_TRUST_SMP;
		} else {
			code |= IO_ST_UNTRUSTED;
		}
		break;
	}
	case OTRL_MSGSTATE_FINISHED:
		code = IO_ST_FINISHED;
		break;
	default:
		otr_logst(MSGLEVEL_CRAP,
			"BUG Found! Please write us a mail and describe how you got here");
		code = IO_ST_UNKNOWN;
		break;
	}

end:
	return code;
}

/*
 * Finish the conversation.
 */
void otr_finish(IRC_CTX *ircctx, char *nick, const char *peername, int inquery)
{
	ConnContext *co;
	char accname[128];
	struct co_info *coi;
	char nickbuf[128];

	if (peername) {
		nick = nickbuf;
		ircctx = ircctx_by_peername(peername, nick);
		if (!ircctx) {
			goto end;
		}
	}

	IRCCTX_ACCNAME(accname, ircctx);

	if (!(co = get_otrl_context(accname, nick, FALSE, ircctx))) {
		if (inquery) {
			otr_noticest(TXT_CTX_NOT_FOUND, accname, nick);
		}
		goto end;
	}

	otrl_message_disconnect(IRCCTX_IO_US(ircctx)->otr_state, &otr_ops, ircctx,
			accname, OTR_PROTOCOL_ID, nick, co->their_instance);

	otr_status_change(ircctx, nick, IO_STC_FINISHED);

	if (inquery) {
		otr_info(ircctx, nick, TXT_CMD_FINISH, nick, IRCCTX_ADDR(ircctx));
	} else {
		otr_infost(TXT_CMD_FINISH, nick, IRCCTX_ADDR(ircctx));
	}

	coi = co->app_data;

	/* finish if /otr finish has been issued. Reset if
	 * we're called cause the query window has been closed. */
	if (coi) {
		coi->finished = inquery;
	}

	/* write the finished into the master as well */
	co = otrl_context_find(IRCCTX_IO_US(ircctx)->otr_state, nick, accname,
		OTR_PROTOCOL_ID, OTRL_INSTAG_MASTER, FALSE, NULL, NULL, NULL);
	if (co) {
		coi = co->app_data;
	}

end:
	return;
}

void otr_finishall(IOUSTATE *ioustate)
{
	ConnContext *context;
	int finished = 0;

	for (context = ioustate->otr_state->context_root; context;
			context = context->next) {
		struct co_info *coi = context->app_data;

		if (context->msgstate != OTRL_MSGSTATE_ENCRYPTED) {
			continue;
		}

		otrl_message_disconnect(ioustate->otr_state, &otr_ops, coi->ircctx,
					context->accountname, OTR_PROTOCOL_ID, context->username,
					context->their_instance);
		otr_status_change(coi->ircctx, context->username, IO_STC_FINISHED);

		otr_infost(TXT_CMD_FINISH, context->username,
				IRCCTX_ADDR(coi->ircctx));
		finished++;
	}

	if (!finished) {
		otr_infost(TXT_CMD_FINISHALL_NONE);
	}
}

/*
 * Trust our peer.
 */
void otr_trust(IRC_CTX *ircctx, char *nick, const char *peername)
{
	ConnContext *co;
	char accname[128];
	struct co_info *coi;
	char nickbuf[128];

	if (peername) {
		nick = nickbuf;
		ircctx = ircctx_by_peername(peername, nick);
		if (!ircctx) {
			goto end;
		}
	}

	IRCCTX_ACCNAME(accname, ircctx);

	if (!(co = get_otrl_context(accname, nick, FALSE, ircctx))) {
		otr_noticest(TXT_CTX_NOT_FOUND, accname, nick);
		goto end;
	}

	otrl_context_set_trust(co->active_fingerprint, "manual");
	otr_status_change(ircctx, nick, IO_STC_TRUST_MANUAL);

	coi = co->app_data;
	coi->smp_failed = FALSE;

	otr_notice(ircctx, nick, TXT_FP_TRUST, nick);

end:
	return;
}

/*
 * Abort any ongoing SMP authentication.
 */
void otr_abort_auth(ConnContext *co, IRC_CTX *ircctx, const char *nick)
{
	struct co_info *coi;

	coi = co->app_data;

	coi->received_smp_init = FALSE;

	otr_notice(ircctx, nick,
			co->smstate->nextExpected != OTRL_SMP_EXPECT1 ?
			TXT_AUTH_ABORTED_ONGOING : TXT_AUTH_ABORTED);

	otrl_message_abort_smp(IRCCTX_IO_US(ircctx)->otr_state, &otr_ops,
			ircctx, co);
	otr_status_change(ircctx, nick, IO_STC_SMP_ABORT);
}

/*
 * implements /otr authabort
 */
void otr_authabort(IRC_CTX *ircctx, char *nick, const char *peername)
{
	ConnContext *co;
	char accname[128];
	char nickbuf[128];

	if (peername) {
		nick = nickbuf;
		ircctx = ircctx_by_peername(peername, nick);
		if (!ircctx) {
			goto end;
		}
	}

	IRCCTX_ACCNAME(accname, ircctx);

	if (!(co = get_otrl_context(accname, nick, FALSE, ircctx))) {
		otr_noticest(TXT_CTX_NOT_FOUND, accname, nick);
		goto end;
	}

	otr_abort_auth(co, ircctx, nick);

end:
	return;
}

/*
 * Initiate or respond to SMP authentication.
 */
void otr_auth(IRC_CTX *ircctx, char *nick, const char *peername,
		const char *question, const char *secret)
{
	ConnContext *co;
	char accname[128];
	struct co_info *coi;
	char nickbuf[128];

	if (peername) {
		nick = nickbuf;
		ircctx = ircctx_by_peername(peername, nick);
		if (!ircctx) {
			goto end;
		}
	}

	IRCCTX_ACCNAME(accname, ircctx);

	if (!(co = get_otrl_context(accname, nick, FALSE, ircctx))) {
		otr_noticest(TXT_CTX_NOT_FOUND, accname, nick);
		goto end;
	}

	if (co->msgstate != OTRL_MSGSTATE_ENCRYPTED) {
		otr_notice(ircctx, nick, TXT_AUTH_NEEDENC);
		goto end;
	}

	coi = co->app_data;

	/* Aborting an ongoing auth */
	if (co->smstate->nextExpected != OTRL_SMP_EXPECT1) {
		otr_abort_auth(co, ircctx, nick);
	}

	coi->smp_failed = FALSE;

	/* reset trust level */
	if (co->active_fingerprint) {
		char *trust = co->active_fingerprint->trust;
		if (trust && (*trust != '\0')) {
			otrl_context_set_trust(co->active_fingerprint, "");
			key_write_fingerprints(IRCCTX_IO_US(ircctx));
		}
	}

	if (!coi->received_smp_init) {
		if (question) {
			otrl_message_initiate_smp_q(IRCCTX_IO_US(ircctx)->otr_state,
				&otr_ops, ircctx, co, question, (unsigned char *) secret,
				strlen(secret));
		} else {
			otrl_message_initiate_smp(IRCCTX_IO_US(ircctx)->otr_state,
				&otr_ops, ircctx, co, (unsigned char *) secret,
				strlen(secret));
		}
		otr_status_change(ircctx, nick, IO_STC_SMP_STARTED);
	} else {
		otrl_message_respond_smp(IRCCTX_IO_US(ircctx)->otr_state, &otr_ops,
			ircctx, co, (unsigned char *) secret, strlen(secret));
		otr_status_change(ircctx, nick, IO_STC_SMP_RESPONDED);
	}

	otr_notice(ircctx, nick, coi->received_smp_init ?  TXT_AUTH_RESPONDING :
			TXT_AUTH_INITIATED);

end:
	return;
}

/*
 * Hand the given message to OTR.
 *
 * Returns 0 if its an OTR protocol message or else negative value.
 */
int otr_receive(IRC_CTX *ircctx, const char *msg, const char *from,
		char **new_msg)
{
	int ret = -1;
	char accname[256];
	OtrlTLV *tlvs;

	IRCCTX_ACCNAME(accname, ircctx);

	otr_logst(MSGLEVEL_CRAP, "%d: receiving...", time(NULL));

	ret = otrl_message_receiving(IRCCTX_IO_US(ircctx)->otr_state,
		&otr_ops, ircctx, accname, OTR_PROTOCOL_ID, from, msg, new_msg, &tlvs,
		NULL, context_add_app_info, ircctx);
	if (ret) {
		otr_debug(ircctx, from, TXT_RECEIVE_IGNORE, strlen(msg), accname, from,
				msg);
	} else {
		if (*new_msg) {
			otr_debug(ircctx, from, TXT_RECEIVE_CONVERTED);
		}
	}

	OtrlTLV *tlv = otrl_tlv_find(tlvs, OTRL_TLV_DISCONNECTED);
	if (tlv) {
		otr_status_change(ircctx, from, IO_STC_PEER_FINISHED);
		otr_notice(ircctx, from, TXT_PEER_FINISHED, from);
	}

	otrl_tlv_free(tlvs);

	otr_logst(MSGLEVEL_CRAP, "%d: received", time(NULL));

	return ret;
}

void otr_setpolicies(IOUSTATE *ioustate, const char *policies, int known)
{
#ifdef HAVE_GREGEX_H
	GMatchInfo *match_info;
	GSList *plist = known ? ioustate->plistknown : ioustate->plistunknown;

	if (plist) {
		GSList *p = plist;
		do {
			struct plistentry *ple = p->data;
			g_pattern_spec_free(ple->namepat);
			g_free(p->data);
		} while ((p = g_slist_next(p)));

		g_slist_free(plist);
		plist = NULL;
	}

	g_regex_match(regex_policies, policies, 0, &match_info);

	while (g_match_info_matches(match_info)) {
		struct plistentry *ple =
			(struct plistentry *) g_malloc0(sizeof(struct plistentry));
		char *pol = g_match_info_fetch(match_info, 2);

		ple->namepat = g_pattern_spec_new(g_match_info_fetch(match_info, 1));

		switch (*pol) {
		case 'n':
			ple->policy = OTRL_POLICY_NEVER;
			break;
		case 'm':
			ple->policy = OTRL_POLICY_MANUAL;
			break;
		case 'h':
			ple->policy = OTRL_POLICY_MANUAL | OTRL_POLICY_WHITESPACE_START_AKE;
			break;
		case 'o':
			ple->policy = OTRL_POLICY_OPPORTUNISTIC;
			break;
		case 'a':
			ple->policy = OTRL_POLICY_ALWAYS;
			break;
		}

		plist = g_slist_append(plist, ple);

		g_free(pol);

		g_match_info_next(match_info, NULL);
	}

	g_match_info_free(match_info);

	if (known)
		ioustate->plistknown = plist;
	else
		ioustate->plistunknown = plist;
#endif
}

/*
 * Get a format describing the OTR status of this conversation.
 */
int otr_getstatus_format(IRC_CTX *ircctx, const char *nick)
{
	int status = otr_getstatus(ircctx, nick);

	if (status & (IO_ST_SMP_ONGOING)) {
		/* we don't care about the trust level in that case */
		status = status & IO_ST_SMP_ONGOING;
	}

	switch (status) {
	case IO_ST_PLAINTEXT:
		return TXT_ST_PLAINTEXT;
	case IO_ST_FINISHED:
		return TXT_ST_FINISHED;
	case IO_ST_UNTRUSTED:
		return TXT_ST_UNTRUSTED;
	case IO_ST_SMP_INCOMING:
		return TXT_ST_SMP_INCOMING;
	case IO_ST_SMP_OUTGOING:
		return TXT_ST_SMP_OUTGOING;
	case IO_ST_SMP_FINALIZE:
		return TXT_ST_SMP_FINALIZE;
	case IO_ST_TRUST_MANUAL:
		return TXT_ST_TRUST_MANUAL;
	case IO_ST_TRUST_SMP:
		return TXT_ST_TRUST_SMP;
	default:
		return TXT_ST_SMP_UNKNOWN;
	}
}

/*
 * Change status bar text for a given nickname.
 */
void otr_status_change(IRC_CTX *ircctx, const char *nick,
		enum statusbar_event event)
{
	statusbar_items_redraw("otr");
	signal_emit("otr event", 3, ircctx, nick, statusbar_txt[event]);
}
