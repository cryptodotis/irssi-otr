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

#include "otr.h"

#include <gcrypt.h>

extern OtrlMessageAppOps otr_ops;
static int otrinited = FALSE;

#ifdef TARGET_BITLBEE
GHashTable *ioustates;
#else
IOUSTATE ioustate_uniq = { 0,0,0 };
#endif

#ifdef HAVE_GREGEX_H
GRegex *regex_policies;
#endif

IOUSTATE *otr_init_user(char *user)
{
	IOUSTATE *ioustate = IO_CREATE_US(user);

	ioustate->otr_state = otrl_userstate_create();

	/* load keys and fingerprints */

	key_load(ioustate);
	fps_load(ioustate);

	return ioustate;
}

void otr_deinit_user(IOUSTATE *ioustate)
{
	keygen_abort(ioustate,TRUE);

	if (ioustate->otr_state) {
		otr_writefps(ioustate);
		otrl_userstate_free(ioustate->otr_state);
		ioustate->otr_state = NULL;
	}
	otr_setpolicies(ioustate,"",FALSE);
	otr_setpolicies(ioustate,"",TRUE);
}

/*
 * init otr lib.
 */
int otrlib_init()
{
	if (!otrinited) {
		OTRL_INIT;
		otrinited = TRUE;
	}

#ifdef TARGET_BITLBEE
	ioustates = g_hash_table_new_full(g_str_hash,g_str_equal,g_free,otr_deinit_user);
#endif

	otr_initops();

#ifdef HAVE_GREGEX_H
	regex_policies = 
		g_regex_new("([^,]+) (never|manual|handlews|opportunistic|always)"
			    "(,|$)",0,0,NULL);
#endif

	return 0;
}

/*
 * deinit otr lib.
 */
void otrlib_deinit()
{
#ifdef HAVE_GREGEX_H
	g_regex_unref(regex_policies);
#endif

#ifdef TARGET_BITLBEE
	g_hash_table_destroy(ioustates);
#endif
}


/*
 * Free our app data.
 */
void context_free_app_info(void *data)
{
	struct co_info *coi = data;
	if (coi->msgqueue) {
		g_free(coi->msgqueue);
	}
	if (coi->ircctx)
		IRCCTX_FREE(coi->ircctx);
}

/*
 * Add app data to context.
 * See struct co_info for details.
 */
void context_add_app_info(void *data,ConnContext *co)
{
	IRC_CTX *ircctx = IRCCTX_DUP(data);
	struct co_info *coi = g_malloc(sizeof(struct co_info));

	memset(coi,0,sizeof(struct co_info));
	co->app_data = coi;
	co->app_data_free = context_free_app_info;

	coi->ircctx = ircctx;
	sprintf(coi->better_msg_two,formats[TXT_OTR_BETTER_TWO].def,co->accountname);
}

/*
 * Get a context from a pair.
 */
ConnContext *otr_getcontext(const char *accname,const char *nick,
			    int create,IRC_CTX *ircctx)
{
	ConnContext *co = otrl_context_find(
		IRCCTX_IO_US(ircctx)->otr_state,
		nick,
		accname,
		PROTOCOLID,
		create,
		NULL,
		context_add_app_info,
		ircctx);

	/* context came from a fingerprint */
	if (co&&ircctx&&!co->app_data)
		context_add_app_info(ircctx,co);

	return co;
}

/*
 * Hand the given message to OTR.
 * Returns NULL if OTR handled the message and 
 * the original message otherwise.
 */
char *otr_send(IRC_CTX *ircctx, const char *msg,const char *to)
{
	gcry_error_t err;
	char *newmessage = NULL;
	ConnContext *co;
	char accname[256];

	IRCCTX_ACCNAME(accname,ircctx);

	err = otrl_message_sending(
		IRCCTX_IO_US(ircctx)->otr_state, 
		&otr_ops, 
		ircctx, 
		accname,
		PROTOCOLID, 
		to, 
		msg, 
		NULL, 
		&newmessage, 
		context_add_app_info, 
		ircctx);

	if (err != 0) {
		otr_notice(ircctx,to,TXT_SEND_FAILED,msg);
		return NULL;
	}

	if (newmessage==NULL)
		return (char*)msg;

	/* OTR message. Need to do fragmentation */

	if (!(co = otr_getcontext(accname,to,FALSE,ircctx))) {
		otr_notice(ircctx,to,TXT_SEND_CHANGE);
		return NULL;
	}

	err = otrl_message_fragment_and_send(
		&otr_ops, 
		ircctx, 
		co,
		newmessage, 
		OTRL_FRAGMENT_SEND_ALL, 
		NULL);

	if (err != 0) {
		otr_notice(ircctx,to,TXT_SEND_FRAGMENT,msg);
	} else
		otr_debug(ircctx,to,TXT_SEND_CONVERTED,newmessage);

	return NULL;
}

struct ctxlist_ *otr_contexts(IOUSTATE *ioustate)
{
	ConnContext *context;
	Fingerprint *fprint;
	struct ctxlist_ *ctxlist = NULL, *ctxhead = NULL;
	struct fplist_ *fplist,*fphead;
	char fp[41];
	char *trust;
	int i;

	for(context = ioustate->otr_state->context_root; context; 
	    context = context->next) {
		if (!ctxlist)
			ctxhead = ctxlist = g_malloc0(sizeof(struct ctxlist_));
		else
			ctxlist = ctxlist->next = g_malloc0(sizeof(struct
								  ctxlist_));
		switch (context->msgstate) {
		case OTRL_MSGSTATE_PLAINTEXT: ctxlist->state = STUNENCRYPTED;break;
		case OTRL_MSGSTATE_ENCRYPTED: ctxlist->state = STENCRYPTED;break;
		case OTRL_MSGSTATE_FINISHED: ctxlist->state = STFINISHED;break;
		default: ctxlist->state = STUNKNOWN;break;
		}
		ctxlist->username = context->username;
		ctxlist->accountname = context->accountname;

		fplist = fphead = NULL;
		for (fprint = context->fingerprint_root.next; fprint;
		     fprint = fprint->next) {
			if (!fplist)
				fphead = fplist = g_malloc0(sizeof(struct
								   fplist_));
			else
				fplist = fplist->next = g_malloc0(sizeof(struct
									 fplist_));
			trust = fprint->trust ? : "";
			for(i=0;i<20;++i)
				sprintf(fp+i*2, "%02x",
					     fprint->fingerprint[i]);
			fplist->fp = g_strdup(fp);
			if (*trust=='\0')
				fplist->authby = NOAUTH;
			else if (strcmp(trust,"smp")==0)
				fplist->authby = AUTHSMP;
			else 
				fplist->authby = AUTHMAN;
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
	ConnContext *co;
	char accname[128];
	struct co_info *coi;

	IRCCTX_ACCNAME(accname,ircctx);

	if (!(co = otr_getcontext(accname,nick,FALSE,ircctx))) {
		return IO_ST_PLAINTEXT;
	}

	coi = co->app_data;

	switch (co->msgstate) {
	case OTRL_MSGSTATE_PLAINTEXT:
		return IO_ST_PLAINTEXT;
	case OTRL_MSGSTATE_ENCRYPTED: {
		char *trust = co->active_fingerprint->trust;
		int ex = co->smstate->nextExpected;
		int code=0;

		switch (ex) {
		case OTRL_SMP_EXPECT1:
			if (coi->received_smp_init)
				code = IO_ST_SMP_INCOMING;
			break;
		case OTRL_SMP_EXPECT2:
			code = IO_ST_SMP_OUTGOING;
			break;
		case OTRL_SMP_EXPECT3: 
		case OTRL_SMP_EXPECT4:
			code = IO_ST_SMP_FINALIZE;
			break;
		default:
			otr_logst(MSGLEVEL_CRAP,"BUG Found! Please write us a mail and describe how you got here");
			return IO_ST_UNKNOWN;
		}

		if (trust&&(*trust!='\0'))
			code |= strcmp(trust,"smp")==0 ? IO_ST_TRUST_SMP :
				IO_ST_TRUST_MANUAL;
		else
			code |= IO_ST_UNTRUSTED;

		return code;
	}
	case OTRL_MSGSTATE_FINISHED:
		return IO_ST_FINISHED;
	default:
		otr_logst(MSGLEVEL_CRAP,"BUG Found! Please write us a mail and describe how you got here");
		return IO_ST_UNKNOWN;
	}
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
		ircctx = ircctx_by_peername(peername,nick);
		if (!ircctx)
			return;
	}

	IRCCTX_ACCNAME(accname,ircctx);

	if (!(co = otr_getcontext(accname,nick,FALSE,ircctx))) {
		if (inquery)
			otr_noticest(TXT_CTX_NOT_FOUND,
				     accname,nick);
		return;
	}

	otrl_message_disconnect(IRCCTX_IO_US(ircctx)->otr_state,&otr_ops,ircctx,accname,
				PROTOCOLID,nick);
	otr_status_change(ircctx,nick,IO_STC_FINISHED);

	if (inquery) {
		otr_info(ircctx,nick,TXT_CMD_FINISH,nick,IRCCTX_ADDR(ircctx));
	} else {
		otr_infost(TXT_CMD_FINISH,nick,IRCCTX_ADDR(ircctx));
	}

	coi = co->app_data;

	/* finish if /otr finish has been issued. Reset if
	 * we're called cause the query window has been closed. */
	if (coi) 
		coi->finished = inquery;
}

void otr_finishall(IOUSTATE *ioustate)
{
	ConnContext *context;
	int finished=0;

	for(context = ioustate->otr_state->context_root; context; 
	    context = context->next) {
		struct co_info *coi = context->app_data;

		if (context->msgstate!=OTRL_MSGSTATE_ENCRYPTED)
			continue;

		otrl_message_disconnect(ioustate->otr_state,&otr_ops,coi->ircctx,
					context->accountname,
					PROTOCOLID,
					context->username);
		otr_status_change(coi->ircctx,context->username,IO_STC_FINISHED);

		otr_infost(TXT_CMD_FINISH,context->username,
			   IRCCTX_ADDR(coi->ircctx));
		finished++;
	}

	if (!finished)
		otr_infost(TXT_CMD_FINISHALL_NONE);
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
		ircctx = ircctx_by_peername(peername,nick);
		if (!ircctx)
			return;
	}

	IRCCTX_ACCNAME(accname,ircctx);

	if (!(co = otr_getcontext(accname,nick,FALSE,ircctx))) {
		otr_noticest(TXT_CTX_NOT_FOUND,
			     accname,nick);
		return;
	}

	otrl_context_set_trust(co->active_fingerprint,"manual");
	otr_status_change(ircctx,nick,IO_STC_TRUST_MANUAL);

	coi = co->app_data;
	coi->smp_failed = FALSE;

	otr_notice(ircctx,nick,TXT_FP_TRUST,nick);

}

/*
 * Abort any ongoing SMP authentication.
 */
void otr_abort_auth(ConnContext *co, IRC_CTX *ircctx, const char *nick)
{
	struct co_info *coi;

	coi = co->app_data;

	coi->received_smp_init = FALSE;

	otr_notice(ircctx,nick,
		   co->smstate->nextExpected!=OTRL_SMP_EXPECT1 ? 
		   TXT_AUTH_ABORTED_ONGOING :
		   TXT_AUTH_ABORTED);

	otrl_message_abort_smp(IRCCTX_IO_US(ircctx)->otr_state,&otr_ops,ircctx,co);
	otr_status_change(ircctx,nick,IO_STC_SMP_ABORT);
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
		ircctx = ircctx_by_peername(peername,nick);
		if (!ircctx)
			return;
	}

	IRCCTX_ACCNAME(accname,ircctx);

	if (!(co = otr_getcontext(accname,nick,FALSE,ircctx))) {
		otr_noticest(TXT_CTX_NOT_FOUND,
			     accname,nick);
		return;
	}

	otr_abort_auth(co,ircctx,nick);

}

/*
 * Initiate or respond to SMP authentication.
 */
void otr_auth(IRC_CTX *ircctx, char *nick, const char *peername, const char *secret)
{
	ConnContext *co;
	char accname[128];
	struct co_info *coi;
	char nickbuf[128];

	if (peername) {
		nick = nickbuf;
		ircctx = ircctx_by_peername(peername,nick);
		if (!ircctx)
			return;
	}

	IRCCTX_ACCNAME(accname,ircctx);

	if (!(co = otr_getcontext(accname,nick,FALSE,ircctx))) {
		otr_noticest(TXT_CTX_NOT_FOUND,
			     accname,nick);
		return;
	}

	if (co->msgstate!=OTRL_MSGSTATE_ENCRYPTED) {
		otr_notice(ircctx,nick,TXT_AUTH_NEEDENC);
		return;
	}

	coi = co->app_data;

	/* Aborting an ongoing auth */
	if (co->smstate->nextExpected!=OTRL_SMP_EXPECT1)
		otr_abort_auth(co,ircctx,nick);

	coi->smp_failed = FALSE;

	/* reset trust level */
	if (co->active_fingerprint) {
		char *trust = co->active_fingerprint->trust;
		if (trust&&(*trust!='\0')) {
			otrl_context_set_trust(co->active_fingerprint, "");
			otr_writefps(IRCCTX_IO_US(ircctx));
		}
	}

	if (!coi->received_smp_init) {
		otrl_message_initiate_smp(
			IRCCTX_IO_US(ircctx)->otr_state, 
			&otr_ops,
			ircctx,
			co,
			(unsigned char*)secret,
			strlen(secret));
		otr_status_change(ircctx,nick,IO_STC_SMP_STARTED);
	} else {
		otrl_message_respond_smp(
			IRCCTX_IO_US(ircctx)->otr_state,
			&otr_ops,
			ircctx,
			co,
			(unsigned char*)secret,
			strlen(secret));
		otr_status_change(ircctx,nick,IO_STC_SMP_RESPONDED);
	}

	otr_notice(ircctx,nick,
		   coi->received_smp_init ?
		   TXT_AUTH_RESPONDING :
		   TXT_AUTH_INITIATED);

}

/* 
 * Handles incoming TLVs of the SMP authentication type. We're not only updating
 * our own state but also giving libotr a leg up so it gets through the auth.
 */
void otr_handle_tlvs(OtrlTLV *tlvs, ConnContext *co, 
		     struct co_info *coi, 
		     IRC_CTX *ircctx, const char *from) 
{
	int abort = FALSE;

	OtrlTLV *tlv = otrl_tlv_find(tlvs, OTRL_TLV_SMP1);
	if (tlv) {
		if (co->smstate->nextExpected != OTRL_SMP_EXPECT1) {
			otr_notice(ircctx,from,TXT_AUTH_HAVE_OLD,
				   from);
			abort = TRUE;
		} else {
			otr_notice(ircctx,from,TXT_AUTH_PEER,
				   from);
			coi->received_smp_init = TRUE;
			otr_status_change(ircctx,from,IO_STC_SMP_INCOMING);
		}
	}

	tlv = otrl_tlv_find(tlvs, OTRL_TLV_SMP2);
	if (tlv) {
		if (co->smstate->nextExpected != OTRL_SMP_EXPECT2) {
			otr_notice(ircctx,from,
				   TXT_AUTH_PEER_REPLY_WRONG,
				   from);
			abort = TRUE;
		} else {
			otr_notice(ircctx,from,
				   TXT_AUTH_PEER_REPLIED,
				   from);
			co->smstate->nextExpected = OTRL_SMP_EXPECT4;
			otr_status_change(ircctx,from,IO_STC_SMP_FINALIZE);
		}
	}

	tlv = otrl_tlv_find(tlvs, OTRL_TLV_SMP3);
	if (tlv) {
		if (co->smstate->nextExpected != OTRL_SMP_EXPECT3) {
			otr_notice(ircctx,from,
				   TXT_AUTH_PEER_WRONG_SMP3,
				   from);
			abort = TRUE;
		} else {
			char *trust = co->active_fingerprint->trust;
			if (trust&&(*trust!='\0')) {
				otr_notice(ircctx,from,
					   TXT_AUTH_SUCCESSFUL);
				otr_status_change(ircctx,from,IO_STC_SMP_SUCCESS);
			} else {
				otr_notice(ircctx,from,
					   TXT_AUTH_FAILED);
				coi->smp_failed = TRUE;
				otr_status_change(ircctx,from,IO_STC_SMP_FAILED);
			}
			co->smstate->nextExpected = OTRL_SMP_EXPECT1;
			coi->received_smp_init = FALSE;
		}
	}

	tlv = otrl_tlv_find(tlvs, OTRL_TLV_SMP4);
	if (tlv) {
		if (co->smstate->nextExpected != OTRL_SMP_EXPECT4) {
			otr_notice(ircctx,from,
				   TXT_AUTH_PEER_WRONG_SMP4,
				   from);
			abort = TRUE;
		} else {
			char *trust = co->active_fingerprint->trust;
			if (trust&&(*trust!='\0')) {
				otr_notice(ircctx,from,
					   TXT_AUTH_SUCCESSFUL);
				otr_status_change(ircctx,from,IO_STC_SMP_SUCCESS);
			} else {
				/* unreachable since 4 is never sent out on
				 * error */
				otr_notice(ircctx,from,
					   TXT_AUTH_FAILED);
				coi->smp_failed = TRUE;
				otr_status_change(ircctx,from,IO_STC_SMP_FAILED);
			}
			co->smstate->nextExpected = OTRL_SMP_EXPECT1;
			coi->received_smp_init = FALSE;
		}
	}
	if (abort) {
		otr_abort_auth(co,ircctx,from);
		otr_status_change(ircctx,from,IO_STC_SMP_ABORTED);
	}

	tlv = otrl_tlv_find(tlvs, OTRL_TLV_DISCONNECTED);
	if (tlv) {
		otr_status_change(ircctx,from,IO_STC_PEER_FINISHED);
		otr_notice(ircctx,from,TXT_PEER_FINISHED,from);
	}

}

/*
 * Hand the given message to OTR.
 * Returns NULL if its an OTR protocol message and 
 * the (possibly) decrypted message otherwise.
 */
char *otr_receive(IRC_CTX *ircctx, const char *msg,const char *from)
{
	int ignore_message;
	char *newmessage = NULL;
	char accname[256];
	char *lastmsg;
	ConnContext *co;
	struct co_info *coi;
	OtrlTLV *tlvs;

	IRCCTX_ACCNAME(accname,ircctx);

	if (!(co = otr_getcontext(accname,from,TRUE,ircctx))) {
		otr_noticest(TXT_CTX_NOT_CREATE,
			     accname,from);
		return NULL;
	}

	coi = co->app_data;

	/* Really lame but I don't see how you could do this in a generic
	 * way unless the IRC server would somehow mark continuation messages.
	 */
	if ((strcmp(msg,coi->better_msg_two)==0)||
	    (strcmp(msg,formats[TXT_OTR_BETTER_THREE].def)==0)) {
		otr_debug(ircctx,from,TXT_RECEIVE_IGNORE_QUERY);
		return NULL;
	}

	/* The server might have split lines that were too long 
	 * (bitlbee does that). The heuristic is simple: If we can find ?OTR:
	 * in the message but it doesn't end with a ".", queue it and wait
	 * for the rest.
	 */
	lastmsg = co->app_data;

	if (coi->msgqueue) { /* already something in the queue */
		strcpy(coi->msgqueue+strlen(coi->msgqueue),msg);

		/* wait for more? */
		if ((strlen(msg)>OTR_MAX_MSG_SIZE)&&
		    (msg[strlen(msg)-1]!='.')&&
		    (msg[strlen(msg)-1]!=','))
			return NULL;

		otr_debug(ircctx,from,TXT_RECEIVE_DEQUEUED,
			  strlen(coi->msgqueue));

		msg = coi->msgqueue;
		coi->msgqueue = NULL;

		/* this is freed thru our caller by otrl_message_free.
		 * Currently ok since that just uses free().
		 */

	} else if (strstr(msg,"?OTR:")&&
		   (strlen(msg)>OTR_MAX_MSG_SIZE)&&
		   (msg[strlen(msg)-1]!='.')&&
		   (msg[strlen(msg)-1]!=',')) {
		coi->msgqueue = malloc(4096*sizeof(char));
		strcpy(coi->msgqueue,msg);
		otr_debug(ircctx,from,TXT_RECEIVE_QUEUED,strlen(msg));
		return NULL;
	}

	ignore_message = otrl_message_receiving(
		IRCCTX_IO_US(ircctx)->otr_state,
		&otr_ops,
		ircctx,
		accname, 
		PROTOCOLID, 
		from, 
		msg, 
		&newmessage,
		&tlvs,
		NULL,
		NULL);

	if (tlvs) 
		otr_handle_tlvs(tlvs,co,coi,ircctx,from);
	
	if (ignore_message) {
		otr_debug(ircctx,from,
			  TXT_RECEIVE_IGNORE, strlen(msg),accname,from,msg);
		return NULL;
	}

	if (newmessage)
		otr_debug(ircctx,from,TXT_RECEIVE_CONVERTED);

	return newmessage ? : (char*)msg;
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

	g_regex_match(regex_policies,policies,0,&match_info);

	while(g_match_info_matches(match_info)) {
		struct plistentry *ple = (struct plistentry *)g_malloc0(sizeof(struct plistentry));
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
			ple->policy = OTRL_POLICY_MANUAL|OTRL_POLICY_WHITESPACE_START_AKE;
			break;
		case 'o':
			ple->policy = OTRL_POLICY_OPPORTUNISTIC;
			break;
		case 'a':
			ple->policy = OTRL_POLICY_ALWAYS;
			break;
		}

		plist = g_slist_append(plist,ple);

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
