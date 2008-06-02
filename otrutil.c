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

#include "otr.h"

#include <gcrypt.h>

OtrlUserState otr_state = NULL;
extern OtrlMessageAppOps otr_ops;
static int otrinited = FALSE;

/*
 * init otr lib.
 */
int otrlib_init()
{

	if (!otrinited) {
		OTRL_INIT;
		otrinited = TRUE;
	}

	otr_state = otrl_userstate_create();

	/* load keys and fingerprints */

	key_load();
	fps_load();

	otr_initops();

	return otr_state==NULL;
}

/*
 * deinit otr lib.
 */
void otrlib_deinit()
{
	if (otr_state) {
		otr_writefps();
		otrl_userstate_free(otr_state);
		otr_state = NULL;
	}

	keygen_abort();
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
}

/*
 * Add app data to context.
 * See struct co_info for details.
 */
void context_add_app_info(void *data,ConnContext *co)
{
	SERVER_REC *server = data;
	struct co_info *coi = g_malloc(sizeof(struct co_info));

	memset(coi,0,sizeof(struct co_info));
	co->app_data = coi;
	co->app_data_free = context_free_app_info;

	coi->server = server;
	sprintf(coi->better_msg_two,formats[TXT_OTR_BETTER_TWO].def,co->accountname);
}

/*
 * Get a context from a pair.
 */
ConnContext *otr_getcontext(const char *accname,const char *nick,
			    int create,void *data)
{
	ConnContext *co = otrl_context_find(
		otr_state,
		nick,
		accname,
		PROTOCOLID,
		create,
		NULL,
		context_add_app_info,
		data);

	/* context came from a fingerprint */
	if (co&&data&&!co->app_data)
		context_add_app_info(data,co);

	return co;
}

/*
 * Hand the given message to OTR.
 * Returns NULL if OTR handled the message and 
 * the original message otherwise.
 */
char *otr_send(SERVER_REC *server, const char *msg,const char *to)
{
	const char *nick = server->nick;
	const char *address = server->connrec->address;
	gcry_error_t err;
	char *newmessage = NULL;
	ConnContext *co;
	char accname[256];

	sprintf(accname, "%s@%s", nick, address);

	err = otrl_message_sending(
		otr_state, 
		&otr_ops, 
		NULL, 
		accname,
		PROTOCOLID, 
		to, 
		msg, 
		NULL, 
		&newmessage, 
		context_add_app_info, 
		server);

	if (err != 0) {
		otr_notice(server,to,TXT_SEND_FAILED,msg);
		return NULL;
	}

	if (newmessage==NULL)
		return (char*)msg;

	/* OTR message. Need to do fragmentation */

	if (!(co = otr_getcontext(accname,to,FALSE,server))) {
		otr_notice(server,to,TXT_SEND_CHANGE);
		return NULL;
	}

	err = otrl_message_fragment_and_send(
		&otr_ops, 
		NULL, 
		co,
		newmessage, 
		OTRL_FRAGMENT_SEND_ALL, 
		NULL);

	if (err != 0) {
		otr_notice(server,to,TXT_SEND_FRAGMENT,msg);
	} else
		otr_debug(server,to,TXT_SEND_CONVERTED,newmessage);

	return NULL;
}

/*
 * Get the OTR status of this conversation.
 * This wouldn't be half as long if the SMP state machine would work better.
 */
int otr_getstatus(char *mynick, char *nick, char *server)
{
	ConnContext *co;
	char accname[128];
	struct co_info *coi;

	sprintf(accname, "%s@%s", mynick, server);

	if (!(co = otr_getcontext(accname,nick,FALSE,NULL))) {
		return 0;
	}

	coi = co->app_data;

	switch (co->msgstate) {
	case OTRL_MSGSTATE_PLAINTEXT:
		return TXT_ST_PLAINTEXT;
	case OTRL_MSGSTATE_ENCRYPTED: {
		char *trust = co->active_fingerprint->trust;
		int ex = co->smstate->nextExpected;

		if (trust&&(*trust!='\0'))
			return strcmp(trust,"smp")==0 ? TXT_ST_TRUST_SMP : TXT_ST_TRUST_MANUAL;

		switch (ex) {
		case OTRL_SMP_EXPECT1:
			return TXT_ST_UNTRUSTED;
		case OTRL_SMP_EXPECT2:
			if (!coi->received_smp_reply)
				return TXT_ST_SMP_WAIT_2;
			else
				return TXT_ST_SMP_HAVE_2;
		case OTRL_SMP_EXPECT3: 
			/* unfortunately, this also covers the case 
			 * where authentication failed */
			return coi->smp_failed ? 
				TXT_ST_SMP_FAILED : TXT_ST_SMP_FINALIZE;
		case OTRL_SMP_EXPECT4: /* unreachable with libotr 3.1 */
			return TXT_ST_SMP_FINALIZE;
		default:
			return TXT_ST_SMP_UNKNOWN;
		}
	}
	case OTRL_MSGSTATE_FINISHED:
		return TXT_ST_FINISHED;
	default:
		return TXT_ST_UNKNOWN;
	}
}

/*
 * Trust our peer.
 */
void otr_trust(SERVER_REC *server, char *nick)
{
	ConnContext *co;
	char accname[128];

	sprintf(accname, "%s@%s", server->nick, server->connrec->address);

	if (!(co = otr_getcontext(accname,nick,FALSE,NULL))) {
		otr_noticest(TXT_CTX_NOT_FOUND,
			     accname,nick);
		return;
	}

	otrl_context_set_trust(co->active_fingerprint,"manual");

	otr_notice(server,nick,TXT_FP_TRUST,accname);
}

/*
 * Abort any ongoing SMP authentication.
 */
void otr_abort_auth(ConnContext *co, SERVER_REC *server, const char *nick)
{
	struct co_info *coi;

	coi = co->app_data;

	coi->received_smp_reply = FALSE;
	coi->received_smp_init = FALSE;
	coi->smp_failed = FALSE;

	otrl_message_abort_smp(otr_state,&otr_ops,NULL,co);

	otr_notice(server,nick,
		   co->smstate->nextExpected!=OTRL_SMP_EXPECT1 ? 
		   TXT_AUTH_ABORTED_ONGOING :
		   TXT_AUTH_ABORTED);
}

/*
 * implements /otr authabort
 */
void otr_authabort(SERVER_REC *server, char *nick)
{
	ConnContext *co;
	char accname[128];

	sprintf(accname, "%s@%s", server->nick, server->connrec->address);

	if (!(co = otr_getcontext(accname,nick,FALSE,NULL))) {
		otr_noticest(TXT_CTX_NOT_FOUND,
			     accname,nick);
		return;
	}

	otr_abort_auth(co,server,nick);
}

/*
 * Initiate or respond to SMP authentication.
 */
void otr_auth(SERVER_REC *server, char *nick, const char *secret)
{
	ConnContext *co;
	char accname[128];
	struct co_info *coi;

	sprintf(accname, "%s@%s", server->nick, server->connrec->address);

	if (!(co = otr_getcontext(accname,nick,FALSE,NULL))) {
		otr_noticest(TXT_CTX_NOT_FOUND,
			     accname,nick);
		return;
	}

	coi = co->app_data;

	/* Aborting an ongoing auth */
	if (co->smstate->nextExpected!=OTRL_SMP_EXPECT1)
		otr_abort_auth(co,server,nick);

	/* reset trust level */
	otrl_context_set_trust(co->active_fingerprint, "");
	otr_writefps();

	if (!coi->received_smp_init)
		otrl_message_initiate_smp(
			otr_state, 
			&otr_ops,
			NULL,
			co,
			(unsigned char*)secret,
			strlen(secret));
	else
		otrl_message_respond_smp(
			otr_state,
			&otr_ops,
			NULL,
			co,
			(unsigned char*)secret,
			strlen(secret));

	otr_notice(server,nick,coi->received_smp_init ? 
		   TXT_AUTH_RESPONDING : 
		   TXT_AUTH_INITIATED);
	statusbar_items_redraw("otr");
}

/*
 * Hand the given message to OTR.
 * Returns NULL if its an OTR protocol message and 
 * the (possibly) decrypted message otherwise.
 */
char *otr_receive(SERVER_REC *server, const char *msg,const char *from)
{
	int ignore_message;
	char *newmessage = NULL;
	char accname[256];
	char *lastmsg;
	ConnContext *co;
	struct co_info *coi;
	OtrlTLV *tlvs;

	sprintf(accname, "%s@%s", server->nick, server->connrec->address);

	if (!(co = otr_getcontext(accname,from,TRUE,server))) {
		otr_noticest(TXT_CTX_NOT_CREATE,
			     accname,from);
		return NULL;
	}

	coi = co->app_data;

	/* Really lame but I don't see how you could do this in a generic
	 * way unless the IRC server would somehow marks continuation messages.
	 */
	if ((strcmp(msg,coi->better_msg_two)==0)||
	    (strcmp(msg,formats[TXT_OTR_BETTER_THREE].def)==0)) {
		otr_debug(server,from,TXT_RECEIVE_IGNORE_QUERY);
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
		if ((strlen(msg)>OTR_MAX_MSG_SIZE)&&msg[strlen(msg)-1]!='.')
			return NULL;

		otr_debug(server,from,TXT_RECEIVE_DEQUEUED,
			  strlen(coi->msgqueue));

		msg = coi->msgqueue;
		coi->msgqueue = NULL;

		/* this is freed thru our caller by otrl_message_free.
		 * Currently ok since that just uses free().
		 */

	} else if (strstr(msg,"?OTR:")&&
		   (strlen(msg)>OTR_MAX_MSG_SIZE)&&
		   msg[strlen(msg)-1]!='.') {
		coi->msgqueue = malloc(4096*sizeof(char));
		strcpy(coi->msgqueue,msg);
		otr_debug(server,from,TXT_RECEIVE_QUEUED,strlen(msg));
		return NULL;
	}

	ignore_message = otrl_message_receiving(
		otr_state,
		&otr_ops,
		NULL,
		accname, 
		PROTOCOLID, 
		from, 
		msg, 
		&newmessage,
		&tlvs,
		NULL,
		NULL);

	if (tlvs) {
		OtrlTLV *tlv = otrl_tlv_find(tlvs, OTRL_TLV_SMP1);
		int abort = FALSE;
		if (tlv) {
			if (co->smstate->nextExpected != OTRL_SMP_EXPECT1) {
				otr_notice(server,from,TXT_AUTH_HAVE_OLD,
					   accname);
				abort = TRUE;
			} else {
				otr_notice(server,from,TXT_AUTH_PEER,
					   accname);
				coi->received_smp_init = TRUE;
			}
		} else
			coi->received_smp_init = FALSE;
		tlv = otrl_tlv_find(tlvs, OTRL_TLV_SMP2);
		if (tlv) {
			if (co->smstate->nextExpected != OTRL_SMP_EXPECT2) {
				otr_notice(server,from,
					   TXT_AUTH_PEER_REPLY_WRONG,
					   accname);
				abort = TRUE;
			} else {
				otr_notice(server,from,
					   TXT_AUTH_PEER_REPLIED,
					   accname);
				coi->received_smp_reply = TRUE;
			}
		} else
			coi->received_smp_reply = FALSE;
		tlv = otrl_tlv_find(tlvs, OTRL_TLV_SMP3);
		if (tlv) {
			if (co->smstate->nextExpected != OTRL_SMP_EXPECT3) {
				otr_notice(server,from,TXT_AUTH_PEER_WRONG_SMP3,accname);
				abort = TRUE;
			} else {
				char *trust = co->active_fingerprint->trust;
				if (trust&&(*trust!='\0'))
					otr_notice(server,from,
						   TXT_AUTH_SUCCESSFUL,
						   accname);
				else {
					otr_notice(server,from,
						   TXT_AUTH_FAILED,
						   accname);
					coi->smp_failed = TRUE;
				}
			}
		} else
			coi->smp_failed = FALSE;

		if (abort)
			otr_abort_auth(co,server,from);

		statusbar_items_redraw("otr");
	}

	if (ignore_message) {
		otr_debug(server,from,
			  TXT_RECEIVE_IGNORE, strlen(msg),accname,from);
		return NULL;
	}

	if (newmessage)
		otr_debug(server,from,TXT_RECEIVE_CONVERTED);

	return newmessage ? : (char*)msg;
}
