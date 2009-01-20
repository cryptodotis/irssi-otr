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

OtrlMessageAppOps otr_ops;
extern OtrlUserState otr_state;
extern GSList *plistunknown,*plistknown;

OtrlPolicy IO_DEFAULT_POLICY =
	OTRL_POLICY_MANUAL|OTRL_POLICY_WHITESPACE_START_AKE;

/*
 * Return policy for given context based on the otr_policy /setting
 */
OtrlPolicy ops_policy(void *opdata, ConnContext *context)
{
	struct co_info *coi = context->app_data;
	char *server = strchr(context->accountname,'@')+1;
	OtrlPolicy op = IO_DEFAULT_POLICY;
	GSList *pl;
	char fullname[1024];

	sprintf(fullname, "%s@%s", context->username, server);

	/* loop through otr_policy */

	if (plistunknown) {
		pl = plistunknown;
		do {
			struct plistentry *ple = pl->data;

			if (g_pattern_match_string(ple->namepat,fullname))
				op = ple->policy;

		} while ((pl = g_slist_next(pl)));
	}

	if (plistknown&&context->fingerprint_root.next) {
		pl = plistknown;

		/* loop through otr_policy_known */

		do {
			struct plistentry *ple = pl->data;

			if (g_pattern_match_string(ple->namepat,fullname))
				op = ple->policy;

		} while ((pl = g_slist_next(pl)));
	}

	if (coi && coi->finished &&
	    (op == OTRL_POLICY_OPPORTUNISTIC ||
	     op == OTRL_POLICY_ALWAYS))
		op = OTRL_POLICY_MANUAL|OTRL_POLICY_WHITESPACE_START_AKE;
	return op;
}

/*
 * Request for key generation.
 * The lib actually expects us to be finished before the call returns.
 * Since this can take more than an hour on some systems there isn't even
 * a point in trying...
 */
void ops_create_privkey(void *opdata, const char *accountname,
			const char *protocol)
{
	keygen_run(accountname);
}

/*
 * Inject OTR message.
 * Deriving the server is currently a hack,
 * need to derive the server from accountname.
 */
void ops_inject_msg(void *opdata, const char *accountname,
		    const char *protocol, const char *recipient, const char *message)
{
	SERVER_REC *a_serv;
	char *msgcopy = g_strdup(message);

	/* OTR sometimes gives us multiple lines 
	 * (e.g. the default query (a.k.a. "better") message) */
	g_strdelimit (msgcopy,"\n",' ');
	a_serv = opdata;
	if (!a_serv)
		otr_notice(a_serv,recipient,TXT_OPS_INJECT,
			   accountname,recipient,message);
	else
		a_serv->send_message(a_serv, recipient, msgcopy,
				     GPOINTER_TO_INT(SEND_TARGET_NICK));
	g_free(msgcopy);
}

/*
 * OTR notification. Haven't seen one yet.
 */
void ops_notify(void *opdata, OtrlNotifyLevel level, const char *accountname, 
		const char *protocol, const char *username, 
		const char *title, const char *primary, 
		const char *secondary)
{
	ConnContext *co = otr_getcontext(accountname,username,FALSE,NULL);
	SERVER_REC *server = opdata;
	struct co_info *coi;
	if (co) {
		coi = co->app_data;
		server = coi->server;
	} else 
		otr_notice(server,username,TXT_OPS_NOTIFY_BUG);

	otr_notice(server,username,TXT_OPS_NOTIFY,
		   title,primary,secondary);
}

#ifdef HAVE_GREGEX_H

/* This is kind of messy. */
const char *convert_otr_msg(const char *msg) 
{
	GRegex *regex_bold  = g_regex_new("</?i([ /][^>]*)?>",0,0,NULL);
	GRegex *regex_del   = g_regex_new("</?b([ /][^>]*)?>",0,0,NULL);
	gchar *msgnohtml = 
		g_regex_replace_literal(regex_del,msg,-1,0,"",0,NULL);

	msg = g_regex_replace_literal(regex_bold,msgnohtml,-1,0,"*",0,NULL);

	g_free(msgnohtml);
	g_regex_unref(regex_del);
	g_regex_unref(regex_bold);

	return msg;
}

#endif

/*
 * OTR message. E.g. "following has been transmitted in clear: ...".
 * We're trying to kill the ugly HTML.
 */
int ops_display_msg(void *opdata, const char *accountname, 
		    const char *protocol, const char *username, 
		    const char *msg)
{
	ConnContext *co = otr_getcontext(accountname,username,FALSE,opdata);
	SERVER_REC *server = opdata;
	struct co_info *coi;

	if (co) {
		coi = co->app_data;
		server = coi->server;
	} else 
		otr_notice(server,username,TXT_OPS_DISPLAY_BUG);

#ifdef HAVE_GREGEX_H
	msg = convert_otr_msg(msg);
	otr_notice(server,username,TXT_OPS_DISPLAY,msg);
	g_free((char*)msg);
#else
	otr_notice(server,username,TXT_OPS_DISPLAY,msg);
#endif

	return 0;
}

/* 
 * Gone secure.
 */
void ops_secure(void *opdata, ConnContext *context)
{
	struct co_info *coi = context->app_data;
	char * trust = context->active_fingerprint->trust ? : "";
	char ownfp[45],peerfp[45];

	otr_notice(coi->server,
		   context->username,TXT_OPS_SEC);
	if (*trust!='\0')
		return;

	/* not authenticated. 
	 * Let's print out the fingerprints for comparison */

	otrl_privkey_hash_to_human(peerfp,
				   context->active_fingerprint->fingerprint);

	otr_notice(coi->server,context->username,TXT_OPS_FPCOMP,
		   otrl_privkey_fingerprint(otr_state,
					    ownfp,
					    context->accountname,
					    PROTOCOLID),
		   context->username,
		   peerfp);
}

/*
 * Gone insecure.
 */
void ops_insecure(void *opdata, ConnContext *context)
{
	struct co_info *coi = context->app_data;
	otr_notice(coi->server,
		   context->username,TXT_OPS_INSEC);
}

/*
 * Still secure? Need to find out what that means...
 */
void ops_still_secure(void *opdata, ConnContext *context, int is_reply)
{
	struct co_info *coi = context->app_data;
	otr_notice(coi->server,
		   context->username,is_reply ?
		   TXT_OPS_STILL_REPLY :
		   TXT_OPS_STILL_NO_REPLY);
}

/*
 * OTR log message. IIRC heartbeats are of this category.
 */
void ops_log(void *opdata, const char *message)
{
	otr_infost(TXT_OPS_LOG,message);
}

/*
 * Really critical with IRC. 
 * Unfortunately, we can't tell our peer which size to use.
 * (reminds me of MTU determination...)
 */
int ops_max_msg(void *opdata, ConnContext *context)
{
	return OTR_MAX_MSG_SIZE;
}

/*
 * A context changed. 
 * I believe this is not happening for the SMP expects.
 */
void ops_up_ctx_list(void *opdata)
{
	statusbar_items_redraw("otr");
}

/*
 * Save fingerprint changes.
 */
void ops_writefps(void *data)
{
	otr_writefps();
}

int ops_is_logged_in(void *opdata, const char *accountname, 
		    const char *protocol, const char *recipient)
{
	/*TODO register a handler for event 401 no such nick and set
	 * a variable offline=TRUE. Reset it to false in otr_receive and
	 * otr_send */
	return TRUE;
}

/*
 * Initialize our OtrlMessageAppOps
 */
void otr_initops() {
	memset(&otr_ops,0,sizeof(otr_ops));

	otr_ops.policy = ops_policy;
	otr_ops.create_privkey = ops_create_privkey;
	otr_ops.inject_message = ops_inject_msg;
	otr_ops.notify = ops_notify;
	otr_ops.display_otr_message = ops_display_msg;
	otr_ops.gone_secure = ops_secure;
	otr_ops.gone_insecure = ops_insecure;
	otr_ops.still_secure = ops_still_secure;
	otr_ops.log_message = ops_log;
	otr_ops.max_message_size = ops_max_msg;
	otr_ops.update_context_list = ops_up_ctx_list;
	otr_ops.write_fingerprints = ops_writefps;
	otr_ops.is_logged_in = ops_is_logged_in;
}
