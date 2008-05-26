/*
	Off-the-Record Messaging (OTR) module for the irssi IRC client
	Copyright (C) 2008  Uli Meis <a.sporto+bee@gmail.com>

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
*/

#include "otr.h"

#include <libgen.h>
#include <gcrypt.h>

static OtrlUserState otr_state = NULL;
static OtrlMessageAppOps otr_ops;
static int otrinited = FALSE;


/* Key generation stuff */

typedef enum { KEYGEN_NO, KEYGEN_RUNNING } keygen_status_t;

struct {
	keygen_status_t status;
	char *accountname;
	char *protocol;
	time_t started;
	GIOChannel *ch[2];
	guint eid;
} kg_st = {.status = KEYGEN_NO };

#define KEYGENMSG "Key generation for %s: "

/*
 * Installed as g_io_watch and called when the key generation
 * process finishs.
 */
gboolean keygen_complete(GIOChannel *source, GIOCondition condition, gpointer data) {
	gcry_error_t err;

	read(g_io_channel_unix_get_fd(kg_st.ch[0]),&err,sizeof(err));

	g_io_channel_shutdown(kg_st.ch[0],FALSE,NULL);
	g_io_channel_shutdown(kg_st.ch[1],FALSE,NULL);
	g_io_channel_unref(kg_st.ch[0]);
	g_io_channel_unref(kg_st.ch[1]);

	if (err)
		otr_logst(LVL_NOTICE,KEYGENMSG "failed: %s (%s)",
			kg_st.accountname,
			gcry_strerror(err),
			gcry_strsource(err));
	else {
		/* reload keys */
		otr_logst(LVL_NOTICE,KEYGENMSG "completed in %d seconds. Reloading keys",
			kg_st.accountname,
			time(NULL)-kg_st.started);
		otrl_privkey_forget_all(otr_state);
		key_load();
	}

	kg_st.status = KEYGEN_NO;
	g_free(kg_st.accountname);

	return FALSE;
}

/*
 * Run key generation in a seperate process (takes ages).
 * The other process will rewrite the key file, we shouldn't 
 * change anything till it's done and we've reloaded the keys.
 */
void keygen_run(const char *accname) {
	gcry_error_t err;
	int ret;
	int fds[2];
	char *filename = g_strconcat(getenv("HOME"),KEYFILE,NULL);
	char *dir = dirname(g_strdup(filename));

	if (kg_st.status!=KEYGEN_NO) {
		otr_logst(LVL_NOTICE,KEYGENMSG "another generation is already in progress",accname);
		return;
	}

	if (!g_file_test(dir, G_FILE_TEST_EXISTS)) {
		if (g_mkdir(dir,S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)) {
			otr_logst(LVL_NOTICE,KEYGENMSG "aborted, failed creating directory %s: %s",
				accname,dir,strerror(errno));
			g_free(dir);
			g_free(filename);
			return;
		} else
			otr_logst(LVL_NOTICE,KEYGENMSG "created directory %s\n",dir);
	}
	g_free(dir);

	if (pipe(fds) != 0) {
		otr_logst(LVL_NOTICE,KEYGENMSG "error creating pipe: %s",accname,strerror(errno));
		g_free(filename);
		return;
	}

	kg_st.ch[0] = g_io_channel_unix_new(fds[0]);
	kg_st.ch[1] = g_io_channel_unix_new(fds[1]);

	kg_st.accountname = g_strdup(accname);
	kg_st.protocol = PROTOCOLID;
	kg_st.started = time(NULL);

	if ((ret = fork())) {
		g_free(filename);
		if (ret==-1) {
			otr_logst(LVL_NOTICE,KEYGENMSG "fork() error: %s",accname,strerror(errno));
			return;
		}

		kg_st.status = KEYGEN_RUNNING;
		otr_logst(LVL_NOTICE,KEYGENMSG "initiated. This might take several minutes.",accname);

		kg_st.eid = g_io_add_watch(kg_st.ch[0], G_IO_IN, (GIOFunc) keygen_complete, NULL);
		kg_st.started = time(NULL);
		return;
	}
	
	/* child */

	err = otrl_privkey_generate(otr_state,filename,accname,PROTOCOLID);
	write(fds[1],&err,sizeof(err));

	//g_free(filename);
        _exit(0);
}

/* Callbacks from the OTR lib */

OtrlPolicy ops_policy(void *opdata, ConnContext *context) {
	/* meaning opportunistic */
	return OTRL_POLICY_DEFAULT;
}

void ops_create_privkey(void *opdata, const char *accountname,
	const char *protocol) {
	keygen_run(accountname);
}

/*
 * Inject OTR message.
 * Deriving the server is currently a hack,
 * need to derive the server from accountname.
 */
void ops_inject_msg(void *opdata, const char *accountname,
	    const char *protocol, const char *recipient, const char *message) {
	SERVER_REC *a_serv;
	a_serv = active_win->active_server; 
	a_serv->send_message(a_serv, recipient, message,
		GPOINTER_TO_INT(SEND_TARGET_NICK));
}

/*
 * OTR notification. Haven't seen one yet.
 */
void ops_notify(void *opdata, OtrlNotifyLevel level, const char *accountname, 
		const char *protocol, const char *username, 
		const char *title, const char *primary, 
		const char *secondary) {
	otr_log(active_win->active_server,accountname,username,LVL_NOTICE,
		"title: %s prim: %s sec: %s",title,primary,secondary);
}

/*
 * OTR message. E.g. "following has been transmitted in clear: ...".
 * We're trying to kill the ugly HTML.
 */
int ops_display_msg(void *opdata, const char *accountname, 
		    const char *protocol, const char *username, 
		    const char *msg) {
	/* This is kind of messy. */
	GRegex *regex_bold  = g_regex_new("</?i([ /][^>]*)?>",0,0,NULL);
	GRegex *regex_del   = g_regex_new("</?b([ /][^>]*)?>",0,0,NULL);
	gchar *msgnohtml = g_regex_replace_literal(regex_del,msg,-1,0,"",0,NULL);
	msg = g_regex_replace_literal(regex_bold,msgnohtml,-1,0,"%9",0,NULL);

	otr_log(active_win->active_server,accountname,username,LVL_NOTICE,
		"msg: %s",msg);

	g_free(msgnohtml);
	g_free((char*)msg);
	g_regex_unref(regex_del);
	g_regex_unref(regex_bold);
	return 0;
}

void ops_secure(void *opdata, ConnContext *context) {
	otr_log(active_win->active_server,context->accountname,
		context->username,LVL_NOTICE,"gone %s","%9secure%9");
}

void ops_insecure(void *opdata, ConnContext *context) {
	otr_log(active_win->active_server,context->accountname,
	context->username,LVL_NOTICE,"gone %s","%9insecure%9");
}

void ops_still_secure(void *opdata, ConnContext *context, int is_reply) {
	otr_log(active_win->active_server,context->accountname,
		context->username,LVL_NOTICE,
		"still %s (%s reply)", 
		"%9secure%9",
		is_reply ? "is" : "is not");
}

void ops_log(void *opdata, const char *message) {
	otr_logst(LVL_NOTICE,"log msg: ",message);
}

int ops_max_msg(void *opdata, ConnContext *context) {
	return OTR_MAX_MSG_SIZE;
}


/*
 * init otr lib.
 */
int otrlib_init() {

	if (!otrinited) {
		OTRL_INIT;
		otrinited = TRUE;
	}

	otr_state = otrl_userstate_create();

	/* load keys */

	key_load();
	//otrl_privkey_generate(otr_state,"/tmp/somekey","jesus@somewhere.com","proto");

	/* set otr ops */
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

	return otr_state==NULL;
}

void otrlib_deinit() {
	if (otr_state) {
		otrl_userstate_free(otr_state);
		otr_state = NULL;
	}
	if (kg_st.status==KEYGEN_RUNNING)
		g_source_remove(kg_st.eid);
}


/*
 * load private keys from given file.
 */
void key_load() {
	gcry_error_t err;
	char *filename = g_strconcat(getenv("HOME"),KEYFILE,NULL);

	if (!g_file_test(filename, G_FILE_TEST_EXISTS)) {
		otr_logst(LVL_NOTICE,"no private keys found");
		return;
	}

	err =  otrl_privkey_read(otr_state, filename);

	if (err == GPG_ERR_NO_ERROR) {
	    otr_logst(LVL_NOTICE,"private keys loaded");
	} else {
	    otr_logst(LVL_NOTICE,"Error loading private keys: %s (%s)",
		    gcry_strerror(err),
		    gcry_strsource(err));
	}
	g_free(filename);
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
		NULL, 
		NULL);

	if (err != 0) {
		otr_logst(LVL_NOTICE,"send failed: acc=%s to=%s msg=%s",accname,to,msg);
		return NULL;
	}

	if (newmessage==NULL)
		return (char*)msg;

	/* OTR message. Need to do fragmentation */

	co = otrl_context_find(
		otr_state,
		to,
		accname,
		PROTOCOLID,
		FALSE,
		NULL,
		NULL,
		NULL);

	if (!co) {
		otr_logst(LVL_NOTICE,"couldn't find context: acc=%s to=%s",accname,to);
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
		otr_logst(LVL_NOTICE,"failed to fragment message: msg=%s",msg);
	} else
		otr_log(server,accname,to,LVL_DEBUG,"OTR converted sent message to %s",newmessage);

	return NULL;
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
	const char *nick = server->nick;
	const char *address = server->connrec->address;
	char accname[256];
	char *lastmsg;
	ConnContext *co;

	sprintf(accname, "%s@%s", nick, address);

	co = otrl_context_find(
		otr_state,
		from,
		accname,
		PROTOCOLID,
		TRUE,
		NULL,
		NULL,
		NULL);

	if (!co) {
		otr_logst(LVL_NOTICE,"couldn't create/find context: acc=%s from=%s",accname,from);
		return NULL;
	}

	/* The server might have split lines that were too long 
	 * (bitlbee does that). The heuristic is simple: If we can find ?OTR:
	 * in the message but it doesn't end with a ".", queue it and wait
	 * for the rest. This works if there are only two fragments which
	 * (fortunately) seems to be the maximum.
	 */
	lastmsg = co->app_data;

	if (lastmsg) {
		strcpy(lastmsg+strlen(lastmsg),msg);
		otr_log(server,accname,from,LVL_DEBUG,"dequeued");
		msg = lastmsg;
		co->app_data = NULL;
	} else if (strstr(msg,"?OTR:")&&(strlen(msg)>OTR_MAX_MSG_SIZE)&&msg[strlen(msg)-1]!='.') {
		co->app_data = malloc(1024*sizeof(char));
		strcpy(co->app_data,msg);
		co->app_data_free = g_free;
		otr_log(server,accname,from,LVL_DEBUG,"queued");
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
		NULL,
		NULL,
		NULL);

	if (ignore_message) {
		otr_log(server,accname,from,LVL_DEBUG,"ignoring protocol message of length %zd, acc=%s, from=%s", strlen(msg),accname,from);
		return NULL;
	}

	if (newmessage)
		otr_log(server,accname,from,LVL_DEBUG,"OTR converted received message");

	return newmessage ? : (char*)msg;
}
