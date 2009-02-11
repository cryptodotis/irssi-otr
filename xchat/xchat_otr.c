#include "otr.h"

int debug = 0;

#ifdef HAVE_GREGEX_H
GRegex *regex_nickignore = NULL;
#endif

xchat_plugin *ph;

static char set_policy[512] = IO_DEFAULT_POLICY;
static char set_policy_known[512] = IO_DEFAULT_POLICY_KNOWN;
static char set_ignore[512] = IO_DEFAULT_IGNORE;
static int set_finishonunload = TRUE;

int extract_nick(char *nick, char *line)
{
	char *excl;

	if (*line++ != ':')
		return FALSE;

	strcpy(nick,line);
	
	if ((excl = strchr(nick,'!')))
		*excl = '\0';

	return TRUE;

}

void irc_send_message(IRC_CTX *ircctx, const char *recipient, char *msg) {
	xchat_commandf(ph, "PRIVMSG %s :%s", recipient, msg);
}

int cmd_otr(char *word[], char *word_eol[], void *userdata)
{
	const char *own_nick = xchat_get_info(ph, "nick");
	char *target = (char*)xchat_get_info(ph, "channel");
	const char *server = xchat_get_info(ph, "server");
	IRC_CTX ircctxs = { 
		.nick = (char*)own_nick, 
		.address = (char*)server },
		*ircctx = &ircctxs;

	char *cmd = word[2];

	if (strcmp(cmd,"debug")==0) {
		debug = !debug;
		otr_noticest(debug ? TXT_CMD_DEBUG_ON : TXT_CMD_DEBUG_OFF);
	} else if (strcmp(cmd,"version")==0) {
		otr_noticest(TXT_CMD_VERSION,IRCOTR_VERSION);
	} else if (strcmp(cmd,"finish")==0) {
		if (word[3]&&*word[3])
			otr_finish(NULL,NULL,word[3],TRUE);
		else
			otr_finish(ircctx,target,NULL,TRUE);
	} else if (strcmp(cmd,"trust")==0) {
		if (word[3]&&*word[3])
			otr_trust(NULL,NULL,word[3]);
		else
			otr_trust(ircctx,target,NULL);
	} else if (strcmp(cmd,"authabort")==0) {
		if (word[3]&&*word[3])
			otr_authabort(NULL,NULL,word[3]);
		else
			otr_authabort(ircctx,target,NULL);
	} else if (strcmp(cmd,"genkey")==0) {
		if (word[3]&&*word[3]) {
			if (strcmp(word[3],"abort")==0)
				keygen_abort(FALSE);
			else if (strchr(word[3],'@'))
				keygen_run(word[3]);
			else
				otr_noticest(TXT_KG_NEEDACC);
		} else {
			otr_noticest(TXT_KG_NEEDACC);
		}
	} else if (strcmp(cmd,"auth")==0) {
		if (!word[3]||!*word[3]) {
			otr_notice(ircctx,target,
				   TXT_CMD_AUTH);
		} else if (word[4]&&*word[4]&&strchr(word[3],'@'))
		    otr_auth(NULL,NULL,word_eol[4],word[3]);
		else 
			otr_auth(ircctx,target,NULL,word_eol[3]);
	} else if (strcmp(cmd,"set")==0) {
		if (strcmp(word[3],"policy")==0) {
			otr_setpolicies(word_eol[4],FALSE);
			strcpy(set_policy,word_eol[4]);
		} else if (strcmp(word[3],"policy_known")==0) {
			otr_setpolicies(word_eol[4],TRUE);
			strcpy(set_policy_known,word_eol[4]);
		} else if (strcmp(word[3],"ignore")==0) {
#ifdef HAVE_GREGEX_H
			if (regex_nickignore)
				g_regex_unref(regex_nickignore);
			regex_nickignore = g_regex_new(word_eol[4],0,0,NULL);
			strcpy(set_ignore,word_eol[4]);
#endif
		} else if (strcmp(word[3],"finishonunload")==0) {
			set_finishonunload = (strcasecmp(word[4],"true")==0);
		} else {
			xchat_printf(ph, "policy: %s\n"
				     "policy_known: %s\nignore: %s\n"
				     "finishonunload: %s\n",
				     set_policy,set_policy_known,set_ignore,
				     set_finishonunload ? "true" : "false");
		}
		
	}

	return XCHAT_EAT_ALL;
}

int hook_outgoing(char *word[], char *word_eol[], void *userdata)
{
	const char *own_nick = xchat_get_info(ph, "nick");
	const char *channel = xchat_get_info(ph, "channel");
	const char *server = xchat_get_info(ph, "server");
	char newmsg[512];
	char *otrmsg;
	IRC_CTX ircctx = { 
		.nick = (char*)own_nick,
		.address = (char*)server };

	if ((*channel == '&')||(*channel == '#'))
		return XCHAT_EAT_NONE;

#ifdef HAVE_GREGEX_H
	if (g_regex_match(regex_nickignore,channel,0,NULL))
		return XCHAT_EAT_NONE;
#endif
	otrmsg = otr_send(&ircctx,word_eol[1],channel);

	if (otrmsg==word_eol[1])
		return XCHAT_EAT_NONE;

	xchat_emit_print(ph, "Your Message", own_nick, word_eol[1], NULL, NULL);

	if (!otrmsg)
		return XCHAT_EAT_ALL;

	snprintf(newmsg, 511, "PRIVMSG %s :%s", channel, otrmsg);

	otrl_message_free(otrmsg);
	xchat_command(ph, newmsg);

	return XCHAT_EAT_ALL;
}

int hook_privmsg(char *word[], char *word_eol[], void *userdata)
{
	char nick[256];
	char *newmsg;
	const char *server = xchat_get_info(ph, "server");
	const char *own_nick = xchat_get_info(ph, "nick");
	IRC_CTX ircctx = { 
		.nick = (char*)own_nick,
		.address = (char*)server };
	xchat_context *query_ctx;

	if (!extract_nick(nick,word[1]))
		return XCHAT_EAT_NONE;

#ifdef HAVE_GREGEX_H
	if (g_regex_match(regex_nickignore,nick,0,NULL))
		return XCHAT_EAT_NONE;
#endif

	newmsg = otr_receive(&ircctx,word_eol[2],nick);

	if (!newmsg) {
		return XCHAT_EAT_ALL;
	}

	if (newmsg==word_eol[2]) {
		return XCHAT_EAT_NONE;
	}

	query_ctx = xchat_find_context(ph, server, nick);

	if (query_ctx)
		xchat_set_context(ph, query_ctx);

	xchat_emit_print(ph, "Private Message", nick, newmsg, NULL, NULL);

	otrl_message_free(newmsg);

	return XCHAT_EAT_ALL;
}

void xchat_plugin_get_info(char **name, char **desc, char **version, void **reserved)
{
   *name = PNAME;
   *desc = PDESC;
   *version = PVERSION;
}

int xchat_plugin_init(xchat_plugin *plugin_handle,
                      char **plugin_name,
                      char **plugin_desc,
                      char **plugin_version,
                      char *arg)
{
	ph = plugin_handle;

	*plugin_name = PNAME;
	*plugin_desc = PDESC;
	*plugin_version = PVERSION;

	if (otrlib_init())
		return 0;

	xchat_hook_server(ph, "PRIVMSG", XCHAT_PRI_NORM, hook_privmsg, 0);
	xchat_hook_command(ph, "", XCHAT_PRI_NORM, hook_outgoing, 0, 0);
	xchat_hook_command(ph, "otr", XCHAT_PRI_NORM, cmd_otr, 0, 0);

	otr_setpolicies(IO_DEFAULT_POLICY,FALSE);
	otr_setpolicies(IO_DEFAULT_POLICY_KNOWN,TRUE);

#ifdef HAVE_GREGEX_H
	if (regex_nickignore)
		g_regex_unref(regex_nickignore);
	regex_nickignore = g_regex_new(IO_DEFAULT_IGNORE,0,0,NULL);
#endif

	xchat_print(ph, "xchat-otr loaded successfully!\n");

	return 1;
}

int xchat_plugin_deinit()
{
#ifdef HAVE_GREGEX_H
	g_regex_unref(regex_nickignore);
#endif

	if (set_finishonunload)
		otr_finishall();

	otrlib_deinit();

	return 1;
}

void printformat(IRC_CTX *ircctx, const char *nick, int lvl, int fnum, ...)
{
	va_list params;
	va_start( params, fnum );
	char msg[LOGMAX], *s = msg;
	xchat_context *find_query_ctx;
	char *server = NULL;

	if (ircctx)
		server = ircctx->address;

	if (server&&nick) {
		find_query_ctx = xchat_find_context(ph, server, nick);
		if(find_query_ctx==NULL) {
			// no query window yet, let's open one
			xchat_commandf(ph, "query %s", nick);
			find_query_ctx = xchat_find_context(ph, server, nick);
		}
	} else {
		find_query_ctx = xchat_find_context(ph,
						    NULL,
						    xchat_get_info(ph,
								   "network") ?
						    :
						    xchat_get_info(ph,"server"));
	}

	xchat_set_context(ph, find_query_ctx);

	if( vsnprintf( s, LOGMAX, formats[fnum].def, params ) < 0 )
		sprintf( s, "internal error parsing error string (BUG)" );
	va_end( params );
	xchat_printf(ph, "OTR: %s", s);
}

IRC_CTX *server_find_address(char *address)
{
	static IRC_CTX ircctx;

	ircctx.address = address;

        return &ircctx;
}
