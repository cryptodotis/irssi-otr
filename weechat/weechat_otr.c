/*
 * Off-the-Record Messaging (OTR) modules for IRC
 * Copyright (C) 2009  Uli Meis <a.sporto+bee@gmail.com>
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

WEECHAT_PLUGIN_NAME("irc-otr");
WEECHAT_PLUGIN_DESCRIPTION("Off-The-Record Messaging for WeeChat");
WEECHAT_PLUGIN_AUTHOR("Uli Meis <a.sporto+bee@gmail.com>");
WEECHAT_PLUGIN_VERSION(IRCOTR_VERSION);
WEECHAT_PLUGIN_WEECHAT_VERSION("unknown");
WEECHAT_PLUGIN_LICENSE("GPL3");

struct t_weechat_plugin *weechat_otr_plugin = NULL;

int debug = 0;

#ifdef HAVE_GREGEX_H
GRegex *regex_nickignore = NULL;
#endif

static char set_policy[512] = IO_DEFAULT_POLICY;
static char set_policy_known[512] = IO_DEFAULT_POLICY_KNOWN;
static char set_ignore[512] = IO_DEFAULT_IGNORE;
static int set_finishonunload = TRUE;

void printformatva(IRC_CTX *ircctx, const char *nick, char *format, va_list params)
{
	char msg[LOGMAX], *s = msg;
	char *server = NULL;
	struct t_gui_buffer *buffer = NULL;

	if (ircctx)
		server = ircctx->address;

	if (server&&nick) {
		char s[256];
		sprintf(s,"%s.%s",ircctx->address,nick);
		buffer = weechat_buffer_search("irc",s);
		//TODO: create query window on demand
	}

	if( vsnprintf( s, LOGMAX, format, params ) < 0 )
		sprintf( s, "internal error parsing error string (BUG)" );
	va_end( params );

	weechat_printf(buffer,"OTR: %s",s);
}

void printformat(IRC_CTX *ircctx, const char *nick, int lvl, int fnum, ...)
{
	va_list params;
	va_start( params, fnum );

	printformatva(ircctx,nick,formats[fnum].def,params);
}

void wc_printf(IRC_CTX *ircctx, const char *nick, char *format, ...)
{
	va_list params;
	va_start( params, format );

	printformatva(ircctx,nick,format,params);
}

#define wc_debug(server,nick,format,...) { \
	if (debug) \
		wc_printf(server,nick, \
			    format, ## __VA_ARGS__); \
}

void irc_send_message(IRC_CTX *ircctx, const char *recipient, char *msg) {
	char s[256];
	char nmsg[512];
	struct t_gui_buffer *buffer;
	
	sprintf(s,"%s.%s",ircctx->address,recipient);
	buffer = weechat_buffer_search("irc",s);
	if (buffer) {
		wc_debug(ircctx,recipient,"OTR injection %s.%s: %s",ircctx->address,recipient,msg);
		sprintf(nmsg,"/quote PRIVMSG %s :%s",recipient,msg);
		weechat_command(buffer,nmsg);
	} else {
		wc_debug(ircctx,recipient,"OTR: injection error, no buffer found");
		//TODO: create query window on demand
	}
}

IRC_CTX *server_find_address(char *address)
{
	static IRC_CTX ircctx;

	ircctx.address = address;

        return &ircctx;
}

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

char *wc_modifier_privmsg_in(void *data, const char *modifier,
			  const char *modifier_data, const char *string)
{
	int argc;
	char **argv, **argv_eol;
	char *server = strdup(modifier_data);
	char nick[256];
	char *newmsg,*msg;
	IRC_CTX ircctx;
	char cmsg[512];

	string = strdup(string);

	argv = weechat_string_explode (string, " ", 0, 0, &argc);
	argv_eol = weechat_string_explode (string, " ", 1, 0, NULL);

	if (!extract_nick(nick,argv[0]))
		goto done;

	if ((*argv[2]=='&')||(*argv[2]=='#'))
		goto done;

#ifdef HAVE_GREGEX_H
	if (g_regex_match(regex_nickignore,nick,0,NULL))
		goto done;
#endif

	ircctx.address = server;
	ircctx.nick = argv[2];

	msg = argv_eol[3]+1;
	wc_debug(&ircctx,nick,"otr receive own %s, server %s, nick %s, msg %s",
		       ircctx.nick,ircctx.address,nick,msg);
	newmsg = otr_receive(&ircctx,msg,nick);

	if (!newmsg) {
		string = strdup("");
		goto done;
	}

	if (newmsg==msg) {
		goto done;
	}

	snprintf(cmsg, 511, "%s %s %s :%s",argv[0],argv[1],argv[2],newmsg);

	otrl_message_free(newmsg);

	string = strdup(cmsg);
done:
	free(server);
	weechat_string_free_exploded(argv);
	weechat_string_free_exploded(argv_eol);

	return (char*)string;
}

char *wc_modifier_privmsg_out(void *data, const char *modifier,
			  const char *modifier_data, const char *string)
{
	int argc;
	char **argv, **argv_eol;
	IRC_CTX ircctx;
	char newmsg[512];
	char *otrmsg;
	struct t_gui_buffer *buffer;
	char s[256];
	char *msg;

	argv = weechat_string_explode (string, " ", 0, 0, &argc);
	argv_eol = weechat_string_explode (string, " ", 1, 0, NULL);

	string = strdup(string);
	
	if ((*argv[1]=='&')||(*argv[1]=='#'))
		goto done;

	msg = argv_eol[2]+1;

#ifdef HAVE_GREGEX_H
	if (g_regex_match(regex_nickignore,argv[1],0,NULL))
		goto done;
#endif

	/* we're unfortunately fed back stuff from irc_send_message above */
	if (strncmp(msg,"?OTR",4)==0)
		return strdup(string);

	ircctx.address = (char*)modifier_data;
	sprintf(s,"%s.%s",ircctx.address,argv[1]);
	buffer = weechat_buffer_search("irc",s);
	if (!buffer) {
		weechat_printf(NULL,"OTR send: no buffer found for %s",s);
		//TODO: create query window on demand
		goto done;
	}
	ircctx.nick = (char*)weechat_buffer_get_string(buffer,"localvar_nick");

	wc_debug(&ircctx,argv[1],"otr send own %s, server %s, nick %s, msg %s",
		       ircctx.nick,ircctx.address,argv[1],msg);
	otrmsg = otr_send(&ircctx,msg,argv[1]);

	if (otrmsg==msg)
		goto done;

	if (!otrmsg) {
		wc_debug(&ircctx,argv[1],"OTR send NULL");
		free((char*)string);
		string = strdup("");
		goto done;
	}

	wc_debug(&ircctx,argv[1],"NEWMSG");
	snprintf(newmsg, 511, "PRIVMSG %s :%s", argv[1], otrmsg);

	otrl_message_free(otrmsg);
	
	free((char*)string);
	string = newmsg;

done:
	weechat_string_free_exploded(argv);
	weechat_string_free_exploded(argv_eol);

	return (char*)string;
}

int cmd_otr(void *data, struct t_gui_buffer *buffer, int argc, char **word, char **word_eol)
{
	const char *own_nick = weechat_buffer_get_string(buffer,"localvar_nick");
	const char *server = weechat_buffer_get_string(buffer,"localvar_server");
	char *target = (char*)weechat_buffer_get_string(buffer,"short_name");
	IRC_CTX ircctxs = {
		.nick = (char*)own_nick,
		.address = (char*)server },
		*ircctx = &ircctxs;

	char *cmd = argc > 1 ? word[1] : NULL;
	char *parm1 = argc > 2 ? word[2] : "";
	char *parm2 = argc > 3 ? word[3] : "";
	
	if (!cmd) {
		weechat_printf(buffer,otr_help);
	} else if (strcmp(cmd,"debug")==0) {
		debug = !debug;
		otr_noticest(debug ? TXT_CMD_DEBUG_ON : TXT_CMD_DEBUG_OFF);
	} else if (strcmp(cmd,"version")==0) {
		otr_noticest(TXT_CMD_VERSION,IRCOTR_VERSION);
	} else if (strcmp(cmd,"finish")==0) {
		if (parm1&&*parm1)
			otr_finish(NULL,NULL,parm1,TRUE);
		else
			otr_finish(ircctx,target,NULL,TRUE);
	} else if (strcmp(cmd,"trust")==0) {
		if (parm1&&*parm1)
			otr_trust(NULL,NULL,parm1);
		else
			otr_trust(ircctx,target,NULL);
	} else if (strcmp(cmd,"authabort")==0) {
		if (parm1&&*parm1)
			otr_authabort(NULL,NULL,parm1);
		else
			otr_authabort(ircctx,target,NULL);
	} else if (strcmp(cmd,"genkey")==0) {
		if (parm1&&*parm1) {
			if (strcmp(parm1,"abort")==0)
				keygen_abort(FALSE);
			else if (strchr(parm1,'@'))
				keygen_run(parm1);
			else
				otr_noticest(TXT_KG_NEEDACC);
		} else {
			otr_noticest(TXT_KG_NEEDACC);
		}
	} else if (strcmp(cmd,"auth")==0) {
		if (!parm1||!*parm1) {
			otr_notice(ircctx,target,
				   TXT_CMD_AUTH);
		} else if (parm2&&*parm2&&strchr(parm1,'@'))
		    otr_auth(NULL,NULL,word_eol[3],parm1);
		else
			otr_auth(ircctx,target,NULL,word_eol[2]);
	} else if (strcmp(cmd,"set")==0) {
		if (strcmp(parm1,"policy")==0) {
			otr_setpolicies(word_eol[3],FALSE);
			strcpy(set_policy,word_eol[3]);
		} else if (strcmp(parm1,"policy_known")==0) {
			otr_setpolicies(word_eol[3],TRUE);
			strcpy(set_policy_known,word_eol[3]);
		} else if (strcmp(parm1,"ignore")==0) {
#ifdef HAVE_GREGEX_H
			if (regex_nickignore)
				g_regex_unref(regex_nickignore);
			regex_nickignore = g_regex_new(word_eol[3],0,0,NULL);
			strcpy(set_ignore,word_eol[3]);
#endif
		} else if (strcmp(parm1,"finishonunload")==0) {
			set_finishonunload = (strcasecmp(parm2,"true")==0);
		} else {
			weechat_printf(buffer, "policy: %s\n"
				     "policy_known: %s\nignore: %s\n"
				     "finishonunload: %s\n",
				     set_policy,set_policy_known,set_ignore,
				     set_finishonunload ? "true" : "false");
		}
		
	}

	return WEECHAT_RC_OK;
}
int weechat_plugin_init (struct t_weechat_plugin *plugin, int argc, char *argv[])
{

	weechat_plugin = plugin;

	weechat_hook_modifier("irc_in_privmsg", &wc_modifier_privmsg_in, NULL);
	weechat_hook_modifier("irc_out_privmsg", &wc_modifier_privmsg_out, NULL);

	if (otrlib_init())
		return WEECHAT_RC_ERROR;

	otr_setpolicies(IO_DEFAULT_POLICY,FALSE);
	otr_setpolicies(IO_DEFAULT_POLICY_KNOWN,TRUE);

#ifdef HAVE_GREGEX_H
	if (regex_nickignore)
		g_regex_unref(regex_nickignore);
	regex_nickignore = g_regex_new(IO_DEFAULT_IGNORE,0,0,NULL);
#endif

	weechat_hook_command ("otr",
			      N_("Control the OTR module"),
			      N_("[text]"),
			      N_("text: write this text"),
			      "",
			      &cmd_otr, NULL);

	return WEECHAT_RC_OK;
}

int weechat_plugin_end (struct t_weechat_plugin *plugin)
{
	return WEECHAT_RC_OK;
}
