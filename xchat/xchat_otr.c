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

int debug = 0;

#ifdef HAVE_GREGEX_H
GRegex *regex_nickignore = NULL;
#endif

static IOUSTATE *ioustate;

xchat_plugin *ph;

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
	int argc=0;

	word+=3;
	word_eol+=3;
	
	while (word[argc]&&*word[argc])
		argc++;

	cmd_generic(ioustate,ircctx,argc,word,word_eol,target);

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

	ioustate = otr_init_user("one to rule them all");

	xchat_hook_server(ph, "PRIVMSG", XCHAT_PRI_NORM, hook_privmsg, 0);
	xchat_hook_command(ph, "", XCHAT_PRI_NORM, hook_outgoing, 0, 0);
	xchat_hook_command(ph, "otr", XCHAT_PRI_NORM, cmd_otr, 0, 0);

	otr_setpolicies(ioustate,IO_DEFAULT_POLICY,FALSE);
	otr_setpolicies(ioustate,IO_DEFAULT_POLICY_KNOWN,TRUE);

#ifdef HAVE_GREGEX_H
	if (regex_nickignore)
		g_regex_unref(regex_nickignore);
	regex_nickignore = g_regex_new(IO_DEFAULT_IGNORE,0,0,NULL);
#endif

	xchat_print(ph, "xchat-otr loaded successfully!\n");

	cmds[CMDCOUNT].name = "set";
	cmds[CMDCOUNT].cmdfunc = cmd_set;

	return 1;
}

int xchat_plugin_deinit()
{
#ifdef HAVE_GREGEX_H
	g_regex_unref(regex_nickignore);
#endif

	if (set_finishonunload)
		otr_finishall(ioustate);

	otr_deinit_user(ioustate);

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
