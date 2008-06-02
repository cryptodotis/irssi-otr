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

int debug = FALSE;
GRegex *regex_nickignore;

/*
 * Pipes all outgoing private messages through OTR
 */
static void sig_server_sendmsg(SERVER_REC *server, const char *target,
			       const char *msg, void *target_type_p)
{
	if (GPOINTER_TO_INT(target_type_p)==SEND_TARGET_NICK) {
		char *otrmsg = otr_send(server,msg,target);
		if (otrmsg&&(otrmsg!=msg)) {
			signal_continue(4,server,target,otrmsg,target_type_p);
			otrl_message_free(otrmsg);
		} else if (!otrmsg)
			signal_stop();
	}
}

/*
 * Pipes all incoming private messages through OTR
 */
static void sig_message_private(SERVER_REC *server, const char *msg,
				const char *nick, const char *address)
{
	char *newmsg;

	if (g_regex_match(regex_nickignore,nick,0,NULL))
		return;

	newmsg = otr_receive(server,msg,nick);

	if (newmsg&&(newmsg!=msg)) {
		signal_continue(4,server,newmsg,nick,address);
		otrl_message_free(newmsg);
	} else if (newmsg==NULL)
		signal_stop();
}

/*
 * /otr
 */
static void cmd_otr(const char *data,void *server,WI_ITEM_REC *item) 
{
	if (*data == '\0')
		otr_noticest(TXT_CMD_OTR);
	else {
		command_runsub("otr", data, server, item);
	}
}

/*
 * /otr trust
 */
static void cmd_trust(const char *data, void *server, WI_ITEM_REC *item)
{
	QUERY_REC *query = QUERY(item);
	if (query&&query->server&&query->server->connrec)
		otr_trust(query->server,query->name);
	else
		otr_notice(item->server,query ? query->name : NULL,
			   TXT_CMD_TRUST);
}

/*
 * /otr genkey nick@irc.server.com
 */
static void cmd_genkey(const char *data, void *server, WI_ITEM_REC *item)
{
	//TODO check data
	keygen_run(data);
}

/*
 * /otr auth <secret>
 */
static void cmd_auth(const char *data, void *server, WI_ITEM_REC *item)
{
	WI_ITEM_REC *wi = active_win->active;
	QUERY_REC *query = QUERY(wi);

	if (query&&query->server&&query->server->connrec) {
		if (!data||(*data=='\0')) {
			otr_notice(server,query->name,
				   TXT_CMD_AUTH);
			return;
		}
		otr_auth(query->server,query->name,data);
	}
}

/*
 * /otr authabort
 */
static void cmd_authabort(const char *data, void *server, WI_ITEM_REC *item)
{
	WI_ITEM_REC *wi = active_win->active;
	QUERY_REC *query = QUERY(wi);

	if (query&&query->server&&query->server->connrec)
		otr_authabort(query->server,query->name);
}

/*
 * /otr debug
 */
static void cmd_debug(const char *data, void *server, WI_ITEM_REC *item)
{
	debug = !debug;
	otr_noticest(debug ? TXT_CMD_DEBUG_ON : TXT_CMD_DEBUG_OFF);
}

/*
 * /otr help
 */
static void cmd_help(const char *data, void *server, WI_ITEM_REC *item)
{
	printtext(NULL,NULL,MSGLEVEL_CRAP,otr_help);
}

/*
 * otr statusbar
 */
static void otr_statusbar(SBAR_ITEM_REC *item, int get_size_only)
{
	WI_ITEM_REC *wi = active_win->active;
	QUERY_REC *query = QUERY(wi);
	int formatnum=0;

	if (query&&query->server&&query->server->connrec)
		formatnum = otr_getstatus(query->server->nick,query->name,query->server->connrec->address);

	statusbar_item_default_handler(
		item, 
		get_size_only, 
		formatnum ? formats[formatnum].def : ""," ",FALSE);
}

/*
 * irssi init()
 */
void otr_init(void)
{
	regex_nickignore = g_regex_new(formats[TXT_NICKIGNORE].def,0,0,NULL);

	module_register(MODULE_NAME,  "core");

	theme_register(formats);

	if (otrlib_init())
		return;

	signal_add_first("server sendmsg", (SIGNAL_FUNC) sig_server_sendmsg);
	signal_add_first("message private", (SIGNAL_FUNC) sig_message_private);

	command_bind("otr", NULL, (SIGNAL_FUNC) cmd_otr);
	command_bind("otr debug", NULL, (SIGNAL_FUNC) cmd_debug);
	command_bind("otr trust", NULL, (SIGNAL_FUNC) cmd_trust);
	command_bind("otr genkey", NULL, (SIGNAL_FUNC) cmd_genkey);
	command_bind("otr auth", NULL, (SIGNAL_FUNC) cmd_auth);
	command_bind("otr authabort", NULL, (SIGNAL_FUNC) cmd_authabort);
	command_bind("otr help", NULL, (SIGNAL_FUNC) cmd_help);

	statusbar_item_register("otr", NULL, otr_statusbar);

	statusbar_items_redraw("window");

}

/*
 * irssi deinit()
 */
void otr_deinit(void)
{
	g_regex_unref(regex_nickignore);

	signal_remove("server sendmsg", (SIGNAL_FUNC) sig_server_sendmsg);
	signal_remove("message private", (SIGNAL_FUNC) sig_message_private);

	command_unbind("otr", (SIGNAL_FUNC) cmd_otr);
	command_unbind("otr debug", (SIGNAL_FUNC) cmd_debug);
	command_unbind("otr trust", (SIGNAL_FUNC) cmd_trust);
	command_unbind("otr genkey", (SIGNAL_FUNC) cmd_genkey);
	command_unbind("otr auth", (SIGNAL_FUNC) cmd_auth);
	command_unbind("otr authabort", (SIGNAL_FUNC) cmd_authabort);
	command_unbind("otr help", (SIGNAL_FUNC) cmd_help);

	statusbar_item_unregister("otr");

	otrlib_deinit();

}
