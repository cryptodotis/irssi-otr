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

int debug = FALSE;

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
static void cmd_otr(const char *data,void *server,WI_ITEM_REC *item) {
	if (*data == '\0')
		otr_logst(LVL_NOTICE,"We're alive");
	else {
		command_runsub("otr", data, server, item);
	}
}

/*
 * /otr debug
 */
static void cmd_debug(const char *data, void *server, WI_ITEM_REC *item) {
	debug = !debug;
	otr_logst(LVL_NOTICE,"Debug mode %s", debug ? "on" : "off" );
}

/*
 * irssi init()
 */
void otr_init(void) {
	module_register(MODULE_NAME,  "core");

	if (otrlib_init())
		return;

	signal_add_first("server sendmsg", (SIGNAL_FUNC) sig_server_sendmsg);
	signal_add_first("message private", (SIGNAL_FUNC) sig_message_private);
	
	command_bind("otr", NULL, (SIGNAL_FUNC) cmd_otr);
	command_bind("otr debug", NULL, (SIGNAL_FUNC) cmd_debug);

	/* use standard irssi style messages */
	theme_register_module(MODULE_NAME,fecommon_core_formats);
}

/*
 * irssi deinit()
 */
void otr_deinit(void) {

	signal_remove("server sendmsg", (SIGNAL_FUNC) sig_server_sendmsg);
	signal_remove("message private", (SIGNAL_FUNC) sig_message_private);

	otrlib_deinit();

}
