/*
 * Off-the-Record Messaging (OTR) module for the irssi IRC client
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

#define _GNU_SOURCE
#include <assert.h>
#include <glib.h>
#include <glib/gprintf.h>
#include <glib/gstdio.h>
#include <stdio.h>

#include "cmd.h"
#include "otr.h"
#include "utils.h"

static const char *signal_args_otr_event[] = {
	"iobject", "string", "string", "NULL" };

int debug = FALSE;

#ifdef HAVE_GREGEX_H
GRegex *regex_nickignore = NULL;
#endif

/* need this to decode arguments in perl signal handlers. Maybe irssi should
 * install perl/perl-signals.h which is where this definition comes from? */
void perl_signal_register(const char *signal, const char **args);

/*
 * Global state for the user.
 */
struct otr_user_state *user_state_global;

/*
 * Pipes all outgoing private messages through OTR
 */
static void sig_server_sendmsg(SERVER_REC *server, const char *target,
		const char *msg, void *target_type_p)
{
	int ret;
	char *otrmsg = NULL;

	if (GPOINTER_TO_INT(target_type_p) != SEND_TARGET_NICK) {
		goto end;
	}

#ifdef HAVE_GREGEX_H
	if (g_regex_match(regex_nickignore, target, 0, NULL)) {
		goto end;
	}
#endif

	/* Critical section. On error, message MUST NOT be sent */
	ret = otr_send(server, msg, target, &otrmsg);
	if (ret) {
		signal_stop();
		goto end;
	}

	if (!otrmsg) {
		/* Send original message */
		signal_continue(4, server, target, msg, target_type_p);
	} else {
		/* Send encrypted message */
		signal_continue(4, server, target, otrmsg, target_type_p);
	}

end:
	otrl_message_free(otrmsg);
	return;
}

/*
 * Pipes all incoming private messages through OTR
 */
void sig_message_private(SERVER_REC *server, const char *msg,
		const char *nick, const char *address)
{
	int ret;
	char *new_msg = NULL;

#ifdef HAVE_GREGEX_H
	if (g_regex_match(regex_nickignore, nick, 0, NULL)) {
		goto end;
	}
#endif

	ret = otr_receive(server, msg, nick, &new_msg);
	if (ret) {
		signal_stop();
		goto end;
	}

	if (!new_msg) {
		/* This message was not OTR */
		signal_continue(4, server, msg, nick, address);
	} else {
		/* OTR received message */
		signal_continue(4, server, new_msg, nick, address);
	}

end:
	otrl_message_free(new_msg);
	return;
}

/*
 * Finish an OTR conversation when its query is closed.
 */
static void sig_query_destroyed(QUERY_REC *query)
{
	if (query && query->server && query->server->connrec) {
		otr_finish(query->server, query->name);
	}
}

/*
 * Handle /me IRC command.
 */
static void cmd_me(const char *data, IRC_SERVER_REC *server,
		WI_ITEM_REC *item)
{
	int ret;
	const char *target;
	char *msg, *otrmsg = NULL;
	QUERY_REC *query;

	query = QUERY(item);

	if (!query || !query->server) {
		goto end;
	}

	CMD_IRC_SERVER(server);
	if (!IS_IRC_QUERY(query)) {
		goto end;
	}

	if (!server || !server->connected) {
		cmd_return_error(CMDERR_NOT_CONNECTED);
	}

	target = window_item_get_target(item);

	ret = asprintf(&msg, "/me %s", data);
	if (ret < 0) {
		goto end;
	}

	/* Critical section. On error, message MUST NOT be sent */
	ret = otr_send(query->server, msg, target, &otrmsg);
	free(msg);

	if (!otrmsg) {
		goto end;
	}

	signal_stop();

	if (otrmsg) {
		/* Send encrypted message */
		irssi_send_message(SERVER(server), target, otrmsg);
		otrl_message_free(otrmsg);
	}

	signal_emit("message irc own_action", 3, server, data, item->visible_name);

end:
	return;
}

/*
 * Handle the "/otr" command.
 */
static void cmd_otr(const char *data, void *server, WI_ITEM_REC *item)
{
	char *cmd = NULL;
	QUERY_REC *query;

	query = QUERY(item);

	if (*data == '\0') {
		IRSSI_INFO(NULL, NULL, "Alive!");
		goto end;
	}

	utils_extract_command(data, &cmd);
	if (!cmd) {
		/* ENOMEM and cmd is untouched. */
		goto end;
	}

	if (query && query->server && query->server->connrec) {
		cmd_generic(user_state_global, query->server, query->name, cmd, data);
	} else {
		cmd_generic(user_state_global, NULL, NULL, cmd, data);
	}

	statusbar_items_redraw("otr");

end:
	free(cmd);
	return;
}

/*
 * Optionally finish conversations on /quit. We're already doing this on unload
 * but the quit handler terminates irc connections before unloading.
 */
static void cmd_quit(const char *data, void *server, WI_ITEM_REC *item)
{
	otr_finishall(user_state_global);
}

/*
 * Handle otr statusbar of irssi.
 */
static void otr_statusbar(struct SBAR_ITEM_REC *item, int get_size_only)
{
	WI_ITEM_REC *wi = active_win->active;
	QUERY_REC *query = QUERY(wi);
	int formatnum = 0;

	if (query && query->server && query->server->connrec) {
		formatnum = otr_getstatus_format(query->server, query->name);
	}

	statusbar_item_default_handler(item, get_size_only,
			formatnum ? formats[formatnum].def : "", " ", FALSE);
}

static void read_settings(void)
{
	otr_setpolicies(user_state_global, settings_get_str("otr_policy"), FALSE);
	otr_setpolicies(user_state_global, settings_get_str("otr_policy_known"), TRUE);

#ifdef HAVE_GREGEX_H
	if (regex_nickignore) {
		g_regex_unref(regex_nickignore);
	}

	regex_nickignore = g_regex_new(settings_get_str("otr_ignore"), 0, 0, NULL);
#endif
}

void irssi_send_message(SERVER_REC *irssi, const char *recipient,
		const char *msg)
{
	/* XXX: Maybe an assert here. Code flow error? */
	if (irssi) {
		irssi->send_message(irssi, recipient, msg,
				GPOINTER_TO_INT(SEND_TARGET_NICK));
	}
}

/*
 * irssi init()
 */
void otr_init(void)
{
	module_register(MODULE_NAME, "core");

	theme_register(formats);

	otr_lib_init();

	/*
	 * Username does not really matter here since well... we got only one :).
	 */
	user_state_global = otr_init_user("one to rule them all");
	if (!user_state_global) {
		IRSSI_MSG("Unable to allocate user global state");
		return;
	}

	signal_add_first("server sendmsg", (SIGNAL_FUNC) sig_server_sendmsg);
	signal_add_first("message private", (SIGNAL_FUNC) sig_message_private);
	signal_add("query destroyed", (SIGNAL_FUNC) sig_query_destroyed);

	command_bind("otr", NULL, (SIGNAL_FUNC) cmd_otr);
	command_bind_first("quit", NULL, (SIGNAL_FUNC) cmd_quit);
	command_bind_irc_first("me", NULL, (SIGNAL_FUNC) cmd_me);

	settings_add_str("otr", "otr_policy", OTR_DEFAULT_POLICY);
	settings_add_str("otr", "otr_policy_known", OTR_DEFAULT_POLICY_KNOWN);
	settings_add_str("otr", "otr_ignore", OTR_DEFAULT_IGNORE);
	settings_add_bool("otr", "otr_finishonunload", TRUE);
	settings_add_bool("otr", "otr_createqueries", TRUE);

	read_settings();

	signal_add("setup changed", (SIGNAL_FUNC) read_settings);

	statusbar_item_register("otr", NULL, otr_statusbar);
	statusbar_items_redraw("window");

	perl_signal_register("otr event", signal_args_otr_event);
}

/*
 * irssi deinit()
 */
void otr_deinit(void)
{
#ifdef HAVE_GREGEX_H
	g_regex_unref(regex_nickignore);
#endif

	signal_remove("server sendmsg", (SIGNAL_FUNC) sig_server_sendmsg);
	signal_remove("message private", (SIGNAL_FUNC) sig_message_private);
	signal_remove("query destroyed", (SIGNAL_FUNC) sig_query_destroyed);

	command_unbind("otr", (SIGNAL_FUNC) cmd_otr);
	command_unbind("quit", (SIGNAL_FUNC) cmd_quit);
	command_unbind("me", (SIGNAL_FUNC) cmd_me);

	signal_remove("setup changed", (SIGNAL_FUNC) read_settings);

	statusbar_item_unregister("otr");

	otr_finishall(user_state_global);

	otr_free_user(user_state_global);

	otr_lib_uninit();

	theme_unregister();
}
