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

static const char *signal_args_otr_event[] = {
	"iobject", "string", "string", "NULL"
};

#ifdef HAVE_GREGEX_H
GRegex *regex_nickignore = NULL;
#endif

/* need this to decode arguments in perl signal handlers. Maybe irssi should
 * install perl/perl-signals.h which is where this definition comes from? */
void perl_signal_register(const char *signal, const char **args);

static IOUSTATE *ioustate;

void irc_send_message(IRC_CTX *ircctx, const char *recipient, char *msg)
{
	ircctx->send_message(
		ircctx, recipient, msg, GPOINTER_TO_INT(SEND_TARGET_NICK));
}

/*
 * Pipes all outgoing private messages through OTR
 */
static void sig_server_sendmsg(SERVER_REC *server, const char *target,
			       const char *msg, void *target_type_p)
{
	if (GPOINTER_TO_INT(target_type_p) == SEND_TARGET_NICK) {
		char *otrmsg;

#ifdef HAVE_GREGEX_H
		if (g_regex_match(regex_nickignore, target, 0, NULL))
			return;
#endif
		otrmsg = otr_send(server, msg, target);
		if (otrmsg && (otrmsg != msg)) {
			signal_continue(4, server, target, otrmsg,
					target_type_p);
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

#ifdef HAVE_GREGEX_H
	if (g_regex_match(regex_nickignore, nick, 0, NULL))
		return;
#endif

	newmsg = otr_receive(server, msg, nick);

	if (newmsg && (newmsg != msg)) {
		if (g_str_has_prefix(newmsg, IRCACTIONMARK)) {
			signal_stop();
			signal_emit("message irc action",
				    5,
				    server,
				    newmsg + IRCACTIONMARKLEN,
				    nick,
				    address,
				    nick);
		} else {
			signal_continue(4, server, newmsg, nick, address);
		}
		otrl_message_free(newmsg);
	} else if (newmsg == NULL)
		signal_stop();
}

static void cmd_me(const char *data, IRC_SERVER_REC *server,
		   WI_ITEM_REC *item)
{
	QUERY_REC *query = QUERY(item);
	const char *target;
	char *otrmsg, *msg;
	int unchanged;

	if (!query || !query->server)
		return;

	CMD_IRC_SERVER(server);
	if (!IS_IRC_QUERY(item))
		return;

	if (server == NULL || !server->connected)
		cmd_return_error(CMDERR_NOT_CONNECTED);

	target = window_item_get_target(item);

#ifdef HAVE_GREGEX_H
	if (g_regex_match(regex_nickignore, target, 0, NULL))
		return;
#endif

	/* since we can't track the message anymore once it's encrypted,
	 * mark it as a /me inline.
	 */
	msg = g_strconcat(IRCACTIONMARK, data, NULL);
	otrmsg = otr_send(query->server, msg, target);

	unchanged = otrmsg == msg;
	g_free(msg);

	if (unchanged)
		return;

	signal_stop();

	if (otrmsg) {
		irc_send_message(SERVER(server), target, otrmsg);
		otrl_message_free(otrmsg);
	}

	signal_emit("message irc own_action", 3, server, data,
		    item->visible_name);
}


/*
 * Finish an OTR conversation when its query is closed.
 */
static void sig_query_destroyed(QUERY_REC *query)
{
	if (query && query->server && query->server->connrec) {
		otr_finish(query->server, query->name, NULL, FALSE);
	}
}

/*
 * /otr
 */
static void cmd_otr(const char *data, void *server, WI_ITEM_REC *item)
{
	char **argv, **argv_eol;
	int argc;
	QUERY_REC *query = QUERY(item);

	if (*data == '\0') {
		otr_noticest(TXT_CMD_OTR);
		return;
	}

	io_explode_args(data, &argv, &argv_eol, &argc);

	if (query && query->server && query->server->connrec) {
		cmd_generic(ioustate, query->server, argc, argv, argv_eol,
			    query->name);
	} else {
		cmd_generic(ioustate, NULL, argc, argv, argv_eol, NULL);
	}

	statusbar_items_redraw("otr");

	g_free(argv_eol[0]);
	g_free(argv_eol);
	g_free(argv);
}

/*
 * Optionally finish conversations on /quit. We're already doing this on unload
 * but the quit handler terminates irc connections before unloading.
 */
static void cmd_quit(const char *data, void *server, WI_ITEM_REC *item)
{
	if (settings_get_bool("otr_finishonunload"))
		otr_finishall(ioustate);
}

/*
 * otr statusbar
 */
static void otr_statusbar(struct SBAR_ITEM_REC *item, int get_size_only)
{
	WI_ITEM_REC *wi = active_win->active;
	QUERY_REC *query = QUERY(wi);
	int formatnum = 0;

	if (query && query->server && query->server->connrec)
		formatnum = otr_getstatus_format(query->server, query->name);

	statusbar_item_default_handler(
		item,
		get_size_only,
		formatnum ? formats[formatnum].def : "", " ", FALSE);
}

void otr_query_create(SERVER_REC *server, const char *nick)
{
	if (!server || !nick ||
	    !settings_get_bool("otr_createqueries") ||
	    query_find(server, nick))
		return;

	irc_query_create(server->tag, nick, TRUE);
}

static void read_settings(void)
{
	otr_setpolicies(ioustate, settings_get_str("otr_policy"), FALSE);
	otr_setpolicies(ioustate, settings_get_str("otr_policy_known"), TRUE);
#ifdef HAVE_GREGEX_H
	if (regex_nickignore)
		g_regex_unref(regex_nickignore);
	regex_nickignore = g_regex_new(settings_get_str(
					       "otr_ignore"), 0, 0, NULL);
#endif
}

void otr_status_change(IRC_CTX *ircctx, const char *nick, int event)
{
	statusbar_items_redraw("otr");
	signal_emit("otr event", 3, ircctx, nick, otr_status_txt[event]);
}

/*
 * irssi init()
 */
void otr_init(void)
{
	module_register(MODULE_NAME, "core");

	theme_register(formats);

	if (otrlib_init())
		return;

	ioustate = otr_init_user("one to rule them all");

	signal_add_first("server sendmsg", (SIGNAL_FUNC)sig_server_sendmsg);
	signal_add_first("message private", (SIGNAL_FUNC)sig_message_private);
	command_bind_irc_first("me", NULL, (SIGNAL_FUNC)cmd_me);
	signal_add("query destroyed", (SIGNAL_FUNC)sig_query_destroyed);

	command_bind("otr", NULL, (SIGNAL_FUNC)cmd_otr);

	command_bind_first("quit", NULL, (SIGNAL_FUNC)cmd_quit);

	settings_add_str("otr", "otr_policy", IO_DEFAULT_POLICY);
	settings_add_str("otr", "otr_policy_known", IO_DEFAULT_POLICY_KNOWN);
	settings_add_str("otr", "otr_ignore", IO_DEFAULT_IGNORE);
	settings_add_bool("otr", "otr_finishonunload", TRUE);
	settings_add_bool("otr", "otr_createqueries", TRUE);
	read_settings();
	signal_add("setup changed", (SIGNAL_FUNC)read_settings);

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

	signal_remove("server sendmsg", (SIGNAL_FUNC)sig_server_sendmsg);
	signal_remove("message private", (SIGNAL_FUNC)sig_message_private);
	command_unbind("me", (SIGNAL_FUNC)cmd_me);
	signal_remove("query destroyed", (SIGNAL_FUNC)sig_query_destroyed);

	command_unbind("otr", (SIGNAL_FUNC)cmd_otr);

	command_unbind("quit", (SIGNAL_FUNC)cmd_quit);

	signal_remove("setup changed", (SIGNAL_FUNC)read_settings);

	statusbar_item_unregister("otr");

	if (settings_get_bool("otr_finishonunload"))
		otr_finishall(ioustate);

	otr_deinit_user(ioustate);

	otrlib_deinit();

	theme_unregister();
}

IRC_CTX *ircctx_by_peername(const char *peername, char *nick)
{
	GSList *tmp;
	char pname[256];
	char *address;

	strcpy(pname, peername);

	address = strchr(pname, '@');

	if (!address)
		return NULL;

	*address = '\0';
	strcpy(nick, pname);
	*address++ = '@';

	for (tmp = servers; tmp != NULL; tmp = tmp->next) {
		SERVER_REC *server = tmp->data;

		if (g_strcasecmp(server->connrec->address, address) == 0)
			return server;
	}

	return NULL;
}

char *lvlstring[] = {
	"NOTICE",
	"DEBUG"
};


void otr_log(IRC_CTX *server, const char *nick,
	     int level, const char *format, ...)
{
	va_list params;
	va_start(params, format);
	char msg[LOGMAX], *s = msg;

	if ((level == LVL_DEBUG) && !debug)
		return;

	s += sprintf(s, "%s", "%9OTR%9");

	if (level != LVL_NOTICE)
		s += sprintf(s, "(%s)", lvlstring[level]);

	s += sprintf(s, ": ");

	if (vsnprintf(s, LOGMAX, format, params) < 0)
		sprintf(s, "internal error parsing error string (BUG)");
	va_end(params);

	printtext(server, nick, MSGLEVEL_MSGS, msg);
}
