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

#define UOFF_T_LONG_LONG 1

#include <src/common.h>
#include <src/core/commands.h>
#include <src/core/modules.h>
#include <src/core/servers.h>
#include <src/core/signals.h>
#include <src/core/levels.h>
#include <src/core/queries.h>
#include <src/fe-common/core/printtext.h>
#include <src/fe-common/core/fe-windows.h>
#include <src/fe-common/core/module-formats.h>
#include <src/core/modules.h>
#include <src/core/settings.h>
#include <src/irc/core/irc.h>
#include <src/irc/core/irc-queries.h>
#include <src/fe-text/statusbar-item.h>

#define IRC_CTX SERVER_REC

#define get_client_config_dir get_irssi_dir

static IRC_CTX *IRSSI_DUP(IRC_CTX *ircctx) __attribute__ ((unused));

static IRC_CTX *IRSSI_DUP(IRC_CTX *ircctx) {
	server_ref(ircctx);
	return ircctx;
}

static IRC_CTX *IRSSI_FREE(IRC_CTX *ircctx) __attribute__ ((unused));

static IRC_CTX *IRSSI_FREE(IRC_CTX *ircctx)
{
	server_unref(ircctx);
	return ircctx;
}

void otr_query_create(IRC_CTX *ircctx, const char *nick);

#define IRSSI_CONN_ADDR(i) i->connrec->address
#define IRSSI_NICK(i) i->nick
#define IRSSI_ACCNAME(accname, i) sprintf(accname, "%s@%s", i->nick, IRSSI_CONN_ADDR(i))
#define IRSSI_IO_US(i) (&ioustate_uniq)
#define IO_CREATE_US(user) (&ioustate_uniq)

#define otr_noticest(formatnum,...) \
	printformat(NULL,NULL,MSGLEVEL_MSGS, formatnum, ## __VA_ARGS__)

#define otr_notice(irssi, nick, formatnum, ...) { \
	otr_query_create(irssi, nick); \
	printformat(irssi, nick, MSGLEVEL_MSGS, formatnum, ## __VA_ARGS__);}

#define otr_infost(formatnum,...) \
	printformat(NULL,NULL,MSGLEVEL_CRAP, formatnum, ## __VA_ARGS__)

#define otr_info(server, nick, formatnum, ...) { \
	otr_query_create(server, nick); \
	printformat(server, nick, MSGLEVEL_CRAP, formatnum, ## __VA_ARGS__);}

#define otr_debug(irssi, nick, formatnum, ...) { \
	if (debug) { \
		otr_query_create(irssi, nick); \
		printformat(irssi, nick, MSGLEVEL_MSGS, formatnum, ## __VA_ARGS__); } }

/*
 * Irssi macros for printing text to console.
 */
#define IRSSI_NOTICE(irssi, username, fmt, ...) \
	printtext(irssi, username, MSGLEVEL_MSGS, fmt, ## __VA_ARGS__);
#define IRSSI_WARN(irssi, username, fmt, ...) \
	printtext(irssi, username, MSGLEVEL_HILIGHT, fmt, ## __VA_ARGS__);
#define IRSSI_DEBUG(irssi, username, fmt, ...) \
	do {                                                                    \
		if (debug) {                                                        \
			printtext(irssi, username, MSGLEVEL_MSGS, fmt, ## __VA_ARGS__); \
		}                                                                   \
	} while (0)
