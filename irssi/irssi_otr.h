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

#include <common.h>
#include <core/commands.h>
#include <core/modules.h>
#include <core/servers.h>
#include <core/signals.h>
#include <core/levels.h>
#include <core/queries.h>
#include <fe-common/core/printtext.h>
#include <fe-common/core/fe-windows.h>
#include <fe-common/core/module-formats.h>
#include <core/modules.h>
#include <core/settings.h>
#include <irc/core/irc.h>
#include <irc/core/irc-queries.h>
#include <irc/core/irc-servers.h>
#include <irc/core/irc-commands.h>

#include <fe-text/statusbar-item.h>

#define IRC_CTX SERVER_REC

#define get_client_config_dir get_irssi_dir

static IRC_CTX *IRCCTX_DUP(IRC_CTX *ircctx) __attribute__ ((unused));

static IRC_CTX *IRCCTX_DUP(IRC_CTX *ircctx)
{
	server_ref(ircctx);
	return ircctx;
}

static IRC_CTX *IRCCTX_FREE(IRC_CTX *ircctx) __attribute__ ((unused));

static IRC_CTX *IRCCTX_FREE(IRC_CTX *ircctx)
{
	server_unref(ircctx);
	return ircctx;
}

void otr_query_create(IRC_CTX *ircctx, const char *nick);

#define IRCCTX_ADDR(ircctx) ircctx->connrec->address
#define IRCCTX_NICK(ircctx) ircctx->nick
#define IRCCTX_ACCNAME(accname, ircctx) sprintf(accname, "%s@%s", \
						ircctx->nick, \
						ircctx->connrec->address)
#define IRCCTX_IO_US(ircctx) (&ioustate_uniq)
#define IO_CREATE_US(user) (&ioustate_uniq)

#define otr_noticest(formatnum, ...) \
	printformat(NULL, NULL, MSGLEVEL_MSGS, formatnum, ## __VA_ARGS__)

#define otr_notice(ircctx, nick, formatnum, ...) { \
		otr_query_create(ircctx, nick);	\
		printformat(ircctx, nick, MSGLEVEL_MSGS, formatnum, \
			    ## __VA_ARGS__); }

#define otr_infost(formatnum, ...) \
	printformat(NULL, NULL, MSGLEVEL_CRAP, formatnum, ## __VA_ARGS__)

#define otr_info(server, nick, formatnum, ...) { \
		otr_query_create(ircctx, nick);	\
		printformat(ircctx, nick, MSGLEVEL_CRAP, formatnum, \
			    ## __VA_ARGS__); }

#define otr_debug(ircctx, nick, formatnum, ...) { \
		if (debug) { \
			otr_query_create(ircctx, nick);	\
			printformat(ircctx, nick, MSGLEVEL_MSGS, formatnum, \
				    ## __VA_ARGS__); } }
