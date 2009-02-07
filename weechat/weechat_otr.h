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

#include "weechat-plugin.h"

extern struct t_weechat_plugin *weechat_otr_plugin;
#define weechat_plugin weechat_otr_plugin

#define MAX_FORMAT_PARAMS 10

struct _IRC_CTX {
	char *nick;
	char *address;
};

typedef struct _IRC_CTX IRC_CTX;
struct _FORMAT_REC {
	char *tag;
	char *def;

	int params;
	int paramtypes[MAX_FORMAT_PARAMS];
};

typedef struct _FORMAT_REC FORMAT_REC;

enum { MSGLEVEL_CRAP, MSGLEVEL_MSGS } lvls;

#define statusbar_items_redraw(name) ;
#define get_client_config_dir() weechat_info_get("weechat_dir",NULL)

void printformat(IRC_CTX *ircctx, const char *nick, int lvl, int fnum, ...);

#define otr_noticest(formatnum,...) \
	printformat(NULL,NULL,MSGLEVEL_MSGS, formatnum, ## __VA_ARGS__)

#define otr_notice(server,nick,formatnum,...) \
	printformat(server,nick,MSGLEVEL_MSGS, formatnum, ## __VA_ARGS__)

#define otr_infost(formatnum,...) \
	printformat(NULL,NULL,MSGLEVEL_CRAP, formatnum, ## __VA_ARGS__)

#define otr_info(server,nick,formatnum,...) \
	printformat(server,nick,MSGLEVEL_CRAP, formatnum, ## __VA_ARGS__)

#define otr_debug(server,nick,formatnum,...) { \
	if (debug) \
		printformat(server,nick, \
			    MSGLEVEL_MSGS, formatnum, ## __VA_ARGS__); \
}

static IRC_CTX *IRCCTX_DUP(IRC_CTX *ircctx) __attribute__ ((unused));
static void IRCCTX_FREE(IRC_CTX *ircctx) __attribute__ ((unused));

//#define IRCCTX_DUP(ircctx) g_memdup(ircctx,sizeof(IRC_CTX));
static IRC_CTX *IRCCTX_DUP(IRC_CTX *ircctx)
{
	IRC_CTX *nctx = g_memdup(ircctx,sizeof(IRC_CTX));

	nctx->nick = strdup(ircctx->nick);
	nctx->address = strdup(ircctx->address);

	return nctx;
}

#define IRCCTX_ADDR(ircctx) ircctx->address
#define IRCCTX_NICK(ircctx) ircctx->nick
//#define IRCCTX_FREE(ircctx) g_free(ircctx)
static void IRCCTX_FREE(IRC_CTX *ircctx)
{
	g_free(ircctx->nick);
	g_free(ircctx->address);
	g_free(ircctx);
}
