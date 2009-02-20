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

#include "xchat-plugin.h"

#define PNAME "xchat-otr"
#define PDESC "Off-The-Record Messaging for xchat"
#define PVERSION IRCOTR_VERSION

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

extern xchat_plugin *ph;   /* plugin handle */

/* stuff from io_set.c */
extern char set_policy[512];
extern char set_policy_known[512];
extern char set_ignore[512];
extern int set_finishonunload;
void cmd_set(IOUSTATE *ioustate, IRC_CTX *ircctx, int argc, 
	     char *argv[], char *argv_eol[], char *target);

#define get_client_config_dir() xchat_get_info(ph,"xchatdir")

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
#define IRCCTX_DUP(ircctx) g_memdup(ircctx,sizeof(IRC_CTX));
#define IRCCTX_ADDR(ircctx) ircctx->address
#define IRCCTX_NICK(ircctx) ircctx->nick
#define IRCCTX_FREE(ircctx) g_free(ircctx)
#define IRCCTX_ACCNAME(accname,ircctx) sprintf(accname, "%s@%s", ircctx->nick, ircctx->address)
#define IRCCTX_IO_US(ircctx) (&ioustate_uniq)
#define IO_CREATE_US(user) (&ioustate_uniq)
