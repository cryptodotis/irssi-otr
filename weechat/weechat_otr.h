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

/* stuff from io_set.c */
extern char set_policy[512];
extern char set_policy_known[512];
extern char set_ignore[512];
extern int set_finishonunload;
void cmd_set(IRC_CTX *ircctx, int argc, char *argv[], char *argv_eol[],
	    char *target);

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

static IRC_CTX *IRCCTX_DUP(IRC_CTX *ircctx)
{
	IRC_CTX *nctx = g_memdup(ircctx,sizeof(IRC_CTX));

	nctx->nick = strdup(ircctx->nick);
	nctx->address = strdup(ircctx->address);

	return nctx;
}

#define IRCCTX_ADDR(ircctx) ircctx->address
#define IRCCTX_NICK(ircctx) ircctx->nick
static void IRCCTX_FREE(IRC_CTX *ircctx)
{
	free(ircctx->nick);
	free(ircctx->address);
	free(ircctx);
}

/* Don't look beyond this point. Ugly temporary hack. */

#define g_io_add_watch(pid,a,func,b) gioaddwatchfake(pid,func)

#define g_child_watch_add(pid,func,dunno) gchildwatchaddfake(pid,dunno)
#define g_io_channel_shutdown(channel,FALSE,NULL) \
	close(g_io_channel_unix_get_fd(channel))

#define g_source_remove(a) gsourceremovefake(a)
#define guint  struct t_hook *

#include <sys/types.h>
#include <sys/wait.h>

static void *gchildwatchaddfake(int pid,void *doit) __attribute__ ((unused));
static void *gchildwatchaddfake(int pid,void *doit)
{
	if (doit)
		waitpid(pid,NULL,0);
	return NULL;

}

static void gsourceremovefake(struct t_hook *hook) __attribute__ ((unused));
static void gsourceremovefake(struct t_hook *hook)
{
	if (hook)
		weechat_unhook(hook);

}

gboolean keygen_complete(GIOChannel *source, GIOCondition condition, 
			 gpointer data);

static int cb(void *data)
{
	keygen_complete(NULL,0,NULL);
	return TRUE;
}

static struct t_hook *gioaddwatchfake(GIOChannel *source, int (*func)(GIOChannel *source,
							   GIOCondition condition, 
							   gpointer data)) 
	__attribute__ ((unused));

static struct t_hook *gioaddwatchfake(GIOChannel *source, int (*func)(GIOChannel *source,GIOCondition
					     condition, gpointer data))
{
	return weechat_hook_fd(g_io_channel_unix_get_fd(source),TRUE,FALSE,FALSE,cb,NULL);
}
