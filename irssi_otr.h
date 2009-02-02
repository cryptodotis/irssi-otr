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

#include <fe-text/statusbar-item.h>

#define IRC_CTX SERVER_REC

static IRC_CTX *IRCCTX_DUP(IRC_CTX *ircctx) __attribute__ ((unused));

static IRC_CTX *IRCCTX_DUP(IRC_CTX *ircctx) {
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

#define otr_noticest(formatnum,...) \
	printformat(NULL,NULL,MSGLEVEL_MSGS, formatnum, ## __VA_ARGS__)

#define otr_notice(ircctx,nick,formatnum,...) { \
	otr_query_create(ircctx,nick); \
	printformat(ircctx,nick,MSGLEVEL_MSGS, formatnum, ## __VA_ARGS__);}

#define otr_infost(formatnum,...) \
	printformat(NULL,NULL,MSGLEVEL_CRAP, formatnum, ## __VA_ARGS__)

#define otr_info(server,nick,formatnum,...) { \
	otr_query_create(ircctx,nick); \
	printformat(ircctx,nick,MSGLEVEL_CRAP, formatnum, ## __VA_ARGS__);}

#define otr_debug(ircctx,nick,formatnum,...) { \
	if (debug) { \
		otr_query_create(ircctx,nick); \
		printformat(ircctx,nick,MSGLEVEL_MSGS, formatnum, ## __VA_ARGS__); } }
