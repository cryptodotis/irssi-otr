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

#include <fe-text/statusbar-item.h>

#define IRC_CTX SERVER_REC

/* no need for duplication */
#define IRCCTX_DUP(ircctx) ircctx
#define IRCCTX_ADDR(ircctx) ircctx->connrec->address
#define IRCCTX_NICK(ircctx) ircctx->nick

#define otr_noticest(formatnum,...) \
	printformat(NULL,NULL,MSGLEVEL_MSGS, formatnum, ## __VA_ARGS__)

#define otr_notice(ircctx,nick,formatnum,...) \
		printformat(ircctx,nick,MSGLEVEL_MSGS, formatnum, ## __VA_ARGS__);

#define otr_infost(formatnum,...) \
	printformat(NULL,NULL,MSGLEVEL_CRAP, formatnum, ## __VA_ARGS__)

#define otr_info(server,nick,formatnum,...) \
	printformat(ircctx,nick,MSGLEVEL_CRAP, formatnum, ## __VA_ARGS__)

#define otr_debug(ircctx,nick,formatnum,...) { \
	if (debug) \
		printformat(ircctx,nick,MSGLEVEL_MSGS, formatnum, ## __VA_ARGS__); }
