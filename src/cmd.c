/*
 * Off-the-Record Messaging (OTR) modules for IRC
 *
 * Copyright (C) 2008  Uli Meis <a.sporto+bee@gmail.com>
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

#include "cmd.h"
#include "key.h"

/*
 * /otr debug
 */
static void _cmd_debug(struct otr_user_state *ustate, IRC_CTX *ircctx, int argc, char *argv[],
		char *argv_eol[], char *target, const char *orig_args)
{
	debug = !debug;
	otr_noticest(debug ? TXT_CMD_DEBUG_ON : TXT_CMD_DEBUG_OFF);
}

/*
 * /otr version 
 */
static void _cmd_version(struct otr_user_state *ustate, IRC_CTX *ircctx, int argc, char *argv[],
		char *argv_eol[], char *target, const char *orig_args)
{
	otr_noticest(TXT_CMD_VERSION, IRCOTR_VERSION);
}

/*
 * /otr help 
 */
static void _cmd_help(struct otr_user_state *ustate, IRC_CTX *ircctx, int argc, char *argv[],
		char *argv_eol[], char *target, const char *orig_args)
{
	otr_log(ircctx, target, MSGLEVEL_CRAP, otr_help);
}

/*
 * /otr finish 
 */
static void _cmd_finish(struct otr_user_state *ustate, IRC_CTX *ircctx, int argc, char *argv[],
		char *argv_eol[], char *target, const char *orig_args)
{
	if (argc) {
		otr_finish(NULL, NULL, argv[0], TRUE);
	} else if (ircctx && target) {
		otr_finish(ircctx, target, NULL, TRUE);
	} else {
		otr_noticest(TXT_CMD_QNOTFOUND);
	}
}

/*
 * /otr trust
 */
static void _cmd_trust(struct otr_user_state *ustate, IRC_CTX *ircctx, int argc, char *argv[],
		char *argv_eol[], char *target, const char *orig_args)
{
	if (argc) {
		otr_trust(NULL, NULL, argv[0]);
	} else if (ircctx && target) {
		otr_trust(ircctx, target, NULL);
	} else {
		otr_noticest(TXT_CMD_QNOTFOUND);
	}
}

/*
 * /otr authabort
 */
static void _cmd_authabort(struct otr_user_state *ustate, IRC_CTX *ircctx, int argc,
		char *argv[], char *argv_eol[], char *target, const char *orig_args)
{
	if (argc) {
		otr_authabort(NULL, NULL, argv[0]);
	} else if (ircctx && target) {
		otr_authabort(ircctx, target, NULL);
	} else {
		otr_noticest(TXT_CMD_QNOTFOUND);
	}
}

/*
 * /otr genkey
 */
static void _cmd_genkey(struct otr_user_state *ustate, IRC_CTX *ircctx, int argc, char *argv[],
		char *argv_eol[], char *target, const char *orig_args)
{
	if (argc) {
		if (strncmp(argv[0], "abort", strlen("abort")) == 0) {
			key_generation_abort(ustate, FALSE);
		} else if (strchr(argv[0], '@')) {
			key_generation_run(ustate, argv[0]);
		} else {
			otr_noticest(TXT_KG_NEEDACC);
		}
	} else {
		otr_noticest(TXT_KG_NEEDACC);
	}
}

/*
 * Generic internal function for /otr auth command.
 */
static void _auth(struct otr_user_state *ustate, IRC_CTX *ircctx, int argc,
		char *argv[], char *argv_eol[], char *target, int qanda,
		const char *orig_args)
{
	int ret;
	char *accountname = NULL, *question = NULL, *secret = NULL;

	/* have args? */
	if (argc < (qanda ? 2 : 1)) {
		otr_notice(ircctx, target, TXT_CMD_AUTH);
		goto end;
	}

	/* have buddy? */
	if (!(ircctx && target)) {
		accountname = strchr(argv[0], '@');
		if (!accountname) {
			otr_noticest(TXT_CMD_QNOTFOUND);
			goto end;
		}
		ircctx = NULL;
		target = NULL;
		argv++; argv_eol++; argc--;
	}

	/* have question? */
	if (qanda) {
		ret = utils_io_extract_smp(orig_args, &question, &secret);
		if (ret < 0) {
			otr_notice(ircctx, target, TXT_CMD_AUTH);
			goto end;
		}
	} else {
		secret = argv_eol[0];
	}

	otr_auth(ircctx, target, accountname, question, secret);

	free(question);
	if (qanda) {
		free(secret);
	}

end:
	return;
}

/*
 * /otr authq (Authentication with a question)
 */
static void _cmd_authq(struct otr_user_state *ustate, IRC_CTX *ircctx, int argc,
		char *argv[], char *argv_eol[], char *target, const char *orig_args)
{
	_auth(ustate, ircctx, argc, argv, argv_eol, target, TRUE, orig_args);
}

/*
 * /otr auth
 */
static void _cmd_auth(struct otr_user_state *ustate, IRC_CTX *ircctx, int argc, char *argv[],
		char *argv_eol[], char *target, const char *orig_args)
{
	_auth(ustate, ircctx, argc, argv, argv_eol, target, FALSE, orig_args);
}

/*
 * /otr contexts
 */
static void _cmd_contexts(struct otr_user_state *ustate, IRC_CTX *ircctx, int argc,
		char *argv[], char *argv_eol[], char *target, const char *orig_args)
{
	struct ctxlist_ *ctxlist = otr_contexts(ustate), *ctxnext = ctxlist;
	struct fplist_ *fplist, *fpnext;

	if (!ctxlist) {
		otr_infost(TXT_CTX_NOCTXS);
	}

	while (ctxlist) {
		otr_infost(TXT_CTX_CTX_UNENCRYPTED + ctxlist->state, ctxlist->username,
				ctxlist->accountname);

		fplist = ctxlist->fplist;
		while (fplist) {
			otr_infost(TXT_CTX_FPS_NO + fplist->authby, fplist->fp);
			fplist = fplist->next;
		}
		ctxlist = ctxlist->next;
	}
	while ((ctxlist = ctxnext)) {
		ctxnext = ctxlist->next;
		fpnext = ctxlist->fplist;
		while ((fplist = fpnext)) {
			fpnext = fplist->next;
			g_free(fplist->fp);
			g_free(fplist);
		}
		g_free(ctxlist);
	}
}

static void _cmd_init(struct otr_user_state *ustate, SERVER_REC *irssi, int argc,
		char *argv[], char *argv_eol[], char *target, const char *orig_args)
{
	char *msg;
	ConnContext *ctx;

	/* No server object, just ignore the request */
	if (!irssi || !target) {
		otr_noticest(TXT_CMD_QNOTFOUND);
		goto end;
	}

	ctx = otr_find_context(irssi, target, 0);
	if (ctx && ctx->msgstate == OTRL_MSGSTATE_ENCRYPTED) {
		IRSSI_NOTICE(irssi, target, "%9OTR%9: Already secure!");
		goto end;
	}

	IRSSI_NOTICE(irssi, target, "%9OTR%9: Initiating OTR session...");

	msg = otrl_proto_default_query_msg(target, OTRL_POLICY_DEFAULT);
	irssi_send_message(irssi, target, msg ? msg : "?OTRv23?");
	free(msg);

end:
	return;
}

static void _cmd_forget(struct otr_user_state *ustate, SERVER_REC *irssi,
		int argc, char *argv[], char *argv_eol[], char *target,
		const char *orig_args)
{
	char str_fp[OTRL_PRIVKEY_FPRINT_HUMAN_LEN], *fp = NULL;

	if (argc == 5) {
		utils_hash_parts_to_readable_hash((const char **) argv, str_fp);
		fp = str_fp;
	} else if (!irssi || (irssi && argc != 0)) {
		/* If no IRSSI or some arguments (not 5), bad command. */
		IRSSI_NOTICE(irssi, target, "%9OTR%9: Usage %9/otr forget [FP]%9 "
				"where FP is the five part of the fingerprint listed by "
				"%9/otr contexts%9 or do the command inside an OTR session "
				"private message window");
		goto error;
	}

	/* Trigger the forget action. */
	otr_forget(irssi, target, fp, ustate);

error:
	return;
}

static void _cmd_distrust(struct otr_user_state *ustate, SERVER_REC *irssi,
		int argc, char *argv[], char *argv_eol[], char *target,
		const char *orig_args)
{
	char str_fp[OTRL_PRIVKEY_FPRINT_HUMAN_LEN], *fp = NULL;

	if (argc == 5) {
		utils_hash_parts_to_readable_hash((const char **) argv, str_fp);
		fp = str_fp;
	} else if (!irssi || (irssi && argc != 0)) {
		/* If no IRSSI or some arguments (not 5), bad command. */
		IRSSI_NOTICE(irssi, target, "%9OTR%9: Usage %9/otr distrust [FP]%9 "
				"where FP is the five part of the fingerprint listed by "
				"%9/otr contexts%9 or do the command inside an OTR session "
				"private message window");
		goto error;
	}

	/* Trigger the forget action. */
	otr_distrust(irssi, target, fp, ustate);

error:
	return;
}

static struct irssi_commands cmds[] = {
	{ "version", _cmd_version },
	{ "debug", _cmd_debug },
	{ "help", _cmd_help },
	{ "init", _cmd_init },
	{ "finish", _cmd_finish },
	{ "trust", _cmd_trust },
	{ "distrust", _cmd_distrust },
	{ "forget", _cmd_forget },
	{ "authabort", _cmd_authabort },
	{ "auth", _cmd_auth },
	{ "authq", _cmd_authq },
	{ "genkey", _cmd_genkey },
	{ "contexts", _cmd_contexts },
	{ NULL, NULL },
	{ NULL, NULL }
};

/*
 * Entry point for all other commands.
 *
 * Return TRUE if command exist and is executed else FALSE.
 */
int cmd_generic(struct otr_user_state *ustate, IRC_CTX *ircctx, int argc, char *argv[],
		char *argv_eol[], char *target, const char *orig_args)
{
	char *cmd;
	struct irssi_commands *commands = cmds;

	if (!argc) {
		otr_noticest(TXT_CMD_OTR);
		goto done;
	}

	cmd = argv[0];

	argv++;
	argv_eol++;
	argc--;

	do {
		if (strcmp(commands->name, cmd) == 0) {
			commands->func(ustate, ircctx, argc, argv, argv_eol, target,
					orig_args);
			goto done;
		}
	} while ((++commands)->name);

	return FALSE;

done:
	return TRUE;
}
