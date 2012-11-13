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
static void _cmd_debug(struct otr_user_state *ustate, SERVER_REC *irssi,
		int argc, char *argv[], char *argv_eol[], char *target,
		const char *orig_args)
{
	debug = !debug;
	if (debug) {
		IRSSI_INFO(NULL, NULL, "Debug on");
	} else {
		IRSSI_INFO(NULL, NULL, "Debug off");
	}
}

/*
 * /otr version 
 */
static void _cmd_version(struct otr_user_state *ustate, SERVER_REC *irssi,
		int argc, char *argv[], char *argv_eol[], char *target,
		const char *orig_args)
{
	IRSSI_INFO(NULL, NULL, "OTR module version: " VERSION);
}

/*
 * /otr help 
 */
static void _cmd_help(struct otr_user_state *ustate, SERVER_REC *irssi, int argc, char *argv[],
		char *argv_eol[], char *target, const char *orig_args)
{
	IRSSI_INFO(NULL, NULL, "%s", otr_help);
}

/*
 * /otr finish 
 */
static void _cmd_finish(struct otr_user_state *ustate, SERVER_REC *irssi,
		int argc, char *argv[], char *argv_eol[], char *target,
		const char *orig_args)
{
	if (!irssi || !target) {
		IRSSI_WARN(irssi, target,
				"Failed: Can't get nick and server of current query window. "
				"(Or maybe you're doing this in the status window?)");
		goto end;
	}

	otr_finish(irssi, target);

end:
	return;
}

/*
 * /otr trust
 */
static void _cmd_trust(struct otr_user_state *ustate, SERVER_REC *irssi,
		int argc, char *argv[], char *argv_eol[], char *target,
		const char *orig_args)
{
	if (!irssi || !target) {
		IRSSI_WARN(irssi, target,
				"Failed: Can't get nick and server of current query window. "
				"(Or maybe you're doing this in the status window?)");
		goto end;
	}

	otr_trust(irssi, target);

end:
	return;
}

/*
 * /otr authabort
 */
static void _cmd_authabort(struct otr_user_state *ustate, SERVER_REC *irssi,
		int argc, char *argv[], char *argv_eol[], char *target,
		const char *orig_args)
{
	if (!irssi || !target) {
		IRSSI_WARN(irssi, target,
				"Failed: Can't get nick and server of current query window. "
				"(Or maybe you're doing this in the status window?)");
		goto end;
	}

	otr_auth_abort(irssi, target);

end:
	return;
}

/*
 * /otr genkey
 */
static void _cmd_genkey(struct otr_user_state *ustate, SERVER_REC *irssi,
		int argc, char *argv[], char *argv_eol[], char *target,
		const char *orig_args)
{
	if (argc) {
		if (strncmp(argv[0], "abort", strlen("abort")) == 0) {
			key_generation_abort(ustate, FALSE);
		} else if (strchr(argv[0], '@')) {
			key_generation_run(ustate, argv[0]);
		} else {
			IRSSI_INFO(NULL, NULL, "I need an account name. "
					"Try something like /otr genkey mynick@irc.server.net");
		}
	} else {
		IRSSI_INFO(NULL, NULL, "I need an account name. "
				"Try something like /otr genkey mynick@irc.server.net");
	}
}

/*
 * Generic internal function for /otr auth command.
 */
static void _auth(struct otr_user_state *ustate, SERVER_REC *irssi, int argc,
		char *argv[], char *argv_eol[], char *target, int qanda,
		const char *orig_args)
{
	int ret;
	char *question = NULL, *secret = NULL;

	/* have question? */
	if (qanda) {
		ret = utils_io_extract_smp(orig_args, &question, &secret);
		if (ret < 0) {
			IRSSI_NOTICE(irssi, target, "Usage: %9/otr authq [QUESTION] "
					"SECRET%9");
			goto end;
		}
	} else {
		secret = argv_eol[0];
	}

	otr_auth(irssi, target, question, secret);

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
static void _cmd_authq(struct otr_user_state *ustate, SERVER_REC *irssi,
		int argc, char *argv[], char *argv_eol[], char *target,
		const char *orig_args)
{
	if (argc == 0) {
		IRSSI_NOTICE(irssi, target, "Huh... I need a question here Bob.");
		goto end;
	}

	_auth(ustate, irssi, argc, argv, argv_eol, target, TRUE, orig_args);

end:
	return;
}

/*
 * /otr auth
 */
static void _cmd_auth(struct otr_user_state *ustate, SERVER_REC *irssi, int argc,
		char *argv[], char *argv_eol[], char *target, const char *orig_args)
{
	if (argc == 0) {
		IRSSI_NOTICE(irssi, target, "Huh... I need a secret here James.");
		goto end;
	}

	_auth(ustate, irssi, argc, argv, argv_eol, target, FALSE, orig_args);

end:
	return;
}

/*
 * /otr contexts
 */
static void _cmd_contexts(struct otr_user_state *ustate, SERVER_REC *irssi,
		int argc, char *argv[], char *argv_eol[], char *target,
		const char *orig_args)
{
	struct ctxlist_ *ctxlist = otr_contexts(ustate), *ctxnext = ctxlist;
	struct fplist_ *fplist, *fpnext;

	if (!ctxlist) {
		IRSSI_INFO(NULL, NULL, "No active OTR contexts found");
		goto end;
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

end:
	return;
}

static void _cmd_init(struct otr_user_state *ustate, SERVER_REC *irssi,
		int argc, char *argv[], char *argv_eol[], char *target,
		const char *orig_args)
{
	char *msg;
	ConnContext *ctx;

	/* No server object, just ignore the request */
	if (!irssi || !target) {
		IRSSI_WARN(irssi, target,
				"Failed: Can't get nick and server of current query window. "
				"(Or maybe you're doing this in the status window?)");
		goto end;
	}

	ctx = otr_find_context(irssi, target, 0);
	if (ctx && ctx->msgstate == OTRL_MSGSTATE_ENCRYPTED) {
		IRSSI_NOTICE(irssi, target, "Already secure!");
		goto end;
	}

	IRSSI_NOTICE(irssi, target, "Initiating OTR session...");

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
	} else if (!irssi || (irssi && argc != 0 &&
				(argc == 1 && argv[0] != NULL))) {
		/* If no IRSSI or some arguments (not 5), bad command. */
		IRSSI_NOTICE(irssi, target, "Usage %9/otr forget [FP]%9 "
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
	} else if (!irssi || (irssi && argc != 0 &&
				(argc == 1 && argv[0] != NULL))) {
		/* If no IRSSI or some arguments (not 5), bad command. */
		IRSSI_NOTICE(irssi, target, "Usage %9/otr distrust [FP]%9 "
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
int cmd_generic(struct otr_user_state *ustate, SERVER_REC *irssi, int argc,
		char *argv[], char *argv_eol[], char *target, const char *orig_args)
{
	char *cmd;
	struct irssi_commands *commands = cmds;

	if (!argc) {
		IRSSI_INFO(NULL, NULL, "Alive");
		goto done;
	}

	cmd = argv[0];

	argv++;
	argv_eol++;
	argc--;

	do {
		if (strcmp(commands->name, cmd) == 0) {
			commands->func(ustate, irssi, argc, argv, argv_eol, target,
					orig_args);
			goto done;
		}
	} while ((++commands)->name);

	return FALSE;

done:
	return TRUE;
}
