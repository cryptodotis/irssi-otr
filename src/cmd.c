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

#include <assert.h>

#include "cmd.h"
#include "key.h"

/*
 * /otr debug
 */
static void _cmd_debug(struct otr_user_state *ustate, SERVER_REC *irssi,
		const char *target, const void *data)
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
		const char *target, const void *data)
{
	IRSSI_INFO(NULL, NULL, "OTR module version: " VERSION);
}

/*
 * /otr help 
 */
static void _cmd_help(struct otr_user_state *ustate, SERVER_REC *irssi,
		const char *target, const void *data)
{
	/* TODO: Add help message. */
}

/*
 * /otr finish 
 */
static void _cmd_finish(struct otr_user_state *ustate, SERVER_REC *irssi,
		const char *target, const void *data)
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
		const char *target, const void *data)
{
	int argc;
	char **argv;
	char str_fp[OTRL_PRIVKEY_FPRINT_HUMAN_LEN], *fp = NULL;

	utils_explode_args(data, &argv, &argc);

	if (argc == 5) {
		utils_hash_parts_to_readable_hash((const char **) argv, str_fp);
		fp = str_fp;
	} else if (!irssi || (irssi && argc != 0)) {
		/* If no IRSSI or some arguments (not 5), bad command. */
		IRSSI_NOTICE(irssi, target, "Usage %9/otr trust [FP]%9 "
				"where FP is the five part of the fingerprint listed by "
				"%9/otr contexts%9 or do the command inside an OTR session "
				"private message window.");
		goto end;
	}

	otr_trust(irssi, target, fp, ustate);

end:
	return;
}

/*
 * /otr authabort
 */
static void _cmd_authabort(struct otr_user_state *ustate, SERVER_REC *irssi,
		const char *target, const void *data)
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
		const char *target, const void *data)
{
	int argc;
	char **argv;

	utils_explode_args(data, &argv, &argc);

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

	utils_free_args(&argv, argc);
}

/*
 * /otr authq (Authentication with a question)
 */
static void _cmd_authq(struct otr_user_state *ustate, SERVER_REC *irssi,
		const char *target, const void *data)
{
	int ret;
	char *question = NULL, *secret = NULL;

	if (!irssi || !target) {
		IRSSI_WARN(irssi, target,
				"Failed: Can't get nick and server of current query window. "
				"(Or maybe you're doing this in the status window?)");
		goto end;
	}

	/*
	 * Returns a negative value if the command arguments are not formatted
	 * correctly or missing. Note, an empty question or secret is valid.
	 */
	ret = utils_io_extract_smp(data, &question, &secret);
	if (ret < 0) {
		IRSSI_NOTICE(irssi, target, "Usage: %9/otr authq [QUESTION] "
				"SECRET%9");
		goto end;
	}

	otr_auth(irssi, target, question, secret);

end:
	return;
}

/*
 * /otr auth
 */
static void _cmd_auth(struct otr_user_state *ustate, SERVER_REC *irssi,
		const char *target, const void *data)
{
	int argc;
	char **argv;

	if (!irssi || !target) {
		IRSSI_WARN(irssi, target,
				"Failed: Can't get nick and server of current query window. "
				"(Or maybe you're doing this in the status window?)");
		goto error;
	}

	utils_explode_args(data, &argv, &argc);

	if (argc == 0) {
		IRSSI_NOTICE(irssi, target, "Huh... I need a secret here James.");
		goto end;
	}

	otr_auth(irssi, target, NULL, argv[0]);

end:
	utils_free_args(&argv, argc);
error:
	return;
}

/*
 * /otr contexts
 */
static void _cmd_contexts(struct otr_user_state *ustate, SERVER_REC *irssi,
		const char *target, const void *data)
{
	otr_contexts(ustate);
}

static void _cmd_init(struct otr_user_state *ustate, SERVER_REC *irssi,
		const char *target, const void *data)
{
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

	/*
	 * Irssi does not handle well the HTML tag in the default OTR query message
	 * so just send the OTR tag instead. Contact me for a better fix! :)
	 */
	irssi_send_message(irssi, target, "?OTRv23?");

end:
	return;
}

static void _cmd_forget(struct otr_user_state *ustate, SERVER_REC *irssi,
		const char *target, const void *data)
{
	int argc;
	char **argv;
	char str_fp[OTRL_PRIVKEY_FPRINT_HUMAN_LEN], *fp = NULL;

	utils_explode_args(data, &argv, &argc);

	if (argc == 5) {
		utils_hash_parts_to_readable_hash((const char **) argv, str_fp);
		fp = str_fp;
	} else if (!irssi || (irssi && argc != 0)) {
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
	utils_free_args(&argv, argc);
	return;
}

static void _cmd_distrust(struct otr_user_state *ustate, SERVER_REC *irssi,
		const char *target, const void *data)
{
	int argc;
	char **argv;
	char str_fp[OTRL_PRIVKEY_FPRINT_HUMAN_LEN], *fp = NULL;

	utils_explode_args(data, &argv, &argc);

	if (argc == 5) {
		utils_hash_parts_to_readable_hash((const char **) argv, str_fp);
		fp = str_fp;
	} else if (!irssi || (irssi && argc != 0)) {
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
	utils_free_args(&argv, argc);
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
void cmd_generic(struct otr_user_state *ustate, SERVER_REC *irssi,
		const char *target, char *cmd, const void *data)
{
	struct irssi_commands *commands = cmds;

	do {
		if (strcmp(commands->name, cmd) == 0) {
			commands->func(ustate, irssi, target, data);
			goto end;
		}
	} while ((++commands)->name);

end:
	return;
}
