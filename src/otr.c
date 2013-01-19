/*
 * Off-the-Record Messaging (OTR) modules for IRC
 *
 * Copyright (C) 2008 - Uli Meis <a.sporto+bee@gmail.com>
 *               2012 - David Goulet <dgoulet@ev0ke.net>
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

#define _GNU_SOURCE
#include <assert.h>
#include <gcrypt.h>
#include <unistd.h>

#include "otr-formats.h"
#include "key.h"

static const char *statusbar_txt[] = {
	"FINISHED",
	"TRUST_MANUAL",
	"TRUST_SMP",
	"SMP_ABORT",
	"SMP_STARTED",
	"SMP_RESPONDED",
	"SMP_INCOMING",
	"SMP_FINALIZE",
	"SMP_ABORTED",
	"PEER_FINISHED",
	"SMP_FAILED",
	"SMP_SUCCESS",
	"GONE_SECURE",
	"GONE_INSECURE",
	"CTX_UPDATE"
};

/* Glib timer for otr. */
static guint otr_timerid;

/*
 * Allocate and return a string containing the account name of the Irssi server
 * record.
 *
 * Return: nick@myserver.net
 */
static char *create_account_name(SERVER_REC *irssi)
{
	int ret;
	char *accname = NULL;

	assert(irssi);

	/* Valid or NULL, the caller should handle this */
	ret = asprintf(&accname, "%s@%s", IRSSI_NICK(irssi),
			IRSSI_CONN_ADDR(irssi));
	if (ret < 0) {
		IRSSI_INFO(NULL, NULL, "Unable to allocate account name.");
	}

	return accname;
}

/*
 * Load instance tags.
 */
static void instag_load(struct otr_user_state *ustate)
{
	int ret;
	char *filename;
	gcry_error_t err;

	assert(ustate);

	/* Getting the otr instance filename path */
	ret = asprintf(&filename, "%s%s", get_client_config_dir(),
			OTR_INSTAG_FILE);
	if (ret < 0) {
		goto error_filename;
	}

	ret = access(filename, F_OK);
	if (ret < 0) {
		IRSSI_DEBUG("no instance tags found at %9%s%9", filename);
		goto end;
	}

	err = otrl_instag_read(ustate->otr_state, filename);
	if (err == GPG_ERR_NO_ERROR) {
		IRSSI_DEBUG("Instance tags loaded from %9%s%9", filename);
	} else {
		IRSSI_DEBUG("Error loading instance tags: %d (%d)",
				gcry_strerror(err), gcry_strsource(err));
	}

end:
	free(filename);
error_filename:
	return;
}

/*
 * Free otr peer context. Callback passed to libotr.
 */
static void destroy_peer_context_cb(void *data)
{
	struct otr_peer_context *opc = data;

	if (opc) {
		free(opc);
	}

	IRSSI_DEBUG("Peer context freed");
}

/*
 * Allocate otr peer context. Callback passed to libotr.
 */
static void add_peer_context_cb(void *data, ConnContext *context)
{
	struct otr_peer_context *opc;

	opc = otr_create_peer_context();
	if (!opc) {
		return;
	}

	opc->active_fingerprint = context->active_fingerprint;

	context->app_data = opc;
	context->app_data_free = destroy_peer_context_cb;

	IRSSI_DEBUG("Peer context created for %s", context->username);
}

/*
 * Find Irssi server record by account name.
 */
static SERVER_REC *find_irssi_by_account_name(const char *accname)
{
	GSList *tmp;
	size_t nick_len;
	char *address, *nick = NULL;
	SERVER_REC *server, *srv = NULL;

	assert(accname);

	address = strchr(accname, '@');
	if (!address) {
		goto error;
	}

	/* Calculate the nickname length. */
	nick_len = address - accname;

	/* Allocate right size for the nickname plus the NULL terminated byte. */
	nick = malloc(nick_len + 1);
	if (!nick) {
		/* ENOMEM */
		goto error;
	}

	/* Get the nick from the account name. */
	strncpy(nick, accname, nick_len);
	nick[nick_len] = '\0';

	/* Move after the @ */
	address++;

	for (tmp = servers; tmp; tmp = tmp->next) {
		server = tmp->data;
		if (g_ascii_strncasecmp(server->connrec->address, address,
					strlen(server->connrec->address)) == 0 &&
				strncmp(server->nick, nick, strlen(nick)) == 0) {
			srv = server;
			break;
		}
	}

	free(nick);

error:
	return srv;
}

/*
 * Check if fingerprint is in an encrypted context.
 *
 * Return 1 if it does, else 0.
 */
static int check_fp_encrypted_msgstate(Fingerprint *fp)
{
	int ret;
	ConnContext *context;

	assert(fp);

	/* Loop on all fingerprint's context(es). */
	for (context = fp->context;
			context != NULL && context->m_context == fp->context;
			context = context->next) {
		if (context->msgstate == OTRL_MSGSTATE_ENCRYPTED &&
				context->active_fingerprint == fp) {
			ret = 1;
			goto end;
		}
	}

	/* No state is encrypted. */
	ret = 0;

end:
	return ret;
}

/*
 * Timer called from the glib main loop and set up by the timer_control
 * callback of libotr.
 */
static gboolean timer_fired_cb(gpointer data)
{
	otrl_message_poll(user_state_global->otr_state, &otr_ops, NULL);
	return TRUE;
}

void otr_control_timer(unsigned int interval, void *opdata)
{
	if (otr_timerid) {
		g_source_remove(otr_timerid);
		otr_timerid = 0;
	}

	if (interval > 0) {
		otr_timerid = g_timeout_add_seconds(interval, timer_fired_cb, opdata);
	}
}

/*
 * Find context from nickname and irssi server record.
 */
ConnContext *otr_find_context(SERVER_REC *irssi, const char *nick, int create)
{
	char *accname = NULL;
	ConnContext *ctx = NULL;

	assert(irssi);
	assert(nick);

	accname = create_account_name(irssi);
	if (!accname) {
		goto error;
	}

	ctx = otrl_context_find(user_state_global->otr_state, nick, accname,
			OTR_PROTOCOL_ID, OTRL_INSTAG_BEST, create, NULL,
			add_peer_context_cb, irssi);

	free(accname);

error:
	return ctx;
}

/*
 * Create otr peer context.
 */
struct otr_peer_context *otr_create_peer_context(void)
{
	struct otr_peer_context *opc;

	return zmalloc(sizeof(*opc));
}

/*
 * Return a newly allocated OTR user state.
 */
struct otr_user_state *otr_init_user_state(void)
{
	struct otr_user_state *ous = NULL;

	ous = zmalloc(sizeof(*ous));
	if (!ous) {
		goto error;
	}

	ous->otr_state = otrl_userstate_create();

	instag_load(ous);

	/* Load keys and fingerprints. */
	key_load(ous);
	key_load_fingerprints(ous);

error:
	return ous;
}

/*
 * Destroy otr user state.
 */
void otr_free_user_state(struct otr_user_state *ustate)
{
	if (ustate->otr_state) {
		otrl_userstate_free(ustate->otr_state);
		ustate->otr_state = NULL;
	}

	free(ustate);
}

/*
 * init otr lib.
 */
void otr_lib_init()
{
	OTRL_INIT;
}

/*
 * deinit otr lib.
 */
void otr_lib_uninit()
{
}

/*
 * Hand the given message to OTR.
 *
 * Return 0 if the message was successfully handled or else a negative value.
 */
int otr_send(SERVER_REC *irssi, const char *msg, const char *to, char **otr_msg)
{
	gcry_error_t err;
	char *accname = NULL;
	ConnContext *ctx = NULL;

	assert(irssi);

	accname = create_account_name(irssi);
	if (!accname) {
		goto error;
	}

	IRSSI_DEBUG("Sending message...");

	err = otrl_message_sending(user_state_global->otr_state, &otr_ops,
		irssi, accname, OTR_PROTOCOL_ID, to, OTRL_INSTAG_BEST, msg, NULL, otr_msg,
		OTRL_FRAGMENT_SEND_ALL_BUT_LAST, &ctx, add_peer_context_cb, irssi);
	if (err) {
		IRSSI_NOTICE(irssi, to, "Send failed.");
		goto error;
	}

	IRSSI_DEBUG("Message sent...");

	/* Add peer context to OTR context if none exists. */
	if (ctx && !ctx->app_data) {
		add_peer_context_cb(irssi, ctx);
	}

	free(accname);
	return 0;

error:
	free(accname);
	return -1;
}

/*
 * List otr contexts to the main Irssi windows.
 */
void otr_contexts(struct otr_user_state *ustate)
{
	char human_fp[OTRL_PRIVKEY_FPRINT_HUMAN_LEN], *trust;
	ConnContext *ctx, *c_iter;
	Fingerprint *fp;

	assert(ustate);

	if (!ustate->otr_state->context_root) {
		IRSSI_INFO(NULL, NULL, "No active OTR contexts found");
		goto end;
	}

	IRSSI_MSG("[ %KUser%n - %KAccount%n - %KStatus%n - %KFingerprint%n - "
			"%KTrust%n ]");

	/* Iterate over all contextes of the user state. */
	for (ctx = ustate->otr_state->context_root; ctx != NULL; ctx = ctx->next) {
		OtrlMessageState best_mstate = OTRL_MSGSTATE_PLAINTEXT;

		/* Skip master context. */
		if (ctx != ctx->m_context) {
			continue;
		}

		for (fp = ctx->fingerprint_root.next; fp != NULL; fp = fp->next) {
			int used = 0;
			char *username, *accountname;

			username = ctx->username;
			accountname = ctx->accountname;

			for (c_iter = ctx->m_context;
					c_iter && c_iter->m_context == ctx->m_context;
					c_iter = c_iter->next) {
				/* Print account name, username and msgstate. */
				if (c_iter->active_fingerprint == fp) {
					used = 1;

					if (c_iter->msgstate == OTRL_MSGSTATE_ENCRYPTED) {
						best_mstate = OTRL_MSGSTATE_ENCRYPTED;
					} else if (c_iter->msgstate == OTRL_MSGSTATE_FINISHED &&
							best_mstate == OTRL_MSGSTATE_PLAINTEXT) {
						best_mstate = OTRL_MSGSTATE_FINISHED;
					}
				}
			}

			if (used) {
				switch (best_mstate) {
				case OTRL_MSGSTATE_ENCRYPTED:
					IRSSI_MSG("%b>%n %9%s%9 - %B%s%n - %GEncrypted%n -",
							accountname, username);
					break;
				case OTRL_MSGSTATE_PLAINTEXT:
					IRSSI_MSG("%b>%n %9%s%9 - %B%s%n - Plaintext -",
							accountname, username);
					break;
				case OTRL_MSGSTATE_FINISHED:
					IRSSI_MSG("%b>%n %9%s%9 - %B%s%n - %yFinished%n -",
							accountname, username);
					break;
				default:
					IRSSI_MSG("%b>%n %9%s%9 - %B%s%n - Unknown -", accountname,
							username);
					break;
				};
			} else {
				IRSSI_MSG("%b>%n %9%s%9 - %B%s%n - Unused -", accountname,
						username);
			}

			/* Hash fingerprint to human. */
			otrl_privkey_hash_to_human(human_fp, fp->fingerprint);

			trust = fp->trust;
			if (trust && trust[0] != '\0') {
				if (strncmp(trust, "smp", 3) == 0) {
					IRSSI_MSG("  %g%s%n - SMP", human_fp);
				} else {
					IRSSI_MSG("  %g%s%n - Manual", human_fp);
				}
			} else {
				IRSSI_MSG("  %r%s%n - Unverified", human_fp);
			}
		}
	}

end:
	return;
}

/*
 * Finish the conversation.
 */
void otr_finish(SERVER_REC *irssi, const char *nick)
{
	ConnContext *ctx;

	assert(irssi);
	assert(nick);

	ctx = otr_find_context(irssi, nick, FALSE);
	if (!ctx) {
		IRSSI_INFO(irssi, nick, "Nothing to do");
		goto end;
	}

	otrl_message_disconnect(user_state_global->otr_state, &otr_ops, irssi,
			ctx->accountname, OTR_PROTOCOL_ID, nick, ctx->their_instance);

	otr_status_change(irssi, nick, OTR_STATUS_FINISHED);

	IRSSI_INFO(irssi, nick, "Finished conversation with %9%s%9",
			nick);

end:
	return;
}

/*
 * Finish all otr contexts.
 */
void otr_finishall(struct otr_user_state *ustate)
{
	ConnContext *context;
	SERVER_REC *irssi;

	assert(ustate);

	for (context = ustate->otr_state->context_root; context;
			context = context->next) {
		/* Only finish encrypted session. */
		if (context->msgstate != OTRL_MSGSTATE_ENCRYPTED) {
			continue;
		}

		irssi = find_irssi_by_account_name(context->accountname);
		if (!irssi) {
			IRSSI_DEBUG("Unable to find server window for account %s",
					context->accountname);
			continue;
		}

		otr_finish(irssi, context->username);
	}
}

/*
 * Trust our peer.
 */
void otr_trust(SERVER_REC *irssi, const char *nick, char *str_fp,
		struct otr_user_state *ustate)
{
	char peerfp[OTRL_PRIVKEY_FPRINT_HUMAN_LEN];
	struct otr_peer_context *opc;
	ConnContext *ctx;
	Fingerprint *fp_trust;

	assert(ustate);

	if (!irssi && !str_fp) {
		IRSSI_NOTICE(NULL, nick, "Need a fingerprint!");
		goto error;
	}

	/* No human string fingerprint given. */
	if (!str_fp) {
		ctx = otr_find_context(irssi, nick, FALSE);
		if (!ctx) {
			goto error;
		}

		opc = ctx->app_data;
		/* Always NEED a peer context or else code error. */
		assert(opc);

		fp_trust = ctx->active_fingerprint;
	} else {
		fp_trust = otr_find_hash_fingerprint_from_human(str_fp, ustate);
	}

	if (fp_trust) {
		int ret;

		ret = otrl_context_is_fingerprint_trusted(fp_trust);
		if (ret) {
			IRSSI_NOTICE(irssi, nick, "Already trusted!");
			goto end;
		}

		/* Trust level is manual at this point. */
		otrl_context_set_trust(fp_trust, "manual");
		key_write_fingerprints(ustate);

		otr_status_change(irssi, nick, OTR_STATUS_TRUST_MANUAL);

		otrl_privkey_hash_to_human(peerfp, fp_trust->fingerprint);
		IRSSI_NOTICE(irssi, nick, "Fingerprint %g%s%n trusted!", peerfp);
	} else {
		IRSSI_NOTICE(irssi, nick, "Fingerprint %y%s%n NOT found",
				(str_fp != NULL) ? str_fp : "");
	}

end:
error:
	return;
}

/*
 * implements /otr authabort
 */
void otr_auth_abort(SERVER_REC *irssi, const char *nick)
{
	ConnContext *ctx;

	assert(irssi);
	assert(nick);

	ctx = otr_find_context(irssi, nick, FALSE);
	if (!ctx) {
		IRSSI_NOTICE(irssi, nick, "Context for %9%s%9 not found.", nick);
		goto end;
	}

	otrl_message_abort_smp(user_state_global->otr_state, &otr_ops, irssi, ctx);
	otr_status_change(irssi, nick, OTR_STATUS_SMP_ABORT);

	if (ctx->smstate->nextExpected != OTRL_SMP_EXPECT1) {
		IRSSI_NOTICE(irssi, nick, "%rOngoing authentication aborted%n");
	} else {
		IRSSI_NOTICE(irssi, nick, "%rAuthentication aborted%n");
	}

end:
	return;
}

/*
 * Initiate or respond to SMP authentication.
 */
void otr_auth(SERVER_REC *irssi, const char *nick, const char *question,
		const char *secret)
{
	int ret;
	size_t secret_len = 0;
	ConnContext *ctx;
	struct otr_peer_context *opc;

	assert(irssi);
	assert(nick);

	ctx = otr_find_context(irssi, nick, 0);
	if (!ctx) {
		IRSSI_NOTICE(irssi, nick, "Context for %9%s%9 not found.", nick);
		goto end;
	}

	opc = ctx->app_data;
	/* Again, code flow error. */
	assert(opc);

	if (ctx->msgstate != OTRL_MSGSTATE_ENCRYPTED) {
		IRSSI_INFO(irssi, nick,
				"You need to establish an OTR session before you "
				"can authenticate.");
		goto end;
	}

	/* Aborting an ongoing auth */
	if (ctx->smstate->nextExpected != OTRL_SMP_EXPECT1) {
		otr_auth_abort(irssi, nick);
	}

	/* reset trust level */
	if (ctx->active_fingerprint) {
		ret = otrl_context_is_fingerprint_trusted(ctx->active_fingerprint);
		if (!ret) {
			otrl_context_set_trust(ctx->active_fingerprint, "");
			key_write_fingerprints(user_state_global);
		}
	}

	/* Libotr allows empty secret. */
	if (secret) {
		secret_len = strlen(secret);
	}

	if (opc->ask_secret) {
		otrl_message_respond_smp(user_state_global->otr_state, &otr_ops,
				irssi, ctx, (unsigned char *) secret, secret_len);
		otr_status_change(irssi, nick, OTR_STATUS_SMP_RESPONDED);
		IRSSI_NOTICE(irssi, nick, "%yResponding to authentication...%n");
	} else {
		if (question) {
			otrl_message_initiate_smp_q(user_state_global->otr_state,
				&otr_ops, irssi, ctx, question, (unsigned char *) secret,
				secret_len);
		} else {
			otrl_message_initiate_smp(user_state_global->otr_state,
				&otr_ops, irssi, ctx, (unsigned char *) secret, secret_len);
		}
		otr_status_change(irssi, nick, OTR_STATUS_SMP_STARTED);
		IRSSI_NOTICE(irssi, nick, "%yInitiated authentication...%n");
	}

	opc->ask_secret = 0;

end:
	return;
}

/*
 * Hand the given message to OTR.
 *
 * Returns 0 if its an OTR protocol message or else negative value.
 */
int otr_receive(SERVER_REC *irssi, const char *msg, const char *from,
		char **new_msg)
{
	int ret = -1;
	char *accname = NULL;
	OtrlTLV *tlvs;
	ConnContext *ctx;

	assert(irssi);

	accname = create_account_name(irssi);
	if (!accname) {
		goto error;
	}

	IRSSI_DEBUG("Receiving message...");

	ret = otrl_message_receiving(user_state_global->otr_state,
		&otr_ops, irssi, accname, OTR_PROTOCOL_ID, from, msg, new_msg, &tlvs,
		&ctx, add_peer_context_cb, irssi);
	if (ret) {
		IRSSI_DEBUG("Ignoring message of length %d from %s to %s.\n"
				"%s", strlen(msg), from, accname, msg);
	} else {
		if (*new_msg) {
			IRSSI_DEBUG("Converted received message.");
		}
	}

	/* Add peer context to OTR context if non exists */
	if (ctx && !ctx->app_data) {
		add_peer_context_cb(irssi, ctx);
	}

	/* Check for disconnected message */
	OtrlTLV *tlv = otrl_tlv_find(tlvs, OTRL_TLV_DISCONNECTED);
	if (tlv) {
		otr_status_change(irssi, from, OTR_STATUS_PEER_FINISHED);
		IRSSI_NOTICE(irssi, from, "%9%s%9 has finished the OTR "
				"conversation. If you want to continue talking enter "
				"%9/otr finish%9 for plaintext or %9/otr init%9 to restart.",
				from);
	}

	otrl_tlv_free(tlvs);

	IRSSI_DEBUG("Message received.");

error:
	free(accname);
	return ret;
}

/*
 * Get the OTR status of this conversation.
 */
enum otr_status_format otr_get_status_format(SERVER_REC *irssi,
		const char *nick)
{
	int ret;
	enum otr_status_format code;
	ConnContext *ctx = NULL;

	assert(irssi);

	ctx = otr_find_context(irssi, nick, FALSE);
	if (!ctx) {
		code = TXT_STB_PLAINTEXT;
		goto end;
	}

	switch (ctx->msgstate) {
	case OTRL_MSGSTATE_PLAINTEXT:
		code = TXT_STB_PLAINTEXT;
		break;
	case OTRL_MSGSTATE_ENCRYPTED:
		/* Begin by checking trust. */
		ret = otrl_context_is_fingerprint_trusted(ctx->active_fingerprint);
		if (ret) {
			code = TXT_STB_TRUST;
		} else {
			code = TXT_STB_UNTRUSTED;
		}
		break;
	case OTRL_MSGSTATE_FINISHED:
		code = TXT_STB_FINISHED;
		break;
	default:
		IRSSI_NOTICE(irssi, nick, "BUG Found! "
				"Please write us a mail and describe how you got here");
		code = TXT_STB_UNKNOWN;
		break;
	}

end:
	if (ctx) {
		IRSSI_DEBUG("Code: %d, state: %d, sm_prog_state: %d, auth state: %d",
				code, ctx->msgstate, ctx->smstate->sm_prog_state,
				ctx->auth.authstate);
	}
	return code;
}

/*
 * Change status bar text for a given nickname.
 */
void otr_status_change(SERVER_REC *irssi, const char *nick,
		enum otr_status_event event)
{
	statusbar_items_redraw("otr");
	signal_emit("otr event", 3, irssi, nick, statusbar_txt[event]);
}

/*
 * Search for a OTR Fingerprint object from the given human readable string and
 * return a pointer to the object if found else NULL.
 */
Fingerprint *otr_find_hash_fingerprint_from_human(const char *human_fp,
		struct otr_user_state *ustate)
{
	char str_fp[OTRL_PRIVKEY_FPRINT_HUMAN_LEN];
	Fingerprint *fp = NULL, *fp_iter = NULL;
	ConnContext *context;

	/* Loop on all context of the user state */
	for (context = ustate->otr_state->context_root; context != NULL;
			context = context->next) {
		/* Loop on all fingerprint of the context */
		for (fp_iter = context->fingerprint_root.next; fp_iter;
				fp_iter = fp_iter->next) {
			otrl_privkey_hash_to_human(str_fp, fp_iter->fingerprint);
			/* Compare human fingerprint given in argument to the current. */
			if (strncmp(str_fp, human_fp, sizeof(str_fp)) == 0) {
				fp = otrl_context_find_fingerprint(context,
						fp_iter->fingerprint, 0, NULL);
				goto end;
			}
		}
	}

end:
	return fp;
}

/*
 * Forget a fingerprint.
 *
 * If str_fp is not NULL, it must be on the OTR human format like this:
 * "487FFADA 5073FEDD C5AB5C14 5BB6C1FF 6D40D48A". If str_fp is NULL, get the
 * context of the target nickname, check for the OTR peer context active
 * fingerprint and forget this one if possible.
 */
void otr_forget(SERVER_REC *irssi, const char *nick, char *str_fp,
		struct otr_user_state *ustate)
{
	int ret;
	char fp[OTRL_PRIVKEY_FPRINT_HUMAN_LEN];
	Fingerprint *fp_forget;
	ConnContext *ctx = NULL;
	struct otr_peer_context *opc;

	if (!irssi && !str_fp) {
		IRSSI_NOTICE(NULL, nick, "Need a fingerprint!");
		goto error;
	}

	/* No human string fingerprint given. */
	if (!str_fp) {
		ctx = otr_find_context(irssi, nick, FALSE);
		if (!ctx) {
			goto error;
		}

		opc = ctx->app_data;
		/* Always NEED a peer context or else code error. */
		assert(opc);

		fp_forget = opc->active_fingerprint;
	} else {
		fp_forget = otr_find_hash_fingerprint_from_human(str_fp, ustate);
	}

	if (fp_forget) {
		/* Don't do anything if context is in encrypted state. */
		ret = check_fp_encrypted_msgstate(fp_forget);
		if (ret) {
			IRSSI_NOTICE(irssi, nick, "Fingerprint "
					"context is still encrypted. Finish the OTR "
					"session before forgetting a fingerprint "
					"(%9/otr finish%9).");
			goto end;
		}

		otrl_privkey_hash_to_human(fp, fp_forget->fingerprint);
		/* Forget fp and context if it's the only one remaining. */
		otrl_context_forget_fingerprint(fp_forget, 1);
		/* Update fingerprints file. */
		key_write_fingerprints(ustate);
		IRSSI_NOTICE(irssi, nick, "Fingerprint %y%s%n forgotten.",
				fp);
	} else {
		IRSSI_NOTICE(irssi, nick, "Fingerprint %y%s%n NOT found",
				(str_fp != NULL) ? str_fp : "");
	}

end:
error:
	return;
}

/*
 * Distrust a fingerprint.
 *
 * If str_fp is not NULL, it must be on the OTR human format like this:
 * "487FFADA 5073FEDD C5AB5C14 5BB6C1FF 6D40D48A". If str_fp is NULL, get the
 * context of the target nickname, check for the OTR peer context active
 * fingerprint and distrust it.
 */
void otr_distrust(SERVER_REC *irssi, const char *nick, char *str_fp,
		struct otr_user_state *ustate)
{
	int ret;
	char fp[OTRL_PRIVKEY_FPRINT_HUMAN_LEN];
	Fingerprint *fp_distrust;
	ConnContext *ctx;
	struct otr_peer_context *opc;

	if (!irssi && !str_fp) {
		IRSSI_NOTICE(NULL, nick, "Need a fingerprint!");
		goto error;
	}

	/* No human string fingerprint given. */
	if (!str_fp) {
		ctx = otr_find_context(irssi, nick, FALSE);
		if (!ctx) {
			goto error;
		}

		opc = ctx->app_data;
		/* Always NEED a peer context or else code error. */
		assert(opc);

		fp_distrust = opc->active_fingerprint;
	} else {
		fp_distrust = otr_find_hash_fingerprint_from_human(str_fp, ustate);
	}

	if (fp_distrust) {
		ret = otrl_context_is_fingerprint_trusted(fp_distrust);
		if (!ret) {
			/* Fingerprint already not trusted. Do nothing. */
			IRSSI_NOTICE(irssi, nick, "Already not trusting it!");
			goto end;
		}

		otrl_privkey_hash_to_human(fp, fp_distrust->fingerprint);
		otrl_context_set_trust(fp_distrust, "");
		/* Update fingerprints file. */
		key_write_fingerprints(ustate);
		IRSSI_NOTICE(irssi, nick, "Fingerprint %y%s%n distrusted.",
				fp);
	} else {
		IRSSI_NOTICE(irssi, nick, "Fingerprint %y%s%n NOT found",
				(str_fp != NULL) ? str_fp : "");
	}

end:
error:
	return;
}
