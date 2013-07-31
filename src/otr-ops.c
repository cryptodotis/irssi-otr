/*
 * Off-the-Record Messaging (OTR) modules for IRC
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

#include <assert.h>

#include "key.h"
#include "module.h"

static OtrlPolicy OTR_DEFAULT_POLICY =
	OTRL_POLICY_MANUAL | OTRL_POLICY_WHITESPACE_START_AKE;

/*
 * Return default policy for now.
 */
static OtrlPolicy ops_policy(void *opdata, ConnContext *context)
{
	return OTR_DEFAULT_POLICY;
}

/*
 * Request for key generation.
 *
 * The lib actually expects us to be finished before the call returns. Since
 * this can take more than an hour on some systems there isn't even a point in
 * trying...
 */
static void ops_create_privkey(void *opdata, const char *accountname,
		const char *protocol)
{
	key_gen_run(user_state_global, accountname);
}

/*
 * Inject OTR message.
 */
static void ops_inject_msg(void *opdata, const char *accountname,
		const char *protocol, const char *recipient, const char *message)
{
	SERVER_REC *irssi = opdata;

	IRSSI_DEBUG("Inject msg:\n[%s]", message);
	irssi_send_message(irssi, recipient, message);
}

/*
 * Gone secure.
 */
static void ops_secure(void *opdata, ConnContext *context)
{
	int ret;
	char ownfp[OTRL_PRIVKEY_FPRINT_HUMAN_LEN];
	char peerfp[OTRL_PRIVKEY_FPRINT_HUMAN_LEN];
	SERVER_REC *irssi = opdata;
	struct otr_peer_context *opc;

	assert(context);
	/* This should *really* not happened */
	assert(context->msgstate == OTRL_MSGSTATE_ENCRYPTED);

	IRSSI_NOTICE(irssi, context->username, "Gone %9secure%9");
	otr_status_change(irssi, context->username, OTR_STATUS_GONE_SECURE);

	opc = context->app_data;
	opc->active_fingerprint = context->active_fingerprint;

	ret = otrl_context_is_fingerprint_trusted(context->active_fingerprint);
	if (ret) {
		/* Secure and trusted */
		goto end;
	}

	/* Not authenticated. Let's print out the fingerprints for comparison. */
	otrl_privkey_hash_to_human(peerfp,
			context->active_fingerprint->fingerprint);
	otrl_privkey_fingerprint(user_state_global->otr_state, ownfp,
			context->accountname, OTR_PROTOCOL_ID);

	IRSSI_NOTICE(irssi, context->username, "Your peer is not "
			"authenticated. To make sure you're talking to the right person you can "
			"either agree on a secret and use the authentication command "
			"%9/otr auth%9 or %9/otr authq [QUESTION] SECRET%9. You can also "
			"use the traditional way and compare fingerprints "
			"(e.g. telephone or GPG-signed mail) and subsequently enter "
			"%9/otr trust%9.");

	IRSSI_NOTICE(irssi, context->username, "Your fingerprint is: %y%s%n",
			ownfp);
	IRSSI_NOTICE(irssi, context->username, "%9%s's%9 fingerprint is: %r%s%n",
			context->username, peerfp);

end:
	return;
}

/*
 * Gone insecure.
 */
static void ops_insecure(void *opdata, ConnContext *context)
{
	SERVER_REC *irssi = opdata;

	IRSSI_NOTICE(irssi, context->username, "Gone %rinsecure%r");
	otr_status_change(irssi, context->username, OTR_STATUS_GONE_INSECURE);
}

/*
 * Really critical with IRC. Unfortunately, we can't tell our peer which size
 * to use.
 */
static int ops_max_msg(void *opdata, ConnContext *context)
{
	return OTR_MAX_MSG_SIZE;
}

static void ops_handle_msg_event(void *opdata, OtrlMessageEvent msg_event,
		ConnContext *context, const char *message, gcry_error_t err)
{
	SERVER_REC *server = opdata;
	char *username = context->username;

	switch (msg_event) {
	case OTRL_MSGEVENT_NONE:
		break;
	case OTRL_MSGEVENT_ENCRYPTION_REQUIRED:
		IRSSI_NOTICE(server, username, "%yEncryption is required.%n");
		break;
	case OTRL_MSGEVENT_ENCRYPTION_ERROR:
		IRSSI_NOTICE(server, username, "An error occurred when "
				"encrypting your message. The message was NOT sent.");
		break;
	case OTRL_MSGEVENT_CONNECTION_ENDED:
		IRSSI_NOTICE(server, username, "%9%s%9 has already closed the "
				"connection to you.", username);
		break;
	case OTRL_MSGEVENT_SETUP_ERROR:
		if (!err) {
			err = GPG_ERR_INV_VALUE;
		}
		switch (err) {
		case GPG_ERR_INV_VALUE:
			IRSSI_NOTICE(server, username, "Error setting up private "
					"conversation: Malformed message received");
			break;
		default:
			IRSSI_NOTICE(server, username, "Error up private "
					"conversation: %s", gcry_strerror(err));
			break;
		}
		break;
	case OTRL_MSGEVENT_MSG_REFLECTED:
		IRSSI_NOTICE(server, username, "Receiving our own OTR messages. "
				"You are either trying to talk to yourself, or someone is "
				"reflecting your messages back at you.");
		break;
	case OTRL_MSGEVENT_MSG_RESENT:
		IRSSI_NOTICE(server, username, "The last message to %9%s%9 "
				"was resent: %s", username, message);
		break;
	case OTRL_MSGEVENT_RCVDMSG_NOT_IN_PRIVATE:
		IRSSI_NOTICE(server, username, "The encrypted message received "
				"from %s is unreadable, as you are not currently communicating "
				"privately.", username);
		break;
	case OTRL_MSGEVENT_RCVDMSG_UNREADABLE:
		IRSSI_NOTICE(server, username, "We received an unreadable "
				"encrypted message from %s.", username);
		break;
	case OTRL_MSGEVENT_RCVDMSG_MALFORMED:
		IRSSI_NOTICE(server, username, "We received a malformed data "
				"message from %s.", username);
		break;
	case OTRL_MSGEVENT_LOG_HEARTBEAT_RCVD:
		IRSSI_DEBUG("Heartbeat received from %s.", username);
		break;
	case OTRL_MSGEVENT_LOG_HEARTBEAT_SENT:
		IRSSI_DEBUG("Heartbeat sent to %s.", username);
		break;
	case OTRL_MSGEVENT_RCVDMSG_GENERAL_ERR:
		IRSSI_NOTICE(server, username, "General Error: %s.", message);
		break;
	case OTRL_MSGEVENT_RCVDMSG_UNENCRYPTED:
		IRSSI_NOTICE(server, username,
				"The following message from %9%s%9 was NOT "
				"encrypted.", username);
		/*
		 * This is a hack I found to send the message in a private window of
		 * the username without creating an infinite loop since the 'message
		 * private' signal is hijacked in this module. If someone is able to
		 * clean this up with a more elegant solution, by all means PLEASE
		 * submit a patch or email me a better way.
		 */
		signal_remove("message private", (SIGNAL_FUNC) sig_message_private);
		signal_emit("message private", 4, server, message, username,
				IRSSI_CONN_ADDR(server));
		signal_add_first("message private", (SIGNAL_FUNC) sig_message_private);
		break;
	case OTRL_MSGEVENT_RCVDMSG_UNRECOGNIZED:
		IRSSI_NOTICE(server, username, "Unrecognized OTR message "
				"received from %s.", username);
		break;
	case OTRL_MSGEVENT_RCVDMSG_FOR_OTHER_INSTANCE:
		IRSSI_DEBUG("%s has sent a message for a different instance.",
				username);
		break;
	}
}

/*
 * A context changed.
 */
static void ops_up_ctx_list(void *opdata)
{
	otr_status_change(opdata, NULL, OTR_STATUS_CTX_UPDATE);
}

/*
 * Save fingerprint changes.
 */
static void ops_write_fingerprints(void *data)
{
	key_write_fingerprints(user_state_global);
}

static int ops_is_logged_in(void *opdata, const char *accountname,
		const char *protocol, const char *recipient)
{
	int ret;
	SERVER_REC *irssi = opdata;

	if (irssi) {
		/* Logged in */
		ret = 1;
	} else {
		/* Not */
		ret = 0;
	}

	IRSSI_DEBUG("User %s %s logged in", accountname,
			(ret == 0) ? "not" : "");

	return ret;
}

static void ops_create_instag(void *opdata, const char *accountname,
		const char *protocol)
{
	otrl_instag_generate(user_state_global->otr_state, "/dev/null",
			accountname, protocol);
	key_write_instags(user_state_global);
}

static void ops_smp_event(void *opdata, OtrlSMPEvent smp_event,
		ConnContext *context, unsigned short progress_percent, char *question)
{
	SERVER_REC *irssi = opdata;
	const char *from = context->username;
	struct otr_peer_context *opc = context->app_data;

	/*
	 * Without a peer context, we can't update the status bar. Code flow error
	 * if none is found. This context is created automatically by an otrl_*
	 * call or if non existent when returned from
	 * otrl_message_sending/receiving.
	 */
	assert(opc);

	opc->smp_event = smp_event;

	switch (smp_event) {
	case OTRL_SMPEVENT_ASK_FOR_SECRET:
		IRSSI_NOTICE(irssi, from, "%9%s%9 wants to authenticate. "
				"Type %9/otr auth <SECRET>%9 to complete.", from);
		opc->ask_secret = 1;
		otr_status_change(irssi, from, OTR_STATUS_SMP_INCOMING);
		break;
	case OTRL_SMPEVENT_ASK_FOR_ANSWER:
		IRSSI_NOTICE(irssi, from, "%9%s%9 wants to authenticate and "
				"asked this question:", from);
		IRSSI_NOTICE(irssi, from, "%b>%n %y%s%n", question);
		IRSSI_NOTICE(irssi, from, "Type %9/otr auth <SECRET>%9 to complete.");
		opc->ask_secret = 1;
		otr_status_change(irssi, from, OTR_STATUS_SMP_INCOMING);
		break;
	case OTRL_SMPEVENT_IN_PROGRESS:
		IRSSI_NOTICE(irssi, from, "%9%s%9 replied to our auth request",
				from);
		otr_status_change(irssi, from, OTR_STATUS_SMP_FINALIZE);
		break;
	case OTRL_SMPEVENT_SUCCESS:
		IRSSI_NOTICE(irssi, from, "%gAuthentication successful.%n");
		otr_status_change(irssi, from, OTR_STATUS_SMP_SUCCESS);
		break;
	case OTRL_SMPEVENT_ABORT:
		otr_auth_abort(irssi, context->username);
		otr_status_change(irssi, from, OTR_STATUS_SMP_ABORTED);
		break;
	case OTRL_SMPEVENT_FAILURE:
	case OTRL_SMPEVENT_CHEATED:
	case OTRL_SMPEVENT_ERROR:
		IRSSI_NOTICE(irssi, from, "%RAuthentication failed%n");
		otr_status_change(irssi, from, OTR_STATUS_SMP_FAILED);
		break;
	default:
		IRSSI_NOTICE(irssi, from, "Received unknown SMP event. "
			"Ignoring");
		break;
	}
}

/*
 * timer_control callback.
 */
static void ops_timer_control(void *opdata, unsigned int interval)
{
	otr_control_timer(interval, opdata);
}

/*
 * Handle otr error message.
 */
static const char *ops_otr_error_message(void *opdata, ConnContext *context,
		OtrlErrorCode code)
{
	char *msg = NULL;

	switch (code) {
	case OTRL_ERRCODE_NONE:
		break;
	case OTRL_ERRCODE_ENCRYPTION_ERROR:
		msg = strdup("Error occurred encrypting message.");
		break;
	case OTRL_ERRCODE_MSG_NOT_IN_PRIVATE:
		if (context) {
			msg = strdup("You sent encrypted data which was unexpected");
		}
		break;
	case OTRL_ERRCODE_MSG_UNREADABLE:
		msg = strdup("You transmitted an unreadable encrypted message");
		break;
	case OTRL_ERRCODE_MSG_MALFORMED:
		msg = strdup("You transmitted a malformed data message.");
		break;
	}

	return msg;
}

/*
 * Free otr error message callback.
 */
static void ops_otr_error_message_free(void *opdata, const char *err_msg)
{
	if (err_msg) {
		free((char *)err_msg);
	}
}

/*
 * Assign OTR message operations.
 */
OtrlMessageAppOps otr_ops = {
	ops_policy,
	ops_create_privkey,
	ops_is_logged_in,
	ops_inject_msg,
	ops_up_ctx_list,
	NULL, /* new_fingerprint */
	ops_write_fingerprints,
	ops_secure,
	ops_insecure,
	NULL, /* still_secure */
	ops_max_msg,
	NULL, /* account_name */
	NULL, /* account_name_free */
	NULL, /* received_symkey */
	ops_otr_error_message,
	ops_otr_error_message_free,
	NULL, /* resent_msg_prefix */
	NULL, /* resent_msg_prefix_free */
	ops_smp_event,
	ops_handle_msg_event,
	ops_create_instag,
	NULL, /* convert_msg */
	NULL, /* convert_free */
	ops_timer_control,
};
