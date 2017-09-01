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
#include <glib/gstdio.h>
#include <libgen.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/poll.h>
#include <signal.h>
#include <unistd.h>

#include "key.h"

/*
 * Key generation data for the thread in charge of creating the key.
 */
static struct key_gen_data key_gen_state = {
	.status = KEY_GEN_IDLE,
	.gcry_error = GPG_ERR_NO_ERROR,
};

static pthread_t keygen_thread;

/*
 * Build file path concatenate to the irssi config dir.
 */
static char *file_path_build(const char *path)
{
	int ret;
	char *filename;

	if (!path) {
		path = "";
	}

	/* Either NULL or the filename is returned here which is valid. */
	ret = asprintf(&filename, "%s%s", get_client_config_dir(), path);
	if (ret < 0) {
		filename = NULL;
	}

	return filename;
}

/*
 * Reset key generation state and status is IDLE.
 */
static void reset_key_gen_state(void)
{
	/* Safety. */
	if (key_gen_state.key_file_path) {
		free(key_gen_state.key_file_path);
	}

	/* Pointer dup when key_gen_run is called. */
	if (key_gen_state.account_name) {
		free(key_gen_state.account_name);
	}

	/* Nullify everything. */
	memset(&key_gen_state, 0, sizeof(key_gen_state));
	key_gen_state.status = KEY_GEN_IDLE;
	key_gen_state.gcry_error = GPG_ERR_NO_ERROR;
}

/*
 * Generate OTR key. Thread in the background.
 *
 * NOTE: NO irssi interaction should be done here like emitting signals or else
 * it causes a segfaults of libperl.
 */
static void *generate_key(void *data)
{
	gcry_error_t err;

	assert(key_gen_state.newkey);

	key_gen_state.status = KEY_GEN_RUNNING;

	err = otrl_privkey_generate_calculate(key_gen_state.newkey);
	if (err != GPG_ERR_NO_ERROR) {
		key_gen_state.status = KEY_GEN_ERROR;
		key_gen_state.gcry_error = err;
		goto error;
	}

	key_gen_state.status = KEY_GEN_FINISHED;

error:
	return NULL;
}

/*
 * Check key generation state and print message to user according to state.
 */
void key_gen_check(void)
{
	gcry_error_t err;

	switch (key_gen_state.status) {
	case KEY_GEN_FINISHED:
		err = otrl_privkey_generate_finish(key_gen_state.ustate->otr_state,
				key_gen_state.newkey, key_gen_state.key_file_path);
		if (err != GPG_ERR_NO_ERROR) {
			IRSSI_MSG("Key generation finish state failed. Err: %s",
					gcry_strerror(err));
		} else {
			IRSSI_MSG("Key generation for %9%s%n completed",
					key_gen_state.account_name);
		}
		reset_key_gen_state();
		break;
	case KEY_GEN_ERROR:
		IRSSI_MSG("Key generation for %9%s%n failed. Err: %s (%d)",
				key_gen_state.account_name,
				gcry_strerror(key_gen_state.gcry_error),
				key_gen_state.gcry_error);
		reset_key_gen_state();
		break;
	case KEY_GEN_RUNNING:
	case KEY_GEN_IDLE:
		/* Do nothing */
		break;
	};
}

/*
 * Run key generation in a separate process (takes ages). The other process
 * will rewrite the key file, we shouldn't change anything till it's done and
 * we've reloaded the keys.
 */
void key_gen_run(struct otr_user_state *ustate, const char *account_name)
{
	int ret;
	gcry_error_t err;

	assert(ustate);
	assert(account_name);

	if (key_gen_state.status != KEY_GEN_IDLE) {
		IRSSI_INFO(NULL, NULL, "Key generation for %s is still in progress. ",
				"Please wait until completion before creating a new key.",
				key_gen_state.account_name);
		goto error_status;
	}

	/* Make sure the pointer does not go away during the proess. */
	key_gen_state.account_name = strdup(account_name);
	key_gen_state.ustate = ustate;

	/* Creating key file path. */
	key_gen_state.key_file_path = file_path_build(OTR_KEYFILE);
	if (!key_gen_state.key_file_path) {
		IRSSI_INFO(NULL, NULL, "Key generation failed. ENOMEM");
		goto error;
	}

	IRSSI_MSG("Key generation started for %9%s%n", key_gen_state.account_name);

	err = otrl_privkey_generate_start(ustate->otr_state, account_name,
			OTR_PROTOCOL_ID, &key_gen_state.newkey);
	if (err != GPG_ERR_NO_ERROR || !key_gen_state.newkey) {
		IRSSI_MSG("Key generation start failed. Err: %s", gcry_strerror(err));
		goto error;
	}

	ret = pthread_create(&keygen_thread, NULL, generate_key, NULL);
	if (ret < 0) {
		IRSSI_MSG("Key generation failed. Thread failure: %s",
				strerror(errno));
		goto error;
	}

	return;

error:
	reset_key_gen_state();
error_status:
	return;
}

/*
 * Write fingerprints to file.
 */
void key_write_fingerprints(struct otr_user_state *ustate)
{
	gcry_error_t err;
	char *filename;

	assert(ustate);

	filename = file_path_build(OTR_FINGERPRINTS_FILE);
	if (!filename) {
		goto error_filename;
	}

	err = otrl_privkey_write_fingerprints(ustate->otr_state, filename);
	if (err == GPG_ERR_NO_ERROR) {
		IRSSI_DEBUG("Fingerprints saved to %9%s%9", filename);
	} else {
		IRSSI_DEBUG("Error writing fingerprints: %d (%d)",
				gcry_strerror(err), gcry_strsource(err));
	}

	free(filename);
error_filename:
	return;
}

/*
 * Write instance tags to file.
 */
void key_write_instags(struct otr_user_state *ustate)
{
	gcry_error_t err;
	char *filename;

	assert(ustate);

	filename = file_path_build(OTR_INSTAG_FILE);
	if (!filename) {
		goto error_filename;
	}

	err = otrl_instag_write(ustate->otr_state, filename);
	if (err == GPG_ERR_NO_ERROR) {
		IRSSI_DEBUG("Instance tags saved in %9%s%9", filename);
	} else {
		IRSSI_DEBUG("Error saving instance tags: %d (%d)",
				gcry_strerror(err), gcry_strsource(err));
	}

	free(filename);
error_filename:
	return;
}

/*
 * Load private keys.
 */
void key_load(struct otr_user_state *ustate)
{
	int ret;
	gcry_error_t err;
	char *filename;

	assert(ustate);

	filename = file_path_build(OTR_KEYFILE);
	if (!filename) {
		goto error_filename;
	}

	ret = access(filename, F_OK);
	if (ret < 0) {
		IRSSI_DEBUG("No private keys found in %9%s%9", filename);
		goto end;
	}

	err = otrl_privkey_read(ustate->otr_state, filename);
	if (err == GPG_ERR_NO_ERROR) {
		IRSSI_DEBUG("Private keys loaded from %9%s%9", filename);
	} else {
		IRSSI_DEBUG("Error loading private keys: %d (%d)",
				gcry_strerror(err), gcry_strsource(err));
	}

end:
	free(filename);
error_filename:
	return;
}

/*
 * Load fingerprints.
 */
void key_load_fingerprints(struct otr_user_state *ustate)
{
	int ret;
	gcry_error_t err;
	char *filename;

	assert(ustate);

	filename = file_path_build(OTR_FINGERPRINTS_FILE);
	if (!filename) {
		goto error_filename;
	}

	ret = access(filename, F_OK);
	if (ret < 0) {
		IRSSI_DEBUG("No fingerprints found in %9%s%9", filename);
		goto end;
	}

	err = otrl_privkey_read_fingerprints(ustate->otr_state, filename, NULL,
			NULL);
	if (err == GPG_ERR_NO_ERROR) {
		IRSSI_DEBUG("Fingerprints loaded from %9%s%9", filename);
	} else {
		IRSSI_DEBUG("Error loading fingerprints: %d (%d)",
				gcry_strerror(err), gcry_strsource(err));
	}

end:
	free(filename);
error_filename:
	return;
}
