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

#define _GNU_SOURCE
#include <assert.h>
#include <glib/gstdio.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/poll.h>
#include <signal.h>
#include <unistd.h>

#include "key.h"

static struct {
	keygen_status_t status;
	char *accountname;
	char *protocol;
	time_t started;
	GIOChannel *ch[2];
	guint cpid;
	guint cwid;
	pid_t pid;
	struct otr_user_state *ustate;
} kg_st = { .status = KEYGEN_NO };

static char *file_path_build(const char *path)
{
	char *filename = NULL;

	if (!path) {
		path = "";
	}

	/* Either NULL or the filename is returned here which is valid. */
	(void) asprintf(&filename, "%s%s", get_client_config_dir(), path);

	return filename;
}

static void keygen_childwatch(GPid pid, gint status, gpointer data)
{
	int ret;
	struct pollfd pfd = {
		.fd = g_io_channel_unix_get_fd(kg_st.ch[0]),
		.events = POLLIN
	};

	/* nothing to do if keygen_complete has already been called */
	if (data) {
		goto end;
	}

	kg_st.pid = 0;

	ret = poll(&pfd, 1, 0);
	if (ret == 1) {
		/* data is there, let's wait for keygen_complete to be called */
		return;
	} else if (ret == 0) {
		/* no data, report error and reset kg_st */
		if (WIFSIGNALED(status)) {
			char sigstr[16];

			ret = snprintf(sigstr, sizeof(sigstr),
#ifndef HAVE_STRSIGNAL
				"%d", WTERMSIG(status)
#else
				"%s", strsignal(WTERMSIG(status))
#endif
			);
			IRSSI_INFO(NULL, NULL, "Key generation for %s, child was killed "
					"by signal %s", kg_st.accountname, sigstr);
		} else {
			IRSSI_INFO(NULL, NULL, "Key generation for %s, child terminated "
					"for unknown reason", kg_st.accountname);
		}
	} else if (ret < 0) {
		IRSSI_INFO(NULL, NULL, "Key generation for %s. Poll error %s",
				kg_st.accountname, strerror(errno));
	}

	key_generation_abort(kg_st.ustate, FALSE);

end:
	return;
}

/*
 * Installed as g_io_watch and called when the key generation
 * process finishs.
 */
static gboolean keygen_complete(GIOChannel *source, GIOCondition condition,
		gpointer data)
{
	gcry_error_t err;
	const char *clconfdir = get_client_config_dir();
	char *filename = g_strconcat(clconfdir, OTR_KEYFILE, NULL);
	char *tmpfilename = g_strconcat(clconfdir, OTR_TMP_KEYFILE, NULL);

	read(g_io_channel_unix_get_fd(kg_st.ch[0]), &err, sizeof(err));

	g_source_remove(kg_st.cpid);
	g_io_channel_shutdown(kg_st.ch[0], FALSE, NULL);
	g_io_channel_shutdown(kg_st.ch[1], FALSE, NULL);
	g_io_channel_unref(kg_st.ch[0]);
	g_io_channel_unref(kg_st.ch[1]);

	if (err) {
		IRSSI_INFO(NULL, NULL, "Key generation failed for %s (err: %s)",
				kg_st.accountname, gcry_strerror(err));
	} else {
		/* reload keys */
		IRSSI_INFO(NULL, NULL, "Key generation for %s completed in %d seconds."
				" Reloading keys.", kg_st.accountname,
				time(NULL) - kg_st.started);
		rename(tmpfilename, filename);
		//otrl_privkey_forget_all(otr_state); <-- done by lib
		key_load(kg_st.ustate);
	}

	g_source_remove(kg_st.cwid);
	kg_st.cwid = g_child_watch_add(kg_st.pid, keygen_childwatch, (void*) 1);

	kg_st.status = KEYGEN_NO;
	g_free(kg_st.accountname);

	g_free(filename);
	g_free(tmpfilename);

	return FALSE;
}

/*
 * Run key generation in a seperate process (takes ages). The other process
 * will rewrite the key file, we shouldn't change anything till it's done and
 * we've reloaded the keys.
 */
void key_generation_run(struct otr_user_state *ustate, const char *accname)
{
	gcry_error_t err;
	int ret;
	int fds[2];
	char *filename = g_strconcat(get_client_config_dir(), OTR_TMP_KEYFILE, NULL);
	char *filenamedup = g_strdup(filename);
	char *dir = dirname(filenamedup);

	if (kg_st.status != KEYGEN_NO) {
		if (strncmp(accname, kg_st.accountname, strlen(accname)) != 0) {
			IRSSI_INFO(NULL, NULL, "Key generation for %s aborted. "
					"Key generation for %s still in progress", accname,
					kg_st.accountname);
		}
		g_free(filenamedup);
		goto end;
	}

	if (!g_file_test(dir, G_FILE_TEST_EXISTS)) {
		if (g_mkdir(dir, S_IRWXU)) {
			IRSSI_INFO(NULL, NULL, "Key generation for %s aborted. Failed "
					"creating directory %s (err: %s)",
					accname, dir, strerror(errno));
			g_free(dir);
			g_free(filenamedup);
			goto end;
		} else {
			IRSSI_INFO(NULL, NULL, "Key generation created directory %9%s%9",
					dir);
		}
	}

	g_free(filenamedup);

	ret = pipe(fds);
	if (ret < 0) {
		IRSSI_INFO(NULL, NULL, "Key generation for %s. Error creating "
				"pipe (err: %s)", accname, strerror(errno));
		goto end;
	}

	kg_st.ch[0] = g_io_channel_unix_new(fds[0]);
	kg_st.ch[1] = g_io_channel_unix_new(fds[1]);

	kg_st.accountname = g_strdup(accname);
	kg_st.ustate = ustate;
	kg_st.protocol = OTR_PROTOCOL_ID;
	kg_st.started = time(NULL);

	if ((ret = fork())) {
		if (ret == -1) {
			IRSSI_INFO(NULL, NULL, "Key generation for %s. Fork error "
					"(err: %s)", accname, strerror(errno));
			goto end;
		}

		kg_st.status = KEYGEN_RUNNING;
		kg_st.pid = ret;

		IRSSI_INFO(NULL, NULL, "Key generation for %s initiated. "
				"This might take several minutes or on some systems even an "
				"hour. If you wanna check that something is happening, see if "
				"there are two processes of your IRC client.", accname);

		kg_st.cpid = g_io_add_watch(kg_st.ch[0], G_IO_IN,
				(GIOFunc) keygen_complete, NULL);
		kg_st.cwid = g_child_watch_add(kg_st.pid, keygen_childwatch, NULL);
		kg_st.started = time(NULL);
		goto end;
	}

	/* child */

	err = otrl_privkey_generate(ustate->otr_state, filename, accname,
			OTR_PROTOCOL_ID);
	(void) write(fds[1], &err, sizeof(err));

	g_free(filename);

	exit(EXIT_SUCCESS);

end:
	g_free(filename);
	return;
}

/*
 * Abort ongoing key generation.
 */
void key_generation_abort(struct otr_user_state *ustate, int ignoreidle)
{
	if (kg_st.status != KEYGEN_RUNNING) {
		if (!ignoreidle) {
			IRSSI_INFO(NULL, NULL, "No ongoing key generation to abort");
		}
		goto end;
	}

	IRSSI_INFO(NULL, NULL, "Key generation for %s aborted", kg_st.accountname);

	g_source_remove(kg_st.cpid);
	g_source_remove(kg_st.cwid);
	g_free(kg_st.accountname);

	if (kg_st.pid != 0) {
		kill(kg_st.pid, SIGTERM);
		g_child_watch_add(kg_st.pid, keygen_childwatch, (void *) 1);
	}

	kg_st.status = KEYGEN_NO;

end:
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
