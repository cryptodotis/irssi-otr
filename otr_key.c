/*
 * Off-the-Record Messaging (OTR) module for the irssi IRC client
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

#include "otr.h"

#include <libgen.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/poll.h>
#include <signal.h>

extern OtrlUserState otr_state;

typedef enum { KEYGEN_NO, KEYGEN_RUNNING } keygen_status_t;

struct {
	keygen_status_t status;
	char *accountname;
	char *protocol;
	time_t started;
	GIOChannel *ch[2];
	guint cpid,cwid;
	pid_t pid;
} kg_st = {.status = KEYGEN_NO };

void keygen_childwatch(GPid pid,gint status, gpointer data) {
	struct pollfd pfd = { 
		.fd = g_io_channel_unix_get_fd(kg_st.ch[0]),
		.events = POLLIN };
	int ret;

	/* nothing to do if keygen_complete has already been called */
	if (data) 
		return;

	kg_st.pid = 0;

	ret = poll(&pfd,1,0);

	/* data is there, let's wait for keygen_complete to be called */
	if (ret == 1)
		return;

	/* no data, report error and reset kg_st */
	if (ret==0) {
		if (WIFSIGNALED(status)) {
			char sigstr[16];

			sprintf(sigstr,
#ifndef HAVE_STRSIGNAL
				"%d",WTERMSIG(status));
#else
				"%s",strsignal(WTERMSIG(status)));
#endif
			otr_noticest(TXT_KG_EXITSIG,
				     kg_st.accountname,
				     sigstr);
		}
		else
			otr_noticest(TXT_KG_EXITED,kg_st.accountname);
	} else if (ret==-1)
		otr_noticest(TXT_KG_POLLERR,kg_st.accountname,strerror(errno));

	keygen_abort(FALSE);
}	

/*
 * Installed as g_io_watch and called when the key generation
 * process finishs.
 */
gboolean keygen_complete(GIOChannel *source, GIOCondition condition, 
			 gpointer data)
{
	gcry_error_t err;

	read(g_io_channel_unix_get_fd(kg_st.ch[0]),&err,sizeof(err));

	g_io_channel_shutdown(kg_st.ch[0],FALSE,NULL);
	g_io_channel_shutdown(kg_st.ch[1],FALSE,NULL);
	g_io_channel_unref(kg_st.ch[0]);
	g_io_channel_unref(kg_st.ch[1]);

	if (err)
		otr_noticest(TXT_KG_FAILED,
			     kg_st.accountname,
			     gcry_strerror(err),
			     gcry_strsource(err));
	else {
		/* reload keys */
		otr_noticest(TXT_KG_COMPLETED,
			     kg_st.accountname,
			     time(NULL)-kg_st.started);
		//otrl_privkey_forget_all(otr_state); <-- done by lib
		key_load();
	}

	g_source_remove(kg_st.cwid);
	kg_st.cwid = g_child_watch_add(kg_st.pid,keygen_childwatch,(void*)1);

	kg_st.status = KEYGEN_NO;
	g_free(kg_st.accountname);

	return FALSE;
}

/*
 * Run key generation in a seperate process (takes ages).
 * The other process will rewrite the key file, we shouldn't 
 * change anything till it's done and we've reloaded the keys.
 */
void keygen_run(const char *accname)
{
	gcry_error_t err;
	int ret;
	int fds[2];
	char *filename = g_strconcat(get_irssi_dir(),KEYFILE,NULL);
	char *dir = dirname(g_strdup(filename));

	if (kg_st.status!=KEYGEN_NO) {
		if (strcmp(accname,kg_st.accountname)!=0)
			otr_noticest(TXT_KG_ABORTED_DUP,
				     accname,kg_st.accountname);
		return;
	}

	if (!g_file_test(dir, G_FILE_TEST_EXISTS)) {
		if (g_mkdir(dir,S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH)) {
			otr_noticest(TXT_KG_ABORTED_DIR,
				     accname,dir,strerror(errno));
			g_free(dir);
			g_free(filename);
			return;
		} else
			otr_noticest(TXT_KG_MKDIR,dir);
	}
	g_free(dir);

	if (pipe(fds) != 0) {
		otr_noticest(TXT_KG_PIPE,
			     accname,strerror(errno));
		g_free(filename);
		return;
	}

	kg_st.ch[0] = g_io_channel_unix_new(fds[0]);
	kg_st.ch[1] = g_io_channel_unix_new(fds[1]);

	kg_st.accountname = g_strdup(accname);
	kg_st.protocol = PROTOCOLID;
	kg_st.started = time(NULL);

	if ((ret = fork())) {
		g_free(filename);
		if (ret==-1) {
			otr_noticest(TXT_KG_FORK,
				     accname,strerror(errno));
			return;
		}

		kg_st.status = KEYGEN_RUNNING;
		kg_st.pid = ret;

		otr_noticest(TXT_KG_INITIATED,
			     accname);

		kg_st.cpid = g_io_add_watch(kg_st.ch[0], G_IO_IN, 
					    (GIOFunc) keygen_complete, NULL);
		kg_st.cwid = g_child_watch_add(kg_st.pid,keygen_childwatch,NULL);

		kg_st.started = time(NULL);
		return;
	}

	/* child */

	err = otrl_privkey_generate(otr_state,filename,accname,PROTOCOLID);
	write(fds[1],&err,sizeof(err));

	//g_free(filename);
	_exit(0);
}

/*
 * Abort ongoing key generation.
 */
void keygen_abort(int ignoreidle)
{
	if (kg_st.status!=KEYGEN_RUNNING) {
		if (!ignoreidle)
			otr_noticest(TXT_KG_NOABORT);
		return;
	}

	otr_noticest(TXT_KG_ABORT,kg_st.accountname);

	g_source_remove(kg_st.cpid);
	g_source_remove(kg_st.cwid);
	g_free(kg_st.accountname);

	if (kg_st.pid!=0) {
		kill(kg_st.pid,SIGTERM);
		g_child_watch_add(kg_st.pid,keygen_childwatch,(void*)1);
	}

	kg_st.status = KEYGEN_NO;
}

/* 
 * Write fingerprints to file.
 */
void otr_writefps()
{
	gcry_error_t err;
	char *filename = g_strconcat(get_irssi_dir(),FPSFILE,NULL);

	err = otrl_privkey_write_fingerprints(otr_state,filename);

	if (err == GPG_ERR_NO_ERROR) {
		otr_noticest(TXT_FP_SAVED);
	} else {
		otr_noticest(TXT_FP_SAVE_ERROR,
			     gcry_strerror(err),
			     gcry_strsource(err));
	}
	g_free(filename);
}

/*
 * Load private keys.
 */
void key_load()
{
	gcry_error_t err;
	char *filename = g_strconcat(get_irssi_dir(),KEYFILE,NULL);

	if (!g_file_test(filename, G_FILE_TEST_EXISTS)) {
		otr_noticest(TXT_KEY_NOT_FOUND);
		return;
	}

	err =  otrl_privkey_read(otr_state, filename);

	if (err == GPG_ERR_NO_ERROR) {
		otr_noticest(TXT_KEY_LOADED);
	} else {
		otr_noticest(TXT_KEY_LOAD_ERROR,
			     gcry_strerror(err),
			     gcry_strsource(err));
	}
	g_free(filename);
}

/*
 * Load fingerprints.
 */
void fps_load()
{
	gcry_error_t err;
	char *filename = g_strconcat(get_irssi_dir(),FPSFILE,NULL);

	if (!g_file_test(filename, G_FILE_TEST_EXISTS)) {
		otr_noticest(TXT_FP_NOT_FOUND);
		return;
	}

	err =  otrl_privkey_read_fingerprints(otr_state,filename,NULL,NULL);

	if (err == GPG_ERR_NO_ERROR) {
		otr_noticest(TXT_FP_LOADED);
	} else {
		otr_noticest(TXT_FP_LOAD_ERROR,
			     gcry_strerror(err),
			     gcry_strsource(err));
	}
	g_free(filename);
}

