/*
 * Off-the-Record Messaging (OTR) modules for IRC
 *
 * Copyright (C) 2012 - David Goulet <dgoulet@ev0ke.net>
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

#ifndef IRSSI_OTR_KEY_H
#define IRSSI_OTR_KEY_H

#include "otr.h"

/*
 * Status of key generation.
 */
enum key_gen_status {
	KEY_GEN_IDLE		= 0,
	KEY_GEN_RUNNING		= 1,
	KEY_GEN_FINISHED    = 2,
	KEY_GEN_ERROR		= 3,
};

/*
 * Data of the state of key generation.
 */
struct key_gen_data {
	struct otr_user_state *ustate;
	char *account_name;
	char *key_file_path;
	enum key_gen_status status;
	gcry_error_t gcry_error;
	void *newkey;
};

void key_gen_check(void);
void key_gen_run(struct otr_user_state *ustate, const char *account_name);
void key_load(struct otr_user_state *ustate);
void key_load_fingerprints(struct otr_user_state *ustate);
void key_write_fingerprints(struct otr_user_state *ustate);
void key_write_instags(struct otr_user_state *ustate);

#endif /* IRSSI_OTR_KEY_H */
