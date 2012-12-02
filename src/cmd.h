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

#ifndef IRSSI_OTR_CMD_H
#define IRSSI_OTR_CMD_H

#include "otr.h"

/*
 * The /otr commands structure.
 */
struct irssi_commands {
	const char *name;
	void (*func)(struct otr_user_state *ustate, SERVER_REC *irssi,
			const char *target, const void *data);
};

/*
 * This is called once the command is received and then dispatch to the correct
 * func() of the right irssi_commands.
 */
void cmd_generic(struct otr_user_state *ustate, SERVER_REC *irssi,
		const char *target, char *cmd, const void *data);

#endif /* IRSSI_OTR_CMD_H */
