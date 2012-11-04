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

#ifndef IRSSI_OTR_CMD_H
#define IRSSI_OTR_CMD_H

#include "otr.h"

struct irssi_commands {
	const char *name;
	void (*func)(IOUSTATE *ioustate, IRC_CTX *ircctx, int argc, char *argv[],
			char *argv_eol[], char *target, const char *orig_args);
};

int cmd_generic(IOUSTATE *ioustate, IRC_CTX *ircctx, int argc, char *argv[],
		char *argv_eol[], char *target, const char *orig_args);

#endif /* IRSSI_OTR_CMD_H */
