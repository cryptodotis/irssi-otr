/*
 * Off-the-Record Messaging (OTR) modules for IRC
 *
 * Copyright (C) - 2012  David Goulet <dgoulet@ev0ke.net>
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

#include "otr.h"
#include "otr-formats.h"

FORMAT_REC otr_formats[] = {
	{ MODULE_NAME, "OTR", 0 },

	/* Status bar format. */
	{ NULL, "Statusbar", 0 } ,

	{ "stb_plaintext", "{sb plaintext}", 0},
	{ "stb_finished", "{sb %yfinished%n}", 0},
	{ "stb_unknown", "{sb {hilight state unknown (BUG!)}}", 0},
	{ "stb_untrusted", "{sb %GOTR%n (%runverified%n)}", 0},
	{ "stb_trust", "{sb %GOTR%n}", 0},

	/* Last element. */
	{ NULL, NULL, 0 }
};
