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

#ifndef IRSSI_OTR_FORMATS_H
#define IRSSI_OTR_FORMATS_H

#include "irssi-otr.h"

/*
 * Must be in sync with the otr_formats array.
 */
enum otr_status_format {
	TXT_OTR_MODULE_NAME      = 0,
	TXT_OTR_FILL_1           = 1,
	TXT_STB_PLAINTEXT        = 2,
	TXT_STB_FINISHED         = 3,
	TXT_STB_UNKNOWN          = 4,
	TXT_STB_UNTRUSTED        = 5,
	TXT_STB_TRUST            = 6,
};

extern FORMAT_REC otr_formats[];

#endif /* IRSSI_OTR_FORMATS_H */
