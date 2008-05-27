/*
	Off-the-Record Messaging (OTR) module for the irssi IRC client
	Copyright (C) 2008  Uli Meis <a.sporto+bee@gmail.com>

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
*/

#include <stdlib.h>

/* OTR */

#include <libotr/proto.h>
#include <libotr/message.h>
#include <libotr/privkey.h>

/* irssi */

#include <common.h>
#include <core/commands.h>
#include <core/modules.h>
#include <core/servers.h>
#include <core/signals.h>
#include <core/levels.h>
#include <core/queries.h>
#include <fe-common/core/printtext.h>
#include <fe-common/core/fe-windows.h>
#include <fe-common/core/module-formats.h>
#include <core/modules.h>

/* copied over, see FS#535 */
#include <statusbar.h>

/* glib */

#include <glib.h>
#include <glib/gprintf.h>
#include <glib/gstdio.h>

/* own */

#include "otrutil.h"
#include "ui.h"

/* irssi module name */
#define MODULE_NAME "otr"

