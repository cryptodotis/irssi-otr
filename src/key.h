/*
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

typedef enum { KEYGEN_NO, KEYGEN_RUNNING } keygen_status_t;

void key_generation_abort(IOUSTATE *ioustate, int ignoreidle);
void key_generation_run(IOUSTATE *ioustate, const char *accname);
void key_load(IOUSTATE *ioustate);
void key_load_fingerprints(IOUSTATE *ioustate);
void otr_writefps(IOUSTATE *ioustate);
void otr_writeinstags(IOUSTATE *ioustate);
void instag_load(IOUSTATE *ioustate);

#endif /* IRSSI_OTR_KEY_H */
