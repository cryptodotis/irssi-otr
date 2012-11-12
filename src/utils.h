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

#ifndef IRSSI_OTR_UTILS_H
#define IRSSI_OTR_UTILS_H

/*
 * Max size of a log message.
 */
#define LOGMAX      1024

#define LVL_NOTICE  0
#define LVL_DEBUG   1

#define otr_logst(level, fmt, ...) \
	otr_log(NULL, NULL, level, fmt, ## __VA_ARGS__)

void otr_log(IRC_CTX *server, const char *to, int lvl, const char *fmt, ...);

void utils_io_explode_args(const char *args, char ***argvp, char ***argv_eolp,
		int *argcp);
int utils_io_extract_smp(const char *data, char **question, char **secret);
void utils_string_to_upper(char *string);
void utils_hash_parts_to_readable_hash(const char **parts, char *dst);

#endif /* IRSSI_OTR_UTILS_H */
