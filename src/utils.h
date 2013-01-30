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

#ifndef IRSSI_OTR_UTILS_H
#define IRSSI_OTR_UTILS_H

void utils_free_args(char ***argv, int argc);
void utils_extract_command(const char *data, char **_cmd);
void utils_explode_args(const char *_data, char ***_argv, int *_argc);
int utils_io_extract_smp(const char *data, char **question, char **secret);
void utils_string_to_upper(char *string);
int utils_auth_extract_secret(const char *_data, char **secret);
void utils_hash_parts_to_readable_hash(const char **parts, char *dst);
char *utils_trim_string(char *s);

#endif /* IRSSI_OTR_UTILS_H */
