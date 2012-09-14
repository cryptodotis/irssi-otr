/*
 * Off-the-Record Messaging (OTR) modules for IRC
 * Copyright (C) 2009  Uli Meis <a.sporto+bee@gmail.com>
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

#include "otr.h"

#ifdef HAVE_GREGEX_H
extern GRegex *regex_nickignore;
#endif

char set_policy[512] = IO_DEFAULT_POLICY;
char set_policy_known[512] = IO_DEFAULT_POLICY_KNOWN;
char set_ignore[512] = IO_DEFAULT_IGNORE;
int set_finishonunload = TRUE;

void cmd_set(IOUSTATE *ioustate, IRC_CTX *ircctx, int argc, char *argv[],
	     char *argv_eol[],
	     char *target)
{
	char *setting, *value;

	if (argc) {
		setting = argv[0];
		value = argv[1] ? : "";
	}

	if (!argc) {
		otr_logst(MSGLEVEL_CRAP, "policy: %s\n"
			  "policy_known: %s\nignore: %s\n"
			  "finishonunload: %s\n",
			  set_policy, set_policy_known, set_ignore,
			  set_finishonunload ? "true" : "false");
	} else if (strcmp(setting, "policy") == 0) {
		otr_setpolicies(ioustate, value, FALSE);
		strcpy(set_policy, value);
	} else if (strcmp(setting, "policy_known") == 0) {
		otr_setpolicies(ioustate, value, TRUE);
		strcpy(set_policy_known, value);
	} else if (strcmp(setting, "ignore") == 0) {
#ifdef HAVE_GREGEX_H
		if (regex_nickignore)
			g_regex_unref(regex_nickignore);
		regex_nickignore = g_regex_new(value, 0, 0, NULL);
		strcpy(set_ignore, value);
#endif
	} else if (strcmp(setting, "finishonunload") == 0) {
		set_finishonunload = (strcasecmp(value, "true") == 0);
	}
}
