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

#include <string.h>

#include "otr.h"
#include "utils.h"

static const char *lvlstring[] = {
	"NOTICE",
	"DEBUG"
};

int utils_io_extract_smp(const char *data, char **question, char **secret)
{
	unsigned int q_len, s_len;
	const char *tmp, *q_end, *q_beg, *args = data;
	char *q, *s;

	*question = *secret = NULL;

	/* Check for '[' as first char */
	q_beg = strchr(args, '[');
	if (!q_beg) {
		goto error;
	}

	/*
	 * Move to "[my questions] secret"
	 *           ^
	 */
	args = q_beg + 1;

	/* Search closing bracket for the end of the question. */
	q_end = strchr(args, ']');
	if (!q_end) {
		/* Malformed authq command */
		goto error;
	}

	/* Get the question length */
	q_len = (unsigned int) (q_end - args);

	/* Add 1 char for the \0 */
	q = malloc((q_len + 1) * sizeof(char));
	if (q == NULL) {
		goto error;
	}

	/* Copy question */
	strncpy(q, args, q_len);
	q[q_len] = '\0';

	/* Move to the closing bracket */
	args = q_end;

	tmp = strchr(args, ' ');
	if (tmp == NULL) {
		goto error;
	}

	/* Ignore the next white space */
	args = tmp + 1;

	/*
	 * "[my questions] secret"
	 *                 ^
	 */
	s_len = (unsigned int) (args - data);

	s = malloc((s_len + 1) * sizeof(char));
	if (s == NULL) {
		free(q);
		goto error;
	}

	strncpy(s, args, s_len);
	s[s_len] = '\0';

	*question = q;
	*secret = s;

	return 0;

error:
	return -1;
}

void utils_io_explode_args(const char *args, char ***argvp, char ***argv_eolp,
		int *argcp)
{
	char **argv, **argv_eol;
	char *s = (char *) args;
	int argc = 1, i;

	while ((s = strchr(s + 1, ' '))) {
		argc++;
	}

	argv = (char **) malloc(argc * sizeof(char *));
	argv_eol = (char **) malloc(argc * sizeof(char *));

	s = (char *) args;
	argv_eol[0] = strdup(args);
	i = 0;

	while (++i < argc) {
		argv_eol[i] = strchr(argv_eol[i - 1], ' ') + 1;
	}

	argv[0] = strtok(strdup(args), " ");
	i = 1;
	while (i < argc) {
		argv[i++] = strtok(NULL, " ");
		otr_logst(MSGLEVEL_CRAP, "arg %d: %s", i, argv[i - 1]);
	}

	*argvp = argv;
	*argv_eolp = argv_eol;
	*argcp = argc;
}

void otr_log(IRC_CTX *server, const char *nick, int lvl, const char *fmt, ...)
{
	va_list params;
	va_start(params, fmt);
	char msg[LOGMAX], *s = msg;

	if ((lvl == LVL_DEBUG) && !debug) {
		return;
	}

	s += sprintf(s, "%s", "%9OTR%9");

	if (lvl != LVL_NOTICE) {
		s += sprintf(s, "(%s)", lvlstring[lvl]);
	}

	s += sprintf(s, ": ");

	if (vsnprintf(s, LOGMAX, fmt, params ) < 0) {
		sprintf(s, "internal error parsing error string (BUG)");
	}
	va_end(params);

	printtext(server, nick, MSGLEVEL_MSGS, msg);
}
