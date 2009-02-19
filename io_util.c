/*
 * Off-the-Record Messaging (OTR) modules for IRC
 * Copyright (C) 2008  Uli Meis <a.sporto+bee@gmail.com>
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

int extract_nick(char *nick, char *line)
{
	char *excl;

	if (*line++ != ':')
		return FALSE;

	strcpy(nick,line);
	
	if ((excl = strchr(nick,'!')))
		*excl = '\0';

	return TRUE;

}

int cmd_generic(IOUSTATE *ioustate, IRC_CTX *ircctx, int argc, char *argv[], char *argv_eol[],
		char *target)
{
	char *cmd;
	struct _cmds *commands = cmds;

	if (!argc) {
		otr_noticest(TXT_CMD_OTR);
		return TRUE;
	}

	cmd = argv[0];

	argv++;
	argv_eol++;
	argc--;
	
	do {
		if (strcmp(commands->name,cmd)==0) {
			commands->cmdfunc(ioustate,ircctx,argc,argv,argv_eol,target);
			return TRUE;
		}
	} while ((++commands)->name);

	return FALSE;
}

void cmd_debug(IOUSTATE *ioustate, IRC_CTX *ircctx, int argc, char *argv[], char *argv_eol[],
	      char *target) {
	debug = !debug;
	otr_noticest(debug ? TXT_CMD_DEBUG_ON : TXT_CMD_DEBUG_OFF);
}

void cmd_version(IOUSTATE *ioustate, IRC_CTX *ircctx, int argc, char *argv[], char *argv_eol[],
		char *target) {
	otr_noticest(TXT_CMD_VERSION,IRCOTR_VERSION);
}

void cmd_help(IOUSTATE *ioustate, IRC_CTX *ircctx, int argc, char *argv[], char *argv_eol[],
		char *target) {
	otr_log(ircctx,target,MSGLEVEL_CRAP,otr_help);
}

void cmd_finish(IOUSTATE *ioustate, IRC_CTX *ircctx, int argc, char *argv[], char *argv_eol[],
	       char *target) {
	if (argc)
		otr_finish(NULL,NULL,argv[0],TRUE);
	else if (ircctx&&target)
		otr_finish(ircctx,target,NULL,TRUE);
	else
		otr_noticest(TXT_CMD_QNOTFOUND);

}

void cmd_trust(IOUSTATE *ioustate, IRC_CTX *ircctx, int argc, char *argv[], char *argv_eol[],
	      char *target) {
	if (argc)
		otr_trust(NULL,NULL,argv[0]);
	else if (ircctx&&target)
		otr_trust(ircctx,target,NULL);
	else
		otr_noticest(TXT_CMD_QNOTFOUND);
}

void cmd_authabort(IOUSTATE *ioustate, IRC_CTX *ircctx, int argc, char *argv[], char *argv_eol[], 
		  char *target) {
	if (argc)
		otr_authabort(NULL,NULL,argv[0]);
	else if (ircctx&&target)
		otr_authabort(ircctx,target,NULL);
	else
		otr_noticest(TXT_CMD_QNOTFOUND);
}

void cmd_genkey(IOUSTATE *ioustate, IRC_CTX *ircctx, int argc, char *argv[], char *argv_eol[],
	       char *target) {
	if (argc) {
		if (strcmp(argv[0],"abort")==0)
			keygen_abort(ioustate,FALSE);
		else if (strchr(argv[0],'@'))
			keygen_run(ioustate,argv[0]);
		else
			otr_noticest(TXT_KG_NEEDACC);
	} else {
		otr_noticest(TXT_KG_NEEDACC);
	}
}

void cmd_auth(IOUSTATE *ioustate, IRC_CTX *ircctx, int argc, char *argv[], char *argv_eol[],
	     char *target) {
	if (!argc) {
		otr_notice(ircctx,target,
			   TXT_CMD_AUTH);
	} else if ((argc>1)&&strchr(argv[0],'@')) {
	    otr_auth(NULL,NULL,argv[0],argv[1]);
	} else if (ircctx&&target) {
		otr_auth(ircctx,target,NULL,argv_eol[0]);
	} else {
		otr_noticest(TXT_CMD_QNOTFOUND);
	}
}

/*
 * /otr contexts
 */
void cmd_contexts(IOUSTATE *ioustate, IRC_CTX *ircctx, int argc, char *argv[], char *argv_eol[],
	     char *target) {
	struct ctxlist_ *ctxlist = otr_contexts(ioustate),*ctxnext = ctxlist;
	struct fplist_ *fplist,*fpnext;

	if (!ctxlist)
		otr_infost(TXT_CTX_NOCTXS);

	while (ctxlist) {
		otr_infost(TXT_CTX_CTX_UNENCRYPTED+ctxlist->state,
			    ctxlist->username,
			    ctxlist->accountname);

		fplist = ctxlist->fplist;
		while (fplist) {
			otr_infost(TXT_CTX_FPS_NO+fplist->authby,
				    fplist->fp);
			fplist = fplist->next;
		}
		ctxlist = ctxlist->next;
	}
	while ((ctxlist = ctxnext)) {
		ctxnext = ctxlist->next;
		fpnext = ctxlist->fplist;
		while ((fplist = fpnext)) {
			fpnext = fplist->next;
			g_free(fplist->fp);
			g_free(fplist);
		}
		g_free(ctxlist);
	}
}

struct _cmds cmds[] = {
	{ "version", cmd_version },
	{ "debug", cmd_debug },
	{ "help", cmd_help },
	{ "finish", cmd_finish },
	{ "trust", cmd_trust },
	{ "authabort", cmd_authabort },
	{ "auth", cmd_auth },
	{ "genkey", cmd_genkey },
	{ "contexts", cmd_contexts },
	{ NULL, NULL },
	{ NULL, NULL }};

void io_explode_args(const char *args, char ***argvp, char ***argv_eolp, int *argcp)
{
	char **argv, **argv_eol;
	char *s = (char*)args;
	int argc=1,i;

	while ((s = strchr(s+1,' ')))
	       argc++;

	argv = (char **)malloc(sizeof(char *)*argc);
	argv_eol = (char **)malloc(sizeof(char *)*argc);

	s = (char*)args;
	argv_eol[0] = strdup(args);
	i = 0;
	while (++i<argc)
		argv_eol[i] = strchr(argv_eol[i-1],' ')+1;

	argv[0] = strtok(strdup(args)," ");
	i = 1;
	while (i<argc) {
		argv[i++] = strtok(NULL," ");
		otr_logst(MSGLEVEL_CRAP,"arg %d: %s",i,argv[i-1]);
	}

	*argvp = argv;
	*argv_eolp = argv_eol;
	*argcp = argc;
}
