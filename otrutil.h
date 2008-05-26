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


/* 
 * maybe this should be configurable?
 * I believe bitlbee has something >500.
 */
#define OTR_MAX_MSG_SIZE 400

/* otr protocol id */
#define PROTOCOLID "IRC"

#define KEYFILE "/.irssi/otr/otr.key"

int otrlib_init();
void otrlib_deinit();
void key_load();
char *otr_send(SERVER_REC *server,const char *msg,const char *to);
char *otr_receive(SERVER_REC *server,const char *msg,const char *from);
void keygen_run(const char *accname);
