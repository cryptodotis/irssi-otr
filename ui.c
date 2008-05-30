/*
 * Off-the-Record Messaging (OTR) module for the irssi IRC client
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

char *lvlstring[] = { 
	"NOTICE",
	"DEBUG"
};


void otr_log(SERVER_REC *server, const char *nick, 
	     int level, const char *format, ...) {
	va_list params;
	va_start( params, format );
	char msg[LOGMAX], *s = msg;

	if ((level==LVL_DEBUG)&&!debug)
		return;

	s += sprintf(s,"%s","%9OTR%9");

	if (level!=LVL_NOTICE)	
		s += sprintf(s,"(%s)",lvlstring[level]);

	s += sprintf(s,": ");

	if( vsnprintf( s, LOGMAX, format, params ) < 0 )
		sprintf( s, "internal error parsing error string (BUG)" );
	va_end( params );

	printtext(server, nick, MSGLEVEL_CRAP, msg);
}
