#!/bin/bash
if [ -z "$2" ]; then echo "Syntax: $0 <src-dir> <git-commit/tag>"; exit 1;fi
SDIR="$1"
VER=$2

PKG=irc-otr-$VER.tar
HDIR=irc-otr-$VER
mkdir "$HDIR" &&\
(cd "$HDIR" && ln -s ../irssi-headers &&\
	echo -e "SET(IRCOTR_VERSION $VER)" >tarballdefs.cmake) &&\
	for plugin in irc xchat irssi; do
		pkg=$plugin-otr-$VER
		(cd "$SDIR" && git archive --format=tar --prefix=$pkg/ HEAD )>$pkg.tar &&\
		tar rhf $pkg.tar "$HDIR" 
		gzip $pkg.tar
	done && rm $HDIR/{irssi-headers,tarballdefs.cmake} &&\
rmdir $HDIR
