#!/bin/bash
if [ -z "$2" ]; then echo "Syntax: $0 <src-dir> <git-commit/tag>"; exit 1;fi
SDIR="$1"
#VER=`(cd "$SDIR/.git/refs/tags/" && ls -t)|head -n1|sed -e 's/.//'`
VER=$2
PKG=irssi-otr-$VER.tar
HDIR=irssi-otr-$VER
mkdir "$HDIR" &&\
(cd "$SDIR" && git archive --format=tar --prefix=irssi-otr-$VER/ HEAD )>$PKG &&\
(cd "$HDIR" && ln -s ../irssi-headers &&\
	echo "SET(IRSSIOTR_VERSION $VER)" >tarballdefs.cmake) &&\
tar rhf $PKG "$HDIR" &&\
rm $HDIR/{irssi-headers,tarballdefs.cmake} &&\
rmdir $HDIR &&\
gzip $PKG
