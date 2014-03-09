AM_CFLAGS = $(PACKAGE_CFLAGS)

ACLOCAL_AMFLAGS = -I config

SUBDIRS = help \
		  src

EXTRA_DIST = README.md LICENSE ChangeLog bootstrap

EXTRA_DIST += irssi-otr.spec.in

RPM_DIRS = --define "_sourcedir `pwd`" \
           --define "_rpmdir `pwd`/rpmbuild" \
           --define "_specdir `pwd`" \
           --define "_builddir `pwd`/rpmbuild" \
           --define "_srcrpmdir `pwd`/rpmbuild"

rpm: dist-bzip2 irssi-otr.spec
	rpmbuild $(RPM_DIRS) -ba irssi-otr.spec
srpm: dist-bzip2 irssi-otr.spec
	rpmbuild $(RPM_DIRS) -bs irssi-otr.spec
