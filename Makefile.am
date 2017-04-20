DISTCHECK_CONFIGURE_FLAGS = \
  --with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)

CLEANFILES =

sbin_PROGRAMS = bLsched
bLsched_SOURCES = src/bLsched.c

docdir = $(datadir)/doc/@PACKAGE@
doc_DATA = AUTHORS COPYING NEWS README

EXTRA_DIST = src/bLsched.service.in

if HAVE_SYSTEMD
systemdsystemunit_DATA = \
	src/bLsched.service

CLEANFILES += src/bLsched.service
endif

SED_PROCESS = $(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
		$(SED) -e 's,\@sbindir\@,$(sbindir),g' \
		< $< > $@

%.service: %.service.in Makefile
	$(SED_PROCESS)

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 configure config.h.in config.sub config.guess \
	ltmain.sh depcomp compile missing install-sh mkinstalldirs test-driver
