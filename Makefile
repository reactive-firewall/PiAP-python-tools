#!/usr/bin/env make -f

ifeq "$(ECHO)" ""
	ECHO=echo
endif

ifeq "$(LINK)" ""
	LINK=ln -sf
endif


ifeq "$(MAKE)" ""
	MAKE=make
endif

ifeq "$(INSTALL)" ""
	INSTALL=install
	ifeq "$(INST_OWN)" ""
		INST_OWN=-o root -g staff
	endif
	ifeq "$(INST_OPTS)" ""
		INST_OPTS=-m 755
	endif
endif

ifeq "$(LOG)" ""
	LOG=no
endif

ifeq "$(LOG)" "no"
	QUIET=@
endif

PHONY: must_be_root

build:
	$(QUIET)$(ECHO) "No need to build. Try make -f Makefile install"

init:
	$(QUIET)$(ECHO) "$@: Done."

install: /usr/local/bin/ /var/lib/restart_service_handler/ must_be_root
	$(QUITE)$(INSTALL) $(INST_OWN) $(INST_OPTS) ./code/pocket.py /var/opt/piaplib/pocket.py
	$(QUITE)$(LINK) /var/opt/piaplib/pocket.py /usr/local/bin/pocket.py
	$(QUITE) $(WAIT)
	$(QUITE)$(INSTALL) $(INST_OWN) $(INST_OPTS) ./piaplib/__init__.py /var/opt/piaplib/__init__.py
	$(QUITE) $(WAIT)
	$(QUIET)$(ECHO) "$@: Done."

uninstall:
	$(QUITE)unlink /usr/local/bin/pocket.py 2>/dev/null || true
	$(QUITE)rm -vfR /var/opt/piaplib/ 2>/dev/null || true
	$(QUITE) $(WAIT)
	$(QUIET)$(ECHO) "$@: Done."

purge: clean uninstall
	$(QUIET)$(ECHO) "$@: Done."

test:
	$(QUIET)python -m unittest tests.test_basic
	$(QUIET)$(ECHO) "$@: Done."

clean:
	$(QUIET)$(MAKE) -C ./docs/ -f Makefile clean 2>/dev/null
	$(QUIET)rm -f tests/*.pyc 2>/dev/null
	$(QUIET)rm -f piaplib/*.pyc 2>/dev/null
	$(QUIET)rm -f *.pyc 2>/dev/null
	$(QUIET)rm -f *.DS_Store 2>/dev/null
	$(QUIET)rm -f ./*/*~ 2>/dev/null
	$(QUIET)$(ECHO) "$@: Done."

must_be_root:
	runner=`whoami` ; \
	if test $$runner != "root" ; then echo "You are not root." ; exit 1 ; fi

/var/lib/piaplib/: /var/lib/ must_be_root
	$(QUITE)$(INSTALL) -d $(INST_OWN) $(INST_OPTS) "$@" 2>/dev/null
	$(QUITE)$(WAIT)

/usr/local/bin/: /usr/local/ must_be_root
	$(QUITE)$(INSTALL) -d $(INST_OWN) $(INST_OPTS) "$@" 2>/dev/null || true
	$(QUITE)$(WAIT)

%:
	$(QUIET)$(ECHO) "No Rule Found For $@" ; $(WAIT) ;

