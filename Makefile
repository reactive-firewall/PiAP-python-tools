#!/usr/bin/env make -f

# License
#
# Copyright (c) 2017 Mr. Walls
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#


ifeq "$(ECHO)" ""
	ECHO=echo
endif

ifeq "$(LINK)" ""
	LINK=ln -sf
endif

ifeq "$(MAKE)" ""
	MAKE=make
endif

ifeq "$(WAIT)" ""
	WAIT=wait
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

ifeq "$(DO_FAIL)" ""
	DO_FAIL=$(ECHO) "ok"
endif

PHONY: must_be_root cleanup

build:
	$(QUIET)$(ECHO) "No need to build. Try make -f Makefile install"

init:
	$(QUIET)$(ECHO) "$@: Done."

install: must_be_root
	$(QUIET)python3 -m pip install "git+https://github.com/reactive-firewall/PiAP-python-tools.git#egg=piaplib"
	$(QUITE)$(WAIT)
	$(QUIET)$(ECHO) "$@: Done."

uninstall:
	$(QUITE)$(QUIET)python3 -m pip uninstall piaplib || true
	$(QUITE)$(WAIT)
	$(QUIET)$(ECHO) "$@: Done."

purge: clean uninstall
	$(QUIET)python3 -m pip uninstall piaplib && python -m pip uninstall piaplib || true
	$(QUIET)$(ECHO) "$@: Done."

test: cleanup
	$(QUIET)coverage run -p --source=piaplib,piaplib/lint,piaplib/keyring,piaplib/pku,piaplib/book -m unittest discover --verbose -s ./tests -t ./ || python3 -m unittest discover --verbose -s ./tests -t ./ || python -m unittest discover --verbose -s ./tests -t ./ || DO_FAIL=exit 2 ;
	$(QUIET)coverage combine 2>/dev/null || true
	$(QUIET)coverage report --include=piaplib* 2>/dev/null || true
	$(QUIET)$(DO_FAIL);
	$(QUIET)$(ECHO) "$@: Done."

test-mats: cleanup
	$(QUIET)coverage run -p --source=piaplib,piaplib/lint,piaplib/keyring,piaplib/pku,piaplib/book -m unittest tests.test_basic tests.test_html tests.test_strings tests.test_salt tests.test_rand tests.test_utils tests.test_lint tests.test_book tests.test_interface tests.test_config tests.test_usage tests.test_pocket || python3 -m unittest tests.test_basic tests.test_html tests.test_strings tests.test_salt tests.test_rand tests.test_utils tests.test_lint tests.test_book tests.test_interface tests.test_config tests.test_usage tests.test_pocket || python -m unittest tests.test_basic tests.test_html tests.test_strings tests.test_salt tests.test_rand tests.test_utils tests.test_lint tests.test_interface tests.test_book tests.test_config tests.test_usage tests.test_pocket
	$(QUIET)coverage combine 2>/dev/null || true
	$(QUIET)coverage report --include=piaplib* 2>/dev/null || true
	$(QUIET)$(ECHO) "$@: Done."

test-tox: cleanup
	$(QUIET)tox -v --
	$(QUIET)$(ECHO) "$@: Done."

test-style: cleanup
	$(QUIET)flake8 --ignore=W191,W391 --max-line-length=100 --verbose --count
	$(QUIET)$(ECHO) "$@: Done."

cleanup:
	$(QUIET)rm -f tests/*.pyc 2>/dev/null || true
	$(QUIET)rm -f tests/*~ 2>/dev/null || true
	$(QUIET)rm -Rf tests/__pycache__ 2>/dev/null || true
	$(QUIET)rm -f piaplib/*.pyc 2>/dev/null || true
	$(QUIET)rm -Rf piaplib/__pycache__ 2>/dev/null || true
	$(QUIET)rm -Rf piaplib/*/__pycache__ 2>/dev/null || true
	$(QUIET)rm -f piaplib/*~ 2>/dev/null || true
	$(QUIET)rm -f *.pyc 2>/dev/null || true
	$(QUIET)rm -f piaplib/*/*.pyc 2>/dev/null || true
	$(QUIET)rm -f piaplib/*/*~ 2>/dev/null || true
	$(QUIET)rm -f *.DS_Store 2>/dev/null || true
	$(QUIET)rm -f piaplib/*.DS_Store 2>/dev/null || true
	$(QUIET)rm -f piaplib/*/*.DS_Store 2>/dev/null || true
	$(QUIET)rm -f piaplib.egg-info/* 2>/dev/null || true
	$(QUIET)rmdir piaplib.egg-info 2>/dev/null || true
	$(QUIET)rm -f ./*/*~ 2>/dev/null || true
	$(QUIET)rm -f ./*~ 2>/dev/null || true
	$(QUIET)coverage erase 2>/dev/null || true
	$(QUIET)rm -f ./.coverage 2>/dev/null || true
	$(QUIET)rm -f ./sitecustomize.py 2>/dev/null || true
	$(QUIET)rm -f ./.*~ 2>/dev/null || true
	$(QUIET)rm -Rf ./.tox/ 2>/dev/null || true
	$(QUIET)rm -f ./the_test_file*.txt 2>/dev/null || true
	$(QUIET)rm -f ./the_test_file*.json 2>/dev/null || true
	$(QUIET)rm -f ./the_test_file*.yml 2>/dev/null || true
	$(QUIET)rm -f ./the_test_file*.yaml 2>/dev/null || true
	$(QUIET)rm -f /tmp/.beta_PiAP_weak_key 2>/dev/null || true

clean: cleanup
	$(QUIET)$(MAKE) -s -C ./docs/ -f Makefile clean 2>/dev/null || true
	$(QUIET)$(ECHO) "$@: Done."

must_be_root:
	$(QUIET)runner=`whoami` ; \
	if test $$runner != "root" ; then echo "You are not root." ; exit 1 ; fi

%:
	$(QUIET)$(ECHO) "No Rule Found For $@" ; $(WAIT) ;

