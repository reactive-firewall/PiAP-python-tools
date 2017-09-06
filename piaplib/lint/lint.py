#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Pocket PiAP
# ......................................................................
# Copyright (c) 2017, Kendrick Walls
# ......................................................................
# Licensed under MIT (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# ......................................................................
# http://www.github.com/reactive-firewall/PiAP-python-tools/LICENSE.rst
# ......................................................................
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ......................................................................


try:
	import os
	import sys
	import argparse
	sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
	try:
		import piaplib as piaplib
	except Exception:
		from . import piaplib as piaplib
	try:
		from .. import utils as utils
	except Exception:
		import pku.utils as utils
	try:
		from .. import remediation as remediation
	except Exception:
		import pku.remediation as remediation
	try:
		from . import html_generator as html_generator
	except Exception as ImpErr:
		ImpErr = None
		del ImpErr
		import html_generator as html_generator
	try:
		from .. import interfaces as interfaces
	except Exception:
		import pku.interfaces as interfaces
	for depends in [interfaces, html_generator, remediation, utils]:
		if depends.__name__ is None:
			raise ImportError("Failed to import depends.")
except Exception as importErr:
	print(str(importErr))
	print(str(importErr.args))
	importErr = None
	del importErr
	raise ImportError("Failed to import " + str(__file__))
	exit(255)

try:
	from . import check as check
except Exception:
	import check as check

try:
	from . import do_execve as do_execve
except Exception:
	import do_execve as do_execve


__prog__ = """piaplib.lint"""
"""The name of this PiAPLib tool is keyring"""


LINT_UNITS = {u'html': html_generator, u'check': check, u'execve': do_execve}
"""	The Pocket Knife Unit actions.
	check - monitoring checks
	execve - sandbox functions.
	html -  (FUTURE/RESERVED)
	"""


@remediation.error_handling
def parseArgs(arguments=None):
	"""Parses the CLI arguments."""
	parser = argparse.ArgumentParser(
		prog=__prog__,
		description='Handles PiAP pocket lint',
		epilog="PiAP Lint Controller for extra tools."
	)
	parser.add_argument(
		'lint_unit',
		choices=LINT_UNITS.keys(),
		help='the pocket lint service option.'
	)
	parser.add_argument('-V', '--version', action='version', version=str(
		"%(prog)s {}"
	).format(str(piaplib.__version__)))
	return parser.parse_known_args(arguments)


@remediation.error_handling
def useLintTool(tool, arguments=[None]):
	"""Handler for launching pocket-tools."""
	if tool is None:
		return None
	if tool in LINT_UNITS.keys():
		theResult = LINT_UNITS[tool].main(arguments)
		return theResult
	else:
		return None


@remediation.bug_handling
def main(argv=None):
	"""The main event"""
	args, extra = parseArgs(argv)
	lint_cmd = args.lint_unit
	useLintTool(lint_cmd, extra)
	return 0


if __name__ in u'__main__':
	try:
		import sys
		error_code = main(sys.argv[1:])
		exit(error_code)
	except Exception as err:
		print(str(u'MAIN FAILED DURRING LINT. ABORT.'))
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		del err
		exit(255)
	finally:
		exit(0)

