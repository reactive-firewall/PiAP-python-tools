#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Pocket PiAP
# ......................................................................
# Copyright (c) 2017-2018, Kendrick Walls
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
	import sys
	import os
	import argparse
	if str("book") in __file__:
		__sys_path__ = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
		if __sys_path__ not in sys.path:
			sys.path.insert(0, __sys_path__)
except Exception as importErr:
	print(str(importErr))
	print(str(importErr.args))
	importErr = None
	del importErr
	raise ImportError("Failed to import " + str(__file__))


try:
	try:
		if 'piaplib' not in sys.modules:
			import piaplib as piaplib
		else:
			piaplib = sys.modules['piaplib']
	except Exception:
		from . import piaplib as piaplib
	if piaplib.__name__ is None:
		raise ImportError("OMG! we could not import piaplib. We're in need of a fix! ABORT.")
except Exception as err:
	raise ImportError(err)
	exit(3)

try:
	from piaplib.pku import baseconfig as baseconfig
except Exception:
	try:
		if 'piaplib.pku.baseconfig' not in sys.modules:
			import piaplib.pku.baseconfig as baseconfig
		else:
			baseconfig = sys.modules['piaplib.pku.baseconfig']
	except Exception:
		raise ImportError("Error Importing baseconfig")


try:
	try:
		from .logs import logs as logs
	except Exception:
		import logs.logs as logs
	try:
		from piaplib.pku import remediation as remediation
	except Exception:
		import piaplib.pku.remediation as remediation
	try:
		from . import version as version
	except Exception:
		import book.version as version
	for dep in [piaplib, baseconfig, remediation, logs, version]:
		if dep.__name__ is None:
			raise ImportError("Failed to open dependency for book")
except Exception as importErr:
	print(str(importErr))
	print(str(importErr.args))
	importErr = None
	del importErr
	raise ImportError("Failed to import " + str(__file__))


__prog__ = """piaplib.book"""
"""The name of this PiAPLib tool is pocket book"""


BOOK_UNITS = {u'logs': logs, u'cache': None, u'version': version}
"""	The Pocket Book Unit actions.
	logs - logbook for logs and output
	version - like the copyright page in old books
	cache - cache and posibly memoization (FUTURE/RESERVED).
	learn -  (FUTURE/RESERVED)
	"""


@remediation.error_handling
def parseArgs(arguments=None):
	"""Parses the CLI arguments."""
	parser = argparse.ArgumentParser(
		prog=__prog__,
		description='Handles PiAP pocket book',
		epilog="PiAP Book Controller for extra tools."
	)
	parser.add_argument(
		'book_unit',
		choices=BOOK_UNITS.keys(),
		help='The pocket book option.'
	)
	parser.add_argument('-V', '--version', action='version', version=str(
		"%(prog)s {}"
	).format(str(piaplib.__version__)))
	return parser.parse_known_args(arguments)


@remediation.error_handling
def useBookTool(tool, arguments=[None]):
	"""Handler for launching pocket-tools."""
	if tool is None:
		return 3
	if tool in BOOK_UNITS.keys():
		BOOK_UNITS[tool].main(arguments)
		return 0
	else:
		return 3


@remediation.bug_handling
def main(argv=None):
	"""The main event"""
	args, extra = parseArgs(argv)
	book_cmd = args.book_unit
	useBookTool(book_cmd, extra)
	return 0


if __name__ in u'__main__':
	exit_code = main(sys.argv[1:])
	exit(exit_code)

