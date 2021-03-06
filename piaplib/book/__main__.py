#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Pocket PiAP
# ......................................................................
# Copyright (c) 2017-2020, Kendrick Walls
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
	if sys.__name__ is None:
		raise ImportError("OMG! we could not import os. We're like in the matrix! ABORT. ABORT.")
except Exception as err:
	raise ImportError(err)


try:
	if 'os' not in sys.modules:
		import os
	else:  # pragma: no branch
		os = sys.modules["""os"""]
except Exception:
	raise ImportError("OS Failed to import.")


try:
	if 'argparse' not in sys.modules:
		import argparse as argparse
	else:  # pragma: no branch
		argparse = sys.modules["""argparse"""]
except Exception:
	raise ImportError("argparse Failed to import")


try:
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
	if 'piaplib' not in sys.modules:
		raise ImportError("Pocket Book failed to import.")  # import piaplib as piaplib
	piaplib = sys.modules["""piaplib"""]
except Exception:
	raise ImportError("OMG! we could not import piaplib. We're in need of a fix! ABORT.")


try:
	if str("piaplib.book.logs") not in sys.modules:
		from piaplib.book import logs
	else:
		logs = sys.modules[str("piaplib.book.logs")]
except Exception:
	try:
		import piaplib.book.logs
	except Exception as err:
		raise ImportError(err, "Error Importing piaplib.book.logs")


try:
	if str("piaplib.pku.remediation") not in sys.modules:
		from piaplib.pku import remediation as remediation
	else:
		remediation = sys.modules[str("piaplib.pku.remediation")]
except Exception:
	try:
		import piaplib.pku.remediation as remediation
	except Exception as err:
		raise ImportError(err, "Error Importing remediation")


try:
	if str("piaplib.book.version") not in sys.modules:
		from piaplib.book import version
	else:
		version = sys.modules[str("piaplib.book.version")]
except Exception:
	try:
		import piaplib.book.version
	except Exception as err:
		raise ImportError(err, "Error Importing piaplib.book.version")


__prog__ = """piaplib.book"""
"""The name of this PiAPLib tool is pocket book"""


BOOK_UNITS = {u'logs': piaplib.book.logs, u'cache': None, u'version': version}
"""	The Pocket Book Unit actions.
	logs - logbook for logs and output
	version - like the copyright page in old books
	cache - cache and posibly memoization (FUTURE/RESERVED).
	learn -  (FUTURE/RESERVED)
	"""


def generateParser(calling_parser_group):
	"""Parses the CLI arguments."""
	if calling_parser_group is None:
		parser = argparse.ArgumentParser(
			prog=__prog__,
			description='Handles PiAP pocket book',
			epilog="PiAP Book Controller for extra tools."
		)
	else:
		parser = calling_parser_group.add_parser(
			str(__prog__).split(".")[-1], help='Handles PiAP pocket book'
		)
	subparser = parser.add_subparsers(
		title="Units", dest='book_unit',
		help='The pocket book options.', metavar="BOOK_UNIT"
	)
	parser.add_argument('-V', '--version', action='version', version=str(
		"%(prog)s {}"
	).format(str(piaplib.__version__)))
	for sub_parser in sorted(BOOK_UNITS.keys()):
		if BOOK_UNITS[sub_parser] is not None:
			subparser = BOOK_UNITS[sub_parser].generateParser(subparser)
	if calling_parser_group is None:
		calling_parser_group = parser
	return calling_parser_group


@remediation.error_handling
def parseArgs(arguments=None):
	"""Parses the CLI arguments."""
	parser = generateParser(None)
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
	useBookTool(book_cmd, argv[1:])
	return 0


if __name__ in u'__main__':
	exit_code = main(sys.argv[1:])
	exit(exit_code)

