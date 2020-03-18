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
		import argparse
	else:  # pragma: no branch
		argparse = sys.modules["""argparse"""]
except Exception:
	raise ImportError("functools Failed to import.")


try:
	try:
		import piaplib as piaplib
	except Exception:
		from .. import piaplib as piaplib
	try:
		from .. import utils as utils
	except Exception:
		import pku.utils as utils
	try:
		from .. import remediation as remediation
	except Exception:
		import pku.remediation as remediation
	for depends in [piaplib, remediation, utils]:
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
	from . import clients_check_status as clients_check_status
except Exception:
	import clients_check_status as clients_check_status

try:
	from . import iface_check_status as iface_check_status
except Exception:
	import iface_check_status as iface_check_status

try:
	from . import users_check_status as users_check_status
except Exception:
	import users_check_status as users_check_status

try:
	from piaplib.book.logs import logs as logs
except Exception:
	try:
		from piaplib.book.logs import logs as logs
	except Exception:
		raise ImportError("Error Importing logs")


__prog__ = """piaplib.lint.check"""
"""The name of this PiAPLib tool is check"""


__description__ = """Handles PiAP pocket checks"""


__epilog__ = """PiAP Pocket Check Controller for health checks."""


CHECK_UNITS = {
	u'clients': clients_check_status,
	u'iface': iface_check_status,
	u'users': users_check_status
}
"""	The Pocket Lint Check actions.
	clients - client monitoring checks
	iface - interface health checks.
	users - users health checks.
	fw -  (FUTURE/RESERVED)
	"""


def generateParser(calling_parser_group):
	"""Parses the CLI arguments."""
	if calling_parser_group is None:
		parser = argparse.ArgumentParser(
			prog=__prog__,
			description=__description__,
			epilog=__epilog__
		)
	else:
		parser = calling_parser_group.add_parser(
			str(__prog__).split(".")[-1], help='the pocket lint service option.'
		)
	parser = utils._handleVersionArgs(parser)
	subparser = parser.add_subparsers(
		title="Checks", dest='check_unit',
		help='the pocket service check option.', metavar="CHECK_UNIT"
	)
	for sub_parser in sorted(CHECK_UNITS.keys()):
		if CHECK_UNITS[sub_parser] is not None:
			subparser = CHECK_UNITS[sub_parser].generateParser(subparser)
	if calling_parser_group is None:
		calling_parser_group = parser
	return calling_parser_group


@remediation.error_handling
def parseArgs(arguments=None):
	"""Parses the CLI arguments."""
	parser = generateParser(None)
	return parser.parse_known_args(arguments)


@remediation.error_handling
def useCheckTool(tool, arguments=[None]):
	"""Handler for launching pocket-tools."""
	if tool is None:
		return None
	if tool in CHECK_UNITS.keys():
		theResult = None
		try:
			logs.log(str("check launching: " + str(tool)), "DEBUG")
			theResult = CHECK_UNITS[tool].main(arguments)
		except Exception:
			logs.log(
				str("An error occurred while handling the health check tool. Cascading failure."),
				"WARNING"
			)
			theResult = None
		return theResult
	else:
		return None


@remediation.bug_handling
def main(argv=None):
	"""The main event"""
	try:
		try:
			(args, extra) = parseArgs(argv)
			chk_cmd = args.check_unit
			useCheckTool(chk_cmd, argv[1:])
		except Exception as cerr:
			logs.log(
				str(
					"An error occurred while handling the arguments. Command failure."
				),
				"ERROR"
			)
			logs.log(str(type(cerr)), "ERROR")
			logs.log(str(cerr), "ERROR")
			logs.log(str((cerr.args)), "ERROR")
			cerr = None
			del(cerr)
			return 3
	except Exception:
		logs.log(
			str(
				"An error occurred while handling the failure. Cascading failure."
			),
			"ERROR"
		)
		return 3
	return 0


if __name__ in u'__main__':
	try:
		import sys
		if (sys.argv is not None and (sys.argv is not []) and (len(sys.argv) > 1)):
			exit(main(sys.argv[1:]))
		else:
			exit(main(["--help"]))
	except Exception:
		raise ImportError("Error running main")
	exit(0)

