#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Pocket PiAP
# ..................................
# Copyright (c) 2017, Kendrick Walls
# ..................................
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# ..........................................
# http://www.apache.org/licenses/LICENSE-2.0
# ..........................................
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys
import argparse
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
	import piaplib as piaplib
except Exception:
	from .. import piaplib as piaplib

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
	from piaplib.pku import remediation as remediation
except Exception:
	try:
		import piaplib.pku.remediation as remediation
	except Exception:
		raise ImportError("Error Importing remediation")

try:
	from piaplib.book.logs import logs as logs
except Exception:
	try:
		from piaplib.book.logs import logs as logs
	except Exception:
		raise ImportError("Error Importing logs")


__prog__ = """piaplib.lint.check"""
"""The name of this PiAPLib tool is check"""


CHECK_UNITS = {
	u'clients': clients_check_status,
	u'iface': iface_check_status,
	u'users': users_check_status
}
"""	The Pocket Lint Check actions.
	clients - client monitoring checks
	iface - interface health checks.
	user - users health checks.
	fw -  (FUTURE/RESERVED)
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
		'check_unit',
		choices=CHECK_UNITS.keys(),
		help='the pocket service check option.'
	)
	parser.add_argument('-V', '--version', action='version', version=str(
		"%(prog)s {}"
	).format(str(piaplib.__version__)))
	return parser.parse_known_args(arguments)


@remediation.error_handling
def useCheckTool(tool, arguments=[None]):
	"""Handler for launching pocket-tools."""
	if tool is None:
		return None
	if tool in CHECK_UNITS.keys():
		try:
			# print(str("check launching: "+tool))
			theResult = CHECK_UNITS[tool].main(arguments)
		except Exception:
			logs.log(
				str(
					"An error occured while handling the health check tool. Cascading failure."
				),
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
			args, extra = parseArgs(argv)
			lint_cmd = args.check_unit
			useCheckTool(lint_cmd, extra)
		except Exception as cerr:
			print(str(cerr))
			print(str(cerr.args))
			print(str(" UNKNOWN - An error occured while handling the arguments. Command failure."))
			exit(3)
	except Exception:
		print(str(" UNKNOWN - An error occured while handling the failure. Cascading failure."))
		exit(3)
	exit(0)


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

