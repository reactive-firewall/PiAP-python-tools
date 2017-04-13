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
	return parser.parse_known_args(arguments)


def getTimeStamp():
	"""Returns the time stamp."""
	theDate = None
	try:
		import time
		theDate = time.strftime("%a %b %d %H:%M:%S %Z %Y", time.localtime())
	except Exception:
		theDate = str("")
	return str(theDate)


def useCheckTool(tool, arguments=[None]):
	"""Handler for launching pocket-tools."""
	if tool is None:
		return None
	if tool in CHECK_UNITS.keys():
		try:
			try:
				# print(str("check launching: "+tool))
				theResult = CHECK_UNITS[tool].main(arguments)
			except Exception:
				timestamp = getTimeStamp()
				theResult = str(
					timestamp +
					" - WARNING - An error occured while handling the keyring tool. " +
					"Cascading failure."
				)
		except Exception:
			theResult = str("CRITICAL - An error occured while handling the cascading failure.")
		return theResult
	else:
		return None


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
	import sys
	main(sys.argv[1:])


