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
	from . import html_generator as html_generator
except Exception:
	import html_generator as html_generator

try:
	from . import check as check
except Exception:
	import check as check

try:
	from . import do_execve as do_execve
except Exception:
	import do_execve as do_execve


__prog__ = """piaplib.keyring"""
"""The name of this PiAPLib tool is keyring"""


LINT_UNITS = {u'html': html_generator, u'check': check, u'execve': do_execve}
"""	The Pocket Knife Unit actions.
	check - monitoring checks
	execve - sandbox functions.
	html -  (FUTURE/RESERVED)
	"""


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


def useLintTool(tool, arguments=[None]):
	"""Handler for launching pocket-tools."""
	if tool is None:
		return None
	if tool in LINT_UNITS.keys():
		try:
			try:
				# print(str("keyring launching: "+tool))
				LINT_UNITS[tool].main(arguments)
			except Exception:
				timestamp = getTimeStamp()
				theResult = str(
					timestamp +
					" - WARNING - An error occured while handling the lint tool. " +
					"Cascading failure."
				)
		except Exception:
			theResult = str("CRITICAL - An error occured while handling the cascading failure.")
		return theResult
	else:
		return None


def main(argv=None):
	"""The main event"""
	# print("PiAP Keyring")
	try:
		try:
			args, extra = parseArgs(argv)
			lint_cmd = args.lint_unit
			useLintTool(lint_cmd, extra)
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


