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
except Exception:
	raise NotImplementedError("OMG! We could not import the os. We're like in the matrix!")
	exit(3)

try:
	from . import saltify as saltify
except Exception:
	import saltify as saltify

try:
	from . import rand as rand
except Exception:
	import rand as rand

try:
	from ..pku import remediation as remediation
except Exception:
	import pku.remediation as remediation


__prog__ = """piaplib.keyring"""
"""The name of this PiAPLib tool is keyring"""


KEYRING_UNITS = {u'saltify': saltify, u'rand': rand, u'keys': None}
""" The Pocket Knife Unit actions.
	saltify - HMAC salt functions.
	keys -  (FUTURE/RESERVED)
	"""


@remediation.error_handling
def parseArgs(arguments=None):
	"""Parses the CLI arguments."""
	parser = argparse.ArgumentParser(
		prog=__prog__,
		description='Handles PiAP keyring tools',
		epilog="PiAP Controller for cryptographic tools."
	)
	parser.add_argument(
		'keyring_unit',
		choices=KEYRING_UNITS.keys(),
		help='the pocket keyring service option.'
	)
	return parser.parse_known_args(arguments)


@remediation.error_handling
def useKeyTool(tool, arguments=[None]):
	"""Handler for launching pocket-tools."""
	if tool is None:
		return None
	if tool in KEYRING_UNITS.keys():
		theResult = None
		try:
			try:
				# print(str("keyring launching: "+tool))
				theResult = KEYRING_UNITS[tool].main(arguments)
			except Exception:
				timestamp = remediation.getTimeStamp()
				theResult = str(
					timestamp +
					" - WARNING - An error occurred while handling the keyring tool." +
					"Cascading failure."
				)
		except Exception:
			theResult = str("CRITICAL - An error occurred while handling the cascading failure.")
		return theResult
	else:
		return None


@remediation.error_handling
def main(argv=None):
	"""The main event"""
	# print("PiAP Keyring")
	try:
		args, extra = parseArgs(argv)
		keyring_cmd = args.keyring_unit
		useKeyTool(keyring_cmd, extra)
	except Exception as cerr:
		print(str(cerr))
		print(str(cerr.args))
		print(str(" UNKNOWN - An error occurred while handling the arguments. Command failure."))
		exit(3)
	exit(0)


if __name__ in u'__main__':
	main(sys.argv[1:])


