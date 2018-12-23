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
	import sys
	import os
	import argparse
	try:
		if str("keyring") in __file__:
			__sys_path__ = os.path.abspath(os.path.dirname(__file__))
			if __sys_path__ not in sys.path:
				sys.path.insert(0, __sys_path__)
	except Exception:
		raise ImportError("PiAPlib Keyring failed to import.")
except Exception as ImportErr:
	print(str(type(ImportErr)))
	print(str(ImportErr))
	print(str((ImportErr.args)))
	ImportErr = None
	del ImportErr
	raise ImportError(u'Keyring Failed to Import')


try:
	if str("piaplib.keyring.saltify") not in sys.modules:
		from piaplib.keyring import saltify as saltify
	else:
		saltify = sys.modules[str("piaplib.keyring.saltify")]
except Exception:
	try:
		import piaplib.keyring.saltify as saltify
	except Exception as err:
		raise ImportError(err, "Error Importing piaplib.keyring.saltify")


try:
	if str("piaplib.keyring.rand") not in sys.modules:
		from piaplib.keyring import rand as rand
	else:
		rand = sys.modules[str("piaplib.keyring.rand")]
except Exception:
	try:
		import piaplib.keyring.rand as rand
	except Exception as err:
		raise ImportError(err, "Error Importing piaplib.keyring.rand")


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
	if str("piaplib.keyring.clarify") not in sys.modules:
		from piaplib.keyring import clarify as clarify
	else:
		clarify = sys.modules[str("piaplib.keyring.clarify")]
except Exception:
	try:
		import piaplib.keyring.clarify as clarify
	except Exception as err:
		raise ImportError(err, "Error Importing piaplib.keyring.clarify")


__prog__ = """piaplib.keyring"""
"""The name of this PiAPLib tool is keyring"""


__description__ = """Handles PiAP keyring tools."""
"""The description is 'Handles PiAP keyring tools.'"""


__epilog__ = """PiAP Controller for cryptographic tools."""
"""...PiAP Controller for cryptographic tools."""


KEYRING_UNITS = {u'saltify': saltify, u'rand': rand, u'clarify': clarify, u'keys': None}
""" The Pocket Knife Unit actions.
	saltify - HMAC salt functions.
	rand - convenience random functions.
	clarify - convenience file encryption functions.
	keys -  (FUTURE/RESERVED)
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
			str(__prog__).split(".")[-1], help='the pocket keyring service option.'
		)
	subparser = parser.add_subparsers(
		title="Units", dest='keyring_unit',
		help='The pocket keyring options.', metavar="KEYRING_UNITS"
	)
	for sub_parser in KEYRING_UNITS.keys():
		if KEYRING_UNITS[sub_parser] is not None:
			subparser = KEYRING_UNITS[sub_parser].generateParser(subparser)
	if calling_parser_group is None:
		calling_parser_group = parser
	return calling_parser_group


@remediation.error_handling
def parseArgs(arguments=None):
	"""Parses the CLI arguments."""
	parser = generateParser(None)
	return parser.parse_known_args(arguments)


@remediation.error_handling
def useKeyTool(tool, arguments=[None]):
	"""Handler for launching pocket-tools."""
	theResult = None
	if tool is not None and tool in KEYRING_UNITS.keys():
		try:
			theResult = KEYRING_UNITS[tool].main(arguments)
		except Exception as err:
			remediation.error_breakpoint(err, u'piaplib.keyring.__MAIN__.useKeyTool')
			err = None
			del err
			theResult = None
	return theResult


@remediation.error_handling
def main(argv=None):
	"""The main event"""
	# print("PiAP Keyring")
	try:
		args, extra = parseArgs(argv)
		keyring_cmd = args.keyring_unit
		useKeyTool(keyring_cmd, extra)
	except Exception as cerr:
		remediation.error_breakpoint(cerr, str(u'piaplib.keyring.__MAIN__.main()'))
		exit(3)
	exit(0)


if __name__ in u'__main__':
	try:
		error_code = main(sys.argv[1:])
		exit(error_code)
	except Exception as err:
		remediation.error_breakpoint(err, str(u'piaplib.keyring.__MAIN__'))
		del err
		exit(255)
	finally:
		exit(0)


