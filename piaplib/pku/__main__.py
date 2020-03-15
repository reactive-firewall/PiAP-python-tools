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
	raise ImportError("argparse Failed to import.")


try:
	if str("pku") in __file__:
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
	if str("""piaplib""") not in sys.modules:
		raise ImportError("Pocket PKU failed to import.")  # import piaplib as piaplib
	piaplib = sys.modules["""piaplib"""]
except Exception:
	raise ImportError("Pocket PKU failed to import.")


try:
	if str("piaplib.pku.upgrade") not in sys.modules:
		from piaplib.pku import upgrade as upgrade
	else:
		upgrade = sys.modules[str("piaplib.pku.upgrade")]
except Exception:
	try:
		import piaplib.pku.upgrade as upgrade
	except Exception as err:
		raise ImportError(err, "Error Importing piaplib.pku.upgrade")


try:
	if str("piaplib.pku.config") not in sys.modules:
		from piaplib.pku import config as config
	else:
		config = sys.modules[str("piaplib.pku.config")]
except Exception:
	try:
		import piaplib.pku.config as config
	except Exception as err:
		raise ImportError(err, "Error Importing piaplib.pku.config")


try:
	if str("piaplib.pku.utils") not in sys.modules:
		from piaplib.pku import utils as utils
	else:
		utils = sys.modules[str("piaplib.pku.utils")]
	if utils.__name__ is None:
		raise ImportError("Error Importing piaplib.pku.utils")
except Exception:
	try:
		import piaplib.pku.utils as utils
	except Exception as err:
		raise ImportError(err, "Error Importing piaplib.pku.utils")


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
	if str("piaplib.pku.interfaces") not in sys.modules:
		from piaplib.pku import interfaces as interfaces
	else:
		interfaces = sys.modules[str("piaplib.pku.interfaces")]
except Exception:
	try:
		import piaplib.pku.interfaces as interfaces
	except Exception as err:
		raise ImportError(err, "Error Importing interfaces")


try:
	if str("piaplib.book.logs.logs") not in sys.modules:
		from piaplib.book.logs import logs as logs
	else:
		logs = sys.modules[str("piaplib.book.logs.logs")]
except Exception:
	try:
		import piaplib.book.logs.logs as logs
	except Exception as err:
		raise ImportError(err, "Error Importing piaplib.book.logs.logs")


__prog__ = """piaplib.pku"""
"""The name of this PiAPLib tool is Pocket Knife Unit"""


__description__ = """Pocket Knife Units. PiAP Pocket Controller for main tools."""
"""The description is 'Pocket Knife Unit PiAP Pocket Controller for main tools.'"""


__epilog__ = """Handles PiAP pockets tools"""
"""...Handles PiAP pockets tools"""


PKU_UNITS = {
	u'config': config,
	u'backup': None,
	u'upgrade': upgrade,
	u'help': None,
	u'interfaces': interfaces
}
""" The Pocket Knife Unit actions.
	config -  configuration stuff
	backup -  (FUTURE/RESERVED)
	upgrade -  (see reactive-firewall/PiAP-python-tools#1)
	help -  (FUTURE/RESERVED)
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
			str(__prog__).split(".")[-1], help='the pocket pku service option.'
		)
	parser.add_argument('-V', '--version', action='version', version=str(
		"%(prog)s {}"
	).format(str(piaplib.__version__)))
	subparser = parser.add_subparsers(
		title="Units", dest='pku_unit',
		help='The pocket pku options.', metavar="PKU_UNIT"
	)
	for sub_parser in sorted(PKU_UNITS.keys()):
		if PKU_UNITS[sub_parser] is not None:
			subparser = PKU_UNITS[sub_parser].generateParser(subparser)
	if calling_parser_group is None:
		calling_parser_group = parser
	return calling_parser_group


@remediation.error_handling
def parseArgs(arguments=None):
	"""Parses the CLI arguments."""
	parser = generateParser(None)
	return parser.parse_known_args(arguments)


def usePKUTool(tool, arguments=[None]):
	"""Handler for launching pocket-tools."""
	theExitCode = 1
	if tool is None:
		theExitCode = 0
	elif tool in PKU_UNITS.keys():
		try:
			logs.log(str("pku launching: {}").format(str(tool)), "DEBUG")
			theExitCode = 0
			PKU_UNITS[tool].main(arguments)
		except Exception:
			logs.log(str("An error occurred while handling the PKU tool. "), "WARNING")
			logs.log(str("PKU failure."), "Error")
			theExitCode = 3
	return theExitCode


@remediation.bug_handling
def main(argv=None):
	"""The main event"""
	(args, extra) = parseArgs(argv)
	pku_cmd = args.pku_unit
	return usePKUTool(pku_cmd, argv[1:])


if __name__ in u'__main__':
	exit_code = main(sys.argv[1:])
	exit(exit_code)

