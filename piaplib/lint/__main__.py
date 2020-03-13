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
	if str("lint") in __file__:
		__sys_path__ = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
		if __sys_path__ not in sys.path:
			sys.path.insert(0, __sys_path__)
except Exception:
	raise ImportError("Pocket Knife Unit Lint failed to accumulate.")


try:
	if str("piaplib") not in sys.modules:
		raise ImportError("Pocket Lint failed to import.")  # import piaplib as piaplib
	piaplib = sys.modules["""piaplib"""]
except Exception:
	raise ImportError("Pocket Lint failed to import.")


try:
	if str("piaplib.pku.utils") not in sys.modules:
		from piaplib.pku import utils as utils
	else:
		utils = sys.modules[str("piaplib.pku.utils")]
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
		raise ImportError(err, "Error Importing piaplib.pku.remediation")


try:
	if str("piaplib.pku.interfaces") not in sys.modules:
		from piaplib.pku import interfaces as interfaces
	else:
		interfaces = sys.modules[str("piaplib.pku.interfaces")]
except Exception:
	try:
		import piaplib.pku.interfaces as interfaces
	except Exception as err:
		raise ImportError(err, "Error Importing piaplib.pku.interfaces")


try:
	if str("piaplib.lint.html_generator") not in sys.modules:
		from piaplib.lint import html_generator as html_generator
	else:
		html_generator = sys.modules[str("piaplib.lint.html_generator")]
except Exception:
	try:
		import piaplib.lint.html_generator as html_generator
	except Exception as err:
		raise ImportError(err, "Error Importing piaplib.lint.html_generator")


try:
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
	if str("piaplib.book.logs.logs") not in sys.modules:
		from piaplib.book.logs import logs as logs
	else:
		logs = sys.modules[str("piaplib.book.logs.logs")]
except Exception:
	try:
		import piaplib.book.logs.logs as logs
	except Exception as err:
		raise ImportError(err, "Error Importing piaplib.book.logs.logs")


try:
	if str("piaplib.lint.check") not in sys.modules:
		from piaplib.lint import check as check
	else:
		check = sys.modules[str("piaplib.lint.check")]
except Exception:
	try:
		import piaplib.lint.check as check
	except Exception as err:
		raise ImportError(err, "Error Importing piaplib.lint.check")


try:
	if str("piaplib.lint.do_execve") not in sys.modules:
		from piaplib.lint import do_execve as do_execve
	else:
		do_execve = sys.modules[str("piaplib.lint.do_execve")]
except Exception:
	try:
		import piaplib.lint.do_execve as do_execve
	except Exception as err:
		raise ImportError(err, "Error Importing piaplib.lint.do_execve")


__prog__ = """piaplib.lint"""
"""The name of this PiAPLib tool is lint"""


__description__ = """Pocket Lint. PiAP Pocket Controller for extra tools."""
"""The description is 'PiAP Pocket Controller for extra tools.'"""


__epilog__ = """Handles PiAP pocket lint"""
"""... Handles PiAP pocket lint"""


LINT_UNITS = {u'check': check, u'execve': do_execve, u'html': None, }
"""	The Pocket Knife Unit actions.
	check - monitoring checks
	do_execve - sandbox functions.
	html -  (FUTURE/RESERVED)
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
		title="Units", dest='lint_unit',
		help='the pocket lint service option.', metavar="LINT_UNIT"
	)
	for sub_parser in sorted(LINT_UNITS.keys()):
		if LINT_UNITS[sub_parser] is not None:
			subparser = LINT_UNITS[sub_parser].generateParser(subparser)
	if calling_parser_group is None:
		calling_parser_group = parser
	return calling_parser_group


@remediation.error_handling
def parseArgs(arguments=None):
	"""Parses the CLI arguments."""
	parser = generateParser(None)
	return parser.parse_known_args(arguments)


def useLintTool(tool, arguments=[None]):
	"""Handler for launching pocket-tools."""
	theExitCode = 1
	if tool is None:
		theExitCode = 0
	elif tool in LINT_UNITS.keys():
		try:
			logs.log(str("lint launching: {}").format(str(tool)), "DEBUG")
			theExitCode = 0
			LINT_UNITS[tool].main(arguments)
		except Exception:
			logs.log(str("An error occurred while handling the lint tool. "), "WARNING")
			logs.log(str("lint failure."), "Error")
			theExitCode = 3
	return theExitCode


@remediation.bug_handling
def main(argv=None):
	"""The main event"""
	(args, extra) = parseArgs(argv)
	lint_cmd = args.lint_unit
	useLintTool(lint_cmd, argv[1:])
	return 0


if __name__ in u'__main__':
	try:
		error_code = main(sys.argv[1:])
		exit(error_code)
	except Exception as err:
		print(str(u'MAIN FAILED DURING LINT. ABORT.'))
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		del err
		exit(255)
	finally:
		exit(0)

