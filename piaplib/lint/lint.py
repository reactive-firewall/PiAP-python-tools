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
"""The name of this PiAPLib tool is keyring"""


LINT_UNITS = {u'html': html_generator, u'check': check, u'execve': do_execve}
"""	The Pocket Knife Unit actions.
	check - monitoring checks
	execve - sandbox functions.
	html -  (FUTURE/RESERVED)
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
		'lint_unit',
		choices=LINT_UNITS.keys(),
		help='the pocket lint service option.'
	)
	parser.add_argument('-V', '--version', action='version', version=str(
		"%(prog)s {}"
	).format(str(piaplib.__version__)))
	return parser.parse_known_args(arguments)


@remediation.error_handling
def useLintTool(tool, arguments=[None]):
	"""Handler for launching pocket-tools."""
	if tool is None:
		return None
	if tool in LINT_UNITS.keys():
		theResult = LINT_UNITS[tool].main(arguments)
		return theResult
	else:
		return None


@remediation.bug_handling
def main(argv=None):
	"""The main event"""
	args, extra = parseArgs(argv)
	lint_cmd = args.lint_unit
	useLintTool(lint_cmd, extra)
	return 0


if __name__ in u'__main__':
	try:
		import sys
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

