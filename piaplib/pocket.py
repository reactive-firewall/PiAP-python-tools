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
	raise ImportError("argparse Failed to import")


try:
	if str("piaplib.") in __file__:
		__sys_path__ = os.path.abspath(os.path.join(os.path.dirname(__file__), '.'))
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
		raise ImportError("Pocket PKU failed to import.")  # import piaplib as piaplib
	else:
		piaplib = sys.modules["""piaplib"""]
except Exception:
	raise ImportError("Pocket failed to import.")


try:
	if 'piaplib.book' not in sys.modules:
		from . import book as book
	else:
		book = sys.modules["""piaplib.book"""]
except Exception as importErr:
	del importErr
	import book as book
	if book.__name__ is None:
		raise ImportError(str(u'Failed to open Pocket Book'))


try:
	if 'piaplib.book.logs.logs' not in sys.modules:
		from book.logs import logs as logs
	else:
		logs = sys.modules[str("piaplib.book.logs.logs")]
except Exception:
	try:
		if str("""piaplib.book.logs.logs""") not in sys.modules:
			from piaplib.book.logs import logs as logs
		else:
			logs = sys.modules[str("""piaplib.book.logs.logs""")]
	except Exception as err:
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		print("")
		raise ImportError("Error Importing logs")


try:
	if 'piaplib.pku' not in sys.modules:
		from . import pku as pku
except Exception as importErr:
	del importErr
	import pku as pku
	if pku.__name__ is None:
		raise ImportError(str(u'Failed to open Pocket Knife Unit'))


try:
	if 'piaplib.keyring' not in sys.modules:
		from . import keyring as keyring
except Exception as importErr:
	del importErr
	import keyring as keyring
	if keyring.__name__ is None:
		raise ImportError(str(u'Failed to find Pocket Keyring'))


try:
	if 'piaplib.lint' not in sys.modules:
		from . import lint as lint
except Exception as importErr:
	del importErr
	import lint as lint
	if lint.__name__ is None:
		raise ImportError(str(u'Failed to gather Pocket Lint'))


__prog__ = """pocket"""
"""The name of this program is pocket"""


__description__ = """Handles PiAP python tools"""
""" ... Handles PiAP python tools"""


__epilog__ = """PiAP Controller for PiAP tools."""
""" ... PiAP Controller for PiAP tools."""


POCKET_UNITS = {
	u'book': piaplib.book,
	u'pku': piaplib.pku,
	u'protector': None,
	u'blade': None,
	u'keyring': piaplib.keyring,
	u'lint': piaplib.lint,
	u'fruitsnack': None
}
""" The Pocket Knife Units available.
	pku - the pocket knife unit. The everything pocket tool.
	protector - the pocket protector. The defensive security tool. (FUTURE/RESERVED)
	blade - the pocket blade. The offensive security tool. (FUTURE/RESERVED)
	keyring - the pocket keyring. The crypto tool.
	lint - the extra pocket stuff tool. Small things always in the pocket.
	fruitsnack - the little Pi in the pocket. Wrapper for all things RaspberryPi.
	book - the little pocket-book for storage and the like.
	"""


PROTECTOR_OPTIONS = [u'fw', u'ids', u'acl']
""" The Pocket Knife Unit actions.
	fw - pocket firewall control.
	ids -  (FUTURE/RESERVED)
	acl -  (FUTURE/RESERVED)
	"""


# etc... (FUTURE/RESERVED)


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
			str(__prog__), help='the pocket pku service option.'
		)
	parser.add_argument('-V', '--version', action='version', version=str(
		"%(prog)s {}"
	).format(str(piaplib.__version__)))
	subparser = parser.add_subparsers(
		title="Tools", dest='pocket_unit',
		help='The pocket service options.', metavar="POCKET_UNIT"
	)
	for sub_parser in sorted(POCKET_UNITS.keys()):
		if POCKET_UNITS[sub_parser] is not None:
			subparser = POCKET_UNITS[sub_parser].generateParser(subparser)
	if calling_parser_group is None:
		calling_parser_group = parser
	return calling_parser_group


def parseArgs(arguments=None):
	"""Parses the CLI arguments."""
	parser = generateParser(None)
	return parser.parse_known_args(arguments)


def useTool(tool, arguments=None):
	"""Handler for launching pocket-tools."""
	if tool is None:
		return None
	if arguments is None:
		arguments = [None]
	if tool in POCKET_UNITS.keys():
		try:
			try:
				POCKET_UNITS[tool].main(arguments)
			except Exception as error:
				logs.log(str(type(error)), "Warning")
				logs.log(str(error), "Error")
				logs.log(str((error.args)), "Warning")
				logs.log(str(
					" - WARNING - An error occurred while handling the shell. Cascading failure."
				), "Warning")
				error = None
				del error
		except Exception:
			logs.log(
				str("CRITICAL - An error occurred while handling the cascading failure."),
				"error"
			)
	else:
		return None


# could do something per count too
# count_options = {1 : first_handler,
# 	2 : second_handler,
# 	3 : last_handler,
# 	4 : error_handler
# }


def main(argv=None):
	"""The Main Event."""
	try:
		try:
			(args, extra) = parseArgs(argv)
			if (argv is not None and len(argv) > 1):
				service_cmd = args.pocket_unit
				useTool(service_cmd, argv[1:])
		except RuntimeError as rterr:
			logs.log(str(rterr), "Warning")
			logs.log(str(rterr.args), "Warning")
			logs.log(str(
				" - UNKNOWN - An error occurred while handling the arguments. Main failure."
			), "Warning")
			exit(3)
	except Exception as err:
		logs.log(str(err), "Warning")
		logs.log(str(err.args), "Warning")
		logs.log(
			str(" UNKNOWN - An error occurred while handling the failure. Cascading failure."),
			"warning"
		)
		exit(3)
	exit(0)


if __name__ == '__main__':
	if (sys.argv is not None and len(sys.argv) > 1):
		main(sys.argv[1:])
	else:
		main([str("""--help""")])
