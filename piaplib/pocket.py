#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Pocket PiAP
# ......................................................................
# Copyright (c) 2017-2018, Kendrick Walls
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
	exit(3)


try:
	import os
	if os.__name__ is None:
		raise ImportError("OMG! we could not import os. We're like in the matrix! ABORT. ABORT.")
except Exception as err:
	raise ImportError(err)
	exit(3)


try:
	import argparse
	if argparse.__name__ is None:
		raise ImportError("OMG! we could not import argparse. We're in need of a fix! ABORT.")
except Exception as err:
	raise ImportError(err)
	exit(3)


try:
	if str("piaplib") in __file__:
		__sys_path__ = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
		if __sys_path__ not in sys.path:
			sys.path.insert(0, __sys_path__)
except Exception as importErr:
	print(str(importErr))
	print(str(importErr.args))
	importErr = None
	del importErr
	raise ImportError("Failed to import " + str(__file__))
	exit(255)


try:
	import piaplib as piaplib
except Exception:
	from . import piaplib as piaplib

try:
	from . import book as book
except Exception:
	import book as book

try:
	from book.logs import logs as logs
except Exception:
	try:
		from piaplib.book.logs import logs as logs
	except Exception as err:
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		print("")
		raise ImportError("Error Importing logs")

try:
	from . import pku as pku
except Exception:
	import pku as pku

try:
	from . import keyring as keyring
except Exception:
	import keyring as keyring

try:
	from . import lint as lint
except Exception:
	import lint as lint

__prog__ = "pocket"
"""The name of this program is pocket"""

POCKET_UNITS = {
	u'book': book,
	u'pku': pku,
	u'protector': None,
	u'blade': None,
	u'keyring': keyring,
	u'lint': lint.lint,
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

LINT_OPTIONS = [u'check', u'nrpe', u'help']
""" The Pocket Lint Unit actions.
	check - pocket health checks.
	nrpe - nagios/sensu/etc. compatible checks (FUTURE/RESERVED)
	help -  (FUTURE/RESERVED)
	"""

# etc... (FUTURE/RESERVED)


def parseArgs(arguments=None):
	"""Parses the CLI arguments."""
	parser = argparse.ArgumentParser(
		prog=__prog__,
		description="Handles PiAP python tools",
		epilog="PiAP Controller for PiAP tools."
	)
	parser.add_argument(
		'pocket_unit',
		choices=POCKET_UNITS.keys(),
		help='the pocket service option.'
	)
	parser.add_argument('-V', '--version', action='version', version=str(
		"%(prog)s {}"
	).format(str(piaplib.__version__)))
	return parser.parse_known_args(arguments)


def useTool(tool, arguments=[None]):
	"""Handler for launching pocket-tools."""
	if tool is None:
		return None
	if tool in POCKET_UNITS.keys():
		try:
			try:
				# print(str("PiAP launching: "+tool))
				POCKET_UNITS[tool].main(arguments)
			except Exception as error:
				logs.log(str(type(error)), "Warning")
				logs.log(str(error), "Error")
				logs.log(str((error.args)), "Warning")
				logs.log(str(
					" - WARNING - An error occurred while handling the shell. Cascading failure."
				), "Warning")
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
			args, extra = parseArgs(argv)
			service_cmd = args.pocket_unit
			useTool(service_cmd, extra)
		except Exception as cerr:
			logs.log(str(cerr), "Warning")
			logs.log(str(cerr.args), "Warning")
			logs.log(str(
				" - UNKNOWN - An error occurred while handling the arguments. Cascading failure."
			), "Warning")
			exit(3)
	except Exception:
		logs.log(
			str(" UNKNOWN - An error occurred while handling the failure. Cascading failure."),
			"warning"
		)
		exit(3)
	exit(0)


if __name__ == '__main__':
	main(sys.argv[1:])

