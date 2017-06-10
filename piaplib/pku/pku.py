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

try:
	import piaplib as piaplib
except Exception:
	from . import piaplib as piaplib

try:
	from . import upgrade as upgrade
except Exception as err:
	try:
		import upgrade as upgrade
	except Exception:
		raise ImportError("Error Importing upgrade tools")

try:
	from . import config as config
except Exception:
	try:
		import config as config
	except Exception:
		raise ImportError("Error Importing config")

try:
	from . import utils as utils
except Exception:
	try:
		import utils as utils
	except Exception:
		raise ImportError("Error Importing utils")

try:
	from . import remediation as remediation
except Exception:
	try:
		import remediation as remediation
	except Exception:
		raise ImportError("Error Importing remediation")

try:
	from . import interfaces as interfaces
except Exception:
	try:
		import interfaces as interfaces
	except Exception:
		raise ImportError("Error Importing interfaces")

try:
	from piaplib.pku.logs import logs as logs
except Exception:
	try:
		from .logs import logs as logs
	except Exception:
		raise ImportError("Error Importing interfaces")

try:
	import argparse
except Exception:
	raise ImportError("Error Importing argparse tools")


__prog__ = """piaplib.pku"""
"""The name of this PiAPLib tool is Pocket Knife Unit"""


PKU_UNITS = {u'config': config, u'backup': None, u'upgrade': upgrade, u'help': None}
""" The Pocket Knife Unit actions.
	config -  (FUTURE/configuration stuff)
	backup -  (FUTURE/RESERVED)
	upgrade -  (see reactive-firewall/PiAP-python-tools#1)
	help -  (FUTURE/RESERVED)
	"""


@remediation.error_handling
def parseArgs(arguments=None):
	"""Parses the CLI arguments."""
	parser = argparse.ArgumentParser(
		prog=__prog__,
		description='Handles PiAP pockets',
		epilog="PiAP Pocket Controller for main tools."
	)
	parser.add_argument(
		'pku_unit',
		choices=PKU_UNITS.keys(),
		help='the pocket pku service option.'
	)
	parser.add_argument('-V', '--version', action='version', version=str(
		"%(prog)s {}"
	).format(str(piaplib.__version__)))
	return parser.parse_known_args(arguments)


def getTimeStamp():
	"""Returns the time stamp."""
	theDate = remediation.getTimeStamp()
	return theDate


def usePKUTool(tool, arguments=[None]):
	"""Handler for launching pocket-tools."""
	if tool is None:
		return None
	if tool in PKU_UNITS.keys():
		try:
			try:
				logs.log(str("pku launching: {}").format(str(tool)), "debug")
				PKU_UNITS[tool].main(arguments)
			except Exception:
				timestamp = getTimeStamp()
				theResult = str(
					timestamp +
					" - WARNING - An error occured while handling the PKU tool. " +
					"Cascading failure."
				)
		except Exception:
			theResult = str("CRITICAL - An error occured while handling the cascading failure.")
		return theResult
	else:
		return None


@remediation.bug_handling
def main(argv=None):
	"""The main event"""
	# print("PiAP PKU")
	try:
		try:
			args, extra = parseArgs(argv)
			pku_cmd = args.pku_unit
			usePKUTool(pku_cmd, extra)
		except Exception as cerr:
			logs.log(str(cerr), "Error")
			logs.log(str(cerr.args), "Error")
			logs.log(
				str(" UNKNOWN - An error occured while handling the arguments. Command failure."),
				"Error"
			)
			exit(3)
	except Exception:
		logs.log(
			str(" UNKNOWN - An error occured while handling the failure. Cascading failure."),
			"Error"
		)
		exit(3)
	exit(0)


if __name__ in u'__main__':
	if utils.__name__ is None:
		raise ImportError("Error Importing utils")
	if config.__name__ is None:
		raise ImportError("Error Importing config")
	if interfaces.__name__ is None:
		raise ImportError("Error Importing interfaces")
	if upgrade.__name__ is None:
		raise ImportError("Error Importing upgrade")
	if remediation.__name__ is None:
		raise ImportError("Error Importing remediation")
	if logs.__name__ is None:
		raise ImportError("Error Importing logs")
	try:
		import sys
		if (sys.argv is not None and (sys.argv is not []) and (len(sys.argv) > 1)):
			exit(main(sys.argv[1:]))
		else:
			exit(main(["--help"]))
	except Exception:
		raise ImportError("Error running main")
	exit(0)

