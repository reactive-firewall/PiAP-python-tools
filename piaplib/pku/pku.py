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
	from . import interfaces as interfaces
except Exception:
	try:
		import interfaces as interfaces
	except Exception:
		raise ImportError("Error Importing interfaces")

try:
	from . import upgrade as upgrade
except Exception as err:
	try:
		import upgrade as upgrade
	except Exception:
		raise ImportError("Error Importing upgrade tools")

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


def usePKUTool(tool, arguments=[None]):
	"""Handler for launching pocket-tools."""
	if tool is None:
		return None
	if tool in PKU_UNITS.keys():
		try:
			try:
				# print(str("pku launching: "+tool))
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


def main(argv=None):
	"""The main event"""
	# print("PiAP PKU")
	try:
		try:
			args, extra = parseArgs(argv)
			pku_cmd = args.pku_unit
			usePKUTool(pku_cmd, extra)
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
	if utils.__name__ is None:
		raise ImportError("Error Importing utils")
	if config.__name__ is None:
		raise ImportError("Error Importing config")
	if interfaces.__name__ is None:
		raise ImportError("Error Importing interfaces")
	if upgrade.__name__ is None:
		raise ImportError("Error Importing upgrade")
	try:
		import sys
		if (sys.argv is not None and (sys.argv is not []) and (len(sys.argv) > 1)):
			main(sys.argv[1:])
		else:
			main(["--help"])
			exit(3)
	except Exception:
		raise ImportError("Error running main")
	exit(0)

