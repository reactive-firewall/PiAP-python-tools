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

# try:
# 	from . import config as config
# except Exception:
# 	import config as config


try:
	import os
	if os.__name__ is None:
		raise NotImplementedError("OMG! We could not import the os. We're like in the matrix!")
except Exception as err:
	raise ImportError(err)
	exit(3)

try:
	import sys
	if sys.__name__ is None:
		raise NotImplementedError("OMG! We could not import the sys. We're like in the matrix!")
except Exception as err:
	raise ImportError(err)
	exit(3)

try:
	from . import remediation as remediation
except Exception:
	try:
		import remediation as remediation
	except Exception:
		raise ImportError("Error Importing remediation")


class ANSIColors:
	"""ANSI colored text"""
	ENDC = """\033[0m"""
	BOLD = """\033[1m"""
	ITALIC   = """\033[3m"""
	URL      = """\033[4m"""
	BLINK    = """\033[5m"""
	BLINK2   = """\033[6m"""
	SELECTED = """\033[7m"""

	BLACK  = """\033[30m"""
	RED    = """\033[31m"""
	GREEN  = """\033[32m"""
	YELLOW = """\033[33m"""
	BLUE   = """\033[34m"""
	VIOLET = """\033[35m"""
	BEIGE  = """\033[36m"""
	WHITE  = """\033[37m"""

	BLACKBG  = """\033[40m"""
	REDBG    = """\033[41m"""
	GREENBG  = """\033[42m"""
	YELLOWBG = """\033[43m"""
	BLUEBG   = """\033[44m"""
	VIOLETBG = """\033[45m"""
	BEIGEBG  = """\033[46m"""
	WHITEBG  = """\033[47m"""

	GREY    = """\033[90m"""
	RED2    = """\033[91m"""
	GREEN2  = """\033[92m"""
	YELLOW2 = """\033[93m"""
	AMBER   = """\033[93m"""
	BLUE2   = """\033[94m"""
	VIOLET2 = """\033[95m"""
	BEIGE2  = """\033[96m"""
	WHITE2  = """\033[97m"""

	GREYBG    = """\033[100m"""
	REDBG2    = """\033[101m"""
	GREENBG2  = """\033[102m"""
	YELLOWBG2 = """\033[103m"""
	BLUEBG2   = """\033[104m"""
	VIOLETBG2 = """\033[105m"""
	BEIGEBG2  = """\033[106m"""
	WHITEBG2  = """\033[107m"""
	WARNING = AMBER
	OKBLUE = BLUE
	OKGREEN = GREEN
	HEADER = VIOLET
	FAIL = RED


class logs:
	"""Class for Pocket PKU logs"""
	import logging as logging
	logging.basicConfig(
		level=logging.DEBUG,
		format=str("%(asctime)s [%(name)s] %(message)s"),
		datefmt=str("%m/%d/%Y %I:%M:%S %p")
	)
	
	logging_level = {
		'debug': logging.DEBUG, 'info': logging.INFO, 'warn': logging.WARNING,
		'warning': logging.WARNING, 'error': logging.ERROR, 'crit': logging.CRITICAL,
		'critical': logging.CRITICAL
	}
	"""Mappings to different log levels."""

	logging_color = {
		'debug': ANSIColors.BLUE, 'info': ANSIColors.GREEN,
		'warn': ANSIColors.AMBER, 'warning': ANSIColors.AMBER,
		'error': ANSIColors.FAIL, 'crit': str(ANSIColors.FAIL + ANSIColors.BLINK),
		'critical': str(ANSIColors.FAIL + ANSIColors.BLINK)
	}
	"""Mappings from different log levels to colors."""

	def log(msg=str("Checked in"), loglevel="info"):
		"""Logs a message."""
		import logging as logging
		logger = logging.getLogger(__name__)
		if not isinstance(msg, str):
			raise ValueError(str("Invalid log message"))
		if not isinstance(loglevel, str):
			raise ValueError(str("Invalid log level"))
		if (loglevel.lower() not in logs.logging_level.keys()):
			raise ValueError(str("Invalid log level"))
		if not isinstance(logs.logging_level[loglevel.lower()], int):
			raise ValueError(str("Invalid log level"))
		logger.log(
			logs.logging_level[loglevel.lower()],
			str("{}{}{}").format(logs.logging_color[loglevel.lower()], msg, ANSIColors.ENDC)
		)
	
	__ALL__ = [logging_level, logging_color]

@remediation.error_handling
def main(argv=None):
	"""The Main Event makes no sense to utils."""
	raise NotImplementedError("CRITICAL - PKU logs main() not implemented. yet?")
	exit(3)


if __name__ in u'__main__':
	try:
		import sys
		main(sys.argv[1:])
	except Exception:
		exit(3)


