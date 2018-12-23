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

# try:
# 	from . import config as config
# except Exception:
# 	import config as config


__prog__ = """piaplib.book.logs"""
"""The name of this PiAPLib tool is pocket logs"""


try:
	import sys
	import os
	import os.path
	import argparse
	if str("book") in __file__:
		__sys_path__ = os.path.abspath(os.path.join(os.path.dirname(__file__), '.'))
		if __sys_path__ not in sys.path:
			sys.path.insert(0, __sys_path__)
except Exception:
	raise ImportError("Pocket Book failed to import.")


try:
	import logging as logging
	if logging.__name__ is None:
		raise NotImplementedError("[CWE-758] We could not import the builtin logs!")
except Exception as err:
	raise ImportError(err)


try:
	if str("piaplib.book.ANSIColors") not in sys.modules:
		from piaplib.book import ANSIColors as ANSIColors
	else:
		ANSIColors = sys.modules[str("piaplib.book.ANSIColors")]
except Exception:
	try:
		import piaplib.book.ANSIColors as ANSIColors
	except Exception as err:
		raise ImportError(err)


LOG_UNITS = {
	u'all': None,
	u'debug': None,
	u'backup': None,
	u'restore': None
}
"""	The Pocket Book Unit actions.
	None - the piaplib version.
	keyring - the keyring version.
	python - which version of python is this.
	os - which platform is this.
	"""


def generateParser(calling_parser_group):
	"""Parses the CLI arguments."""
	if calling_parser_group is None:
		parser = argparse.ArgumentParser(
			prog=__prog__,
			description='Handles PiAP pocket logging',
			epilog="PiAP Book Controller for logging tools."
		)
	else:
		parser = calling_parser_group.add_parser(
			str(__prog__).split(".")[-1], help="PiAP Book Controller for logging tools."
		)
	parser.add_argument(
		nargs='?',
		dest='log_unit',
		choices=LOG_UNITS.keys(),
		default=u'all',
		help='The pocket log option.'
	)
	if calling_parser_group is None:
		calling_parser_group = parser
	return calling_parser_group


class logs(object):
	"""Class for Pocket PKU logs"""

	logging_level = {
		'debug': logging.DEBUG, 'info': logging.INFO, 'warn': logging.WARNING,
		'warning': logging.WARNING, 'error': logging.ERROR, 'crit': logging.CRITICAL,
		'critical': logging.CRITICAL
	}
	"""Mappings to different log levels."""

	try:
		try:
			import baseconfig as baseconfig
		except Exception:
			try:
				import piaplib.pku.baseconfig as baseconfig
			except Exception as err:
				raise ImportError(err)
				exit(3)
		if baseconfig.loadMainConfigFile()['PiAP-logging-outputs']['file']:
			prefix_path = baseconfig.loadMainConfigFile()['PiAP-logging']['dir']
			log_lvl = logging_level[str(baseconfig.loadMainConfigFile()['PiAP-logging']['level'])]
			file_path = os.path.join(str(prefix_path), str("piaplib.log"))
		else:
			log_lvl = logging.INFO
			file_path = sys.stdout
		log_settings = dict({
			"""level""": log_lvl,
			"""format""": str("%(asctime)s [piaplib] %(message)s"),
			"""datefmt""": str("%a %b %d %H:%M:%S %Z %Y")
		})
		try:
			if os.access(file_path, os.F_OK ^ os.R_OK):
				log_settings["""filename"""] = file_path
		except Exception:
			log_settings["""filename"""] = None
			log_settings["""stream"""] = sys.stdout
		logging.basicConfig(**log_settings)
	except Exception as err:
		print(str("Error:"))
		print(str(err))
		print(str(type(err)))
		logging.basicConfig(
			level=logging.DEBUG,
			format=str("%(asctime)s [piaplib] %(message)s"),
			datefmt=str("%a %b %d %H:%M:%S %Z %Y")
		)

	logging_color = {
		'debug': ANSIColors.BLUE, 'info': ANSIColors.GREEN,
		'warn': ANSIColors.AMBER, 'warning': ANSIColors.AMBER,
		'error': ANSIColors.FAIL, 'crit': str(str(ANSIColors.BLACK) + str(ANSIColors.REDBG)),
		'critical': str(str(ANSIColors.BLACK) + str(ANSIColors.REDBG))
	}
	"""Mappings from different log levels to colors."""

	def __call__(self, *args, **kwargs):
		return logs.log(*args, **kwargs)

	@staticmethod
	def log(msg=str("Checked in"), loglevel="info"):
		"""Logs a message."""
		logger = logging.getLogger(__name__)
		context_details = logger.findCaller()
		myName = str("piaplib")
		if context_details is not None:
			myName = context_details[2]
		if not isinstance(msg, str):
			raise ValueError(str("Invalid log message"))
		if not isinstance(loglevel, str):
			raise ValueError(str("Invalid log level"))
		if (loglevel.lower() not in logs.logging_level.keys()):
			raise ValueError(str("Invalid log level"))
		if (sys.stdout.isatty()):
			colorPrefix = logs.logging_color[loglevel.lower()]
			endColor = ANSIColors.ENDC
		else:
			colorPrefix = str("")
			endColor = colorPrefix
		logger.log(
			logs.logging_level[loglevel.lower()],
			str("{name} -- {prefix}{message}{suffix}").format(
				name=str(myName),
				prefix=colorPrefix,
				message=msg, suffix=endColor
			)
		)

	__all__ = [logging_level, logging_color]


def main(argv=None):
	"""The Main Event makes no sense to logs yet."""
	try:
		raise NotImplementedError("[CWE-758] - Pocket Book logs main() not implemented.")
	except Exception as err:
		logs.log(str(type(err)), "Critical")
		logs.log(str(err), "Critical")
		logs.log(str(err.args), "Critical")
	return 3


if __name__ in u'__main__':
	try:
		exitcode = main(sys.argv[1:])
	except Exception:
		exitcode = 3
	exit(exitcode)


