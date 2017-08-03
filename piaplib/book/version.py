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
	import argparse
	if argparse.__name__ is None:
		raise NotImplementedError("OMG! We could not import argparse.")
except Exception as err:
	raise ImportError(err)
	exit(3)


try:
	try:
		import piaplib as piaplib
	except Exception:
		from . import piaplib as piaplib
	try:
		from pku import utils as utils
	except Exception:
		import piaplib.pku.utils as utils
	try:
		from pku import remediation as remediation
	except Exception:
		import piaplib.pku.remediation as remediation
	try:
		from .logs import logs as logs
	except Exception as impErr:
		impErr = None
		del(impErr)
		try:
			import logs.logs as logs
		except Exception:
			raise ImportError("Error Importing logs")
	if utils.__name__ is None:
		raise ImportError("Failed to open PKU Utils")
	if remediation.__name__ is None:
		raise ImportError("Failed to open PKU Remediation")
	if logs.__name__ is None:
		raise ImportError("Failed to open Pocket LogBook")
except Exception as importErr:
	print(str(importErr))
	print(str(importErr.args))
	importErr = None
	del importErr
	raise ImportError("Failed to import " + str(__file__))
	exit(255)


__prog__ = """piaplib.version"""
"""The name of this PiAPLib tool is pocket version"""


@remediation.error_handling
def getKeyringVersion(verbose=False):
	"""returns the keyring version."""
	try:
		from keyring import clearify as clearify
	except Exception:
		import piaplib.keyring.clearify as clearify
	try:
		from keyring import keyring as keyring
	except Exception:
		import piaplib.keyring.keyring as keyring
	keyring_version = str(
		"{name} {version}"
	).format(
		name=str(keyring.__prog__),
		version=str(piaplib.__version__)
	)
	if verbose:
		if clearify.hasBackendCommand():
			keyring_version = str(
				"Pocket Keyring: {version}\nBackend Cryptographic Library: {backend}\n" +
				"Cryptographic Algorithm: {algo}"
			).format(
				version=str(keyring_version),
				backend=str(clearify.getBackendCommand()),
				algo=str(clearify.getAlgoForOS())
			)
	return keyring_version


@remediation.error_handling
def getPythonVersion(verbose=False):
	"""returns which version of python is this"""
	import sys
	python_version = str(
		"Python {major}.{minor}"
	).format(
		major=str(sys.version_info[0]),
		minor=str(sys.version_info[1])
	)
	if verbose:
		python_version = str(
			"Python: {version}\n{flags}\n{copyright}\nBackend Python Library: {backend}"
		).format(
			version=str(sys.version),
			flags=str(sys.flags),
			copyright=str(sys.copyright),
			backend=str(sys.executable)
		)
	return python_version


@remediation.error_handling
def getOSVersion(*args, **kwargs):
	"""returns which version of the platform this is"""
	import sys
	return str("Platform: {}").format(str(sys.platform))


@remediation.error_handling
def getVersion(verbose=False):
	piaplib_version = str("piaplib: {}").format(str(piaplib.__version__))
	if verbose:
		piaplib_version = str(
			"{version}\n{python}\n{os}"
		).format(
			version=str(piaplib_version),
			python=str(getPythonVersion(verbose)),
			os=str(getOSVersion(verbose))
		)
	return piaplib_version


VERSION_UNITS = {
	u'all': getVersion,
	u'keyring': getKeyringVersion,
	u'python': getPythonVersion,
	u'os': getOSVersion
}
"""	The Pocket Book Unit actions.
	None - the piaplib version.
	keyring - the keyring version.
	python - which version of python is this.
	os - which platform is this.
	"""


@remediation.error_handling
def getRunVersion(tool, verbose_mode=False):
	"""Handler for checking versions."""
	if tool is None:
		return getVersion(verbose_mode)
	theResult = None
	if tool in VERSION_UNITS.keys():
		try:
			theResult = VERSION_UNITS[tool](verbose_mode)
		except Exception:
			theResult = str("{} {}").format(str(__prog__), str(piaplib.__version__))
	return theResult


@remediation.error_handling
def parseArgs(arguments=None):
	"""Parses the CLI arguments."""
	parser = argparse.ArgumentParser(
		prog=__prog__,
		description='Handles PiAP pocket version reports',
		epilog="PiAP Book Controller for version tools."
	)
	parser.add_argument(
		nargs='?',
		dest='version_unit',
		choices=VERSION_UNITS.keys(),
		default=u'all',
		help='The pocket version option.'
	)
	parser.add_argument(
		'-v',
		'--verbose',
		dest='verbose_mode',
		default=False,
		action='store_true',
		help='verbose reporting mode.'
	)
	parser.add_argument('-V', '--version', action='version', version=str(
		"%(prog)s {}"
	).format(str(piaplib.__version__)))
	return parser.parse_known_args(arguments)


@remediation.bug_handling
def main(argv=None):
	"""The Main Event makes no sense to logs yet."""
	try:
		args, extra = parseArgs(argv)
		del extra
		output = str(getRunVersion(args.version_unit, args.verbose_mode))
		if __name__ in u'__main__':
			print(output)
			return 0
		else:
			return output
	except Exception as err:
		logs.log(str(type(err)), "Critical")
		logs.log(str(err), "Critical")
		logs.log(str(err.args), "Critical")
	return 3


if __name__ in u'__main__':
	try:
		import sys
		exitcode = main(sys.argv[1:])
	except Exception:
		exitcode = 3
	exit(exitcode)


