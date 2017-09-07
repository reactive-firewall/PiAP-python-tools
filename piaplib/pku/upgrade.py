#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Pocket PiAP
# ......................................................................
# Copyright (c) 2017, Kendrick Walls
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
	import piaplib as piaplib
except Exception:
	from . import piaplib as piaplib


try:
	from . import remediation as remediation
except Exception:
	try:
		import remediation as remediation
	except Exception:
		raise ImportError("Error Importing remediation")


try:
	import warnings
	with warnings.catch_warnings():
		warnings.filterwarnings("ignore", category=PendingDeprecationWarning)
		import imp
		if imp.__name__ is None:
			raise ImportError("Not Implemented.")
	import pip as pip
except Exception:
	try:
		class pip():
			"""on-the-fly monkey patch for calling pip main"""

			@remediation.bug_handling
			def main(args=None, stderr=None):
				"""function for backend subprocess check_output command"""
				import subprocess
				theOutput = None
				try:
					if args is None or args is [None]:
						theOutput = None
					else:
						if str("pip") not in args[0]:
							args.insert(0, "pip")
						theOutput = subprocess.check_output(args, stderr=stderr)
				except Exception:
					theOutput = None
				return theOutput

	except Exception:
		raise ImportError("Not Implemented.")

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
	import argparse
except Exception:
	raise ImportError("Error Importing argparse tools")


"""
Upgrades are basicly just done via pip right now.
"""


__prog__ = """piaplib.pku.upgrades"""
"""The name of this PiAPLib tool is Pocket Knife Upgrade Unit"""


@remediation.error_passing
def parseargs(arguments=None):
	"""Parse the arguments"""
	parser = argparse.ArgumentParser(
		prog=__prog__,
		description='Run piaplib upgrade functions.',
		epilog='Basicly a python wrapper for pip install --upgrade.'
	)
	the_action = parser.add_mutually_exclusive_group()
	the_action.add_argument(
		'-u',
		'--upgrade',
		dest='upgrade_core',
		default=True,
		action='store_false',
		help='Upgrade the piaplib. This is the default.'
	)
	the_action.add_argument(
		'-P',
		'--upgrade-pip',
		dest='upgrade_pip',
		default=False,
		action='store_true',
		help='Upgrade the pip module. This is needed for hashes in the future. EXPEREMENTAL.'
	)
	the_action.add_argument(
		'-A',
		'--upgrade-all',
		dest='upgrade_all',
		default=False,
		action='store_true',
		help='Upgrade the piaplib. This is the default.'
	)
	parser.add_argument(
		'-V',
		'--version',
		action='version',
		version=str(
			"%(prog)s {}"
		).format(str(piaplib.__version__))
	)
	theResult = parser.parse_known_args(arguments)
	return theResult


@remediation.error_passing
def upgradepip():
	"""Upgrade pip via pip."""
	try:
		pip.main(args=["install", "--upgrade", "pip"])
	except Exception as permErr:
		print(str(type(permErr)))
		print(str(permErr))
		print(str((permErr.args)))
		permErr = ""
		permErr = None
		del(permErr)
	return None


@remediation.error_passing
def upgradePiAPlib():
	"""Upgrade piaplib via pip."""
	upsream_repo = str("git+https://github.com/reactive-firewall/PiAP-python-tools.git")
	pip.main(args=["install", "--upgrade", upsream_repo])
	return None


@remediation.error_passing
def upgradePiAPlib_depends():
	"""Upgrade piaplib via pip."""
	upsream_repo_depends = str(
		"https://raw.githubusercontent.com/reactive-firewall" +
		"/PiAP-python-tools/master/requirements.txt"
	)
	utils.getFileResource(upsream_repo_depends, "temp_req.txt")
	pip.main(args=[
		"install", "--upgrade-strategy",
		"only-if-needed", "--upgrade",
		"-r", "temp_req.txt"
	])
	utils.cleanFileResource("temp_req.txt")
	return None


@remediation.error_passing
def upgradePiAPlib_webui():
	"""Upgrade PiAP version via update script."""
	upsream_repo_depends = str(
		"https://raw.githubusercontent.com/reactive-firewall" +
		"/Pocket-PiAP/master/upgrade.sh"
	)
	utils.getFileResource(upsream_repo_depends, "upgrade.sh")
	# run script here
	utils.cleanFileResource("upgrade.sh")
	return None


@remediation.error_passing
def upgradeAll():
	"""Upgrade piaplib and requirements via pip."""
	upgradepip()
	upgradePiAPlib()
	upgradePiAPlib_depends()
	return None


@remediation.bug_handling
def main(argv=None):
	"""The Main Event. Upgrade Time."""
	(args, extras) = parseargs(argv)
	if args.upgrade_core is True:
		upgradePiAPlib()
		return 0
	elif args.upgrade_pip is True:
		upgradepip()
		return 0
	elif args.upgrade_all is True:
		upgradeAll()
		return 0
	return 3


if __name__ == u'__main__':
	try:
		import sys
		if (sys.argv is not None and (sys.argv is not []) and (len(sys.argv) > 1)):
			main(sys.argv[1:])
	except Exception as main_err:
		print(str("upgrade: REALLY BAD ERROR: PiAPLib Refused to upgrade! ABORT!"))
		print(str(type(main_err)))
		print(str(main_err))
		print(str(main_err.args[0]))
		main_err = None
		del(main_err)
		exit(3)

