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
	import os
	import sys
	import argparse
	import subprocess
	import threading
	for someModule in [os, sys, argparse, subprocess, threading]:
		if someModule.__name__ is None:
			raise ImportError(str("OMG! we could not import {}. ABORT. ABORT.").format(someModule))
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


try:
	import warnings
	with warnings.catch_warnings():
		warnings.filterwarnings("ignore", category=PendingDeprecationWarning)
		warnings.filterwarnings("ignore", category=DeprecationWarning)
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
	from piaplib.book.logs import logs as logs
except Exception:
	try:
		from book.logs import logs as logs
	except Exception:
		raise ImportError("Error Importing logs")


"""
Upgrades are basically just done via pip right now.
"""


__prog__ = """piaplib.pku.upgrade"""
"""The name of this PiAPLib tool is Pocket Knife Upgrade Unit"""


__description__ = """Run piaplib upgrade functions."""
"""The description of this PiAPLib tool is 'Run piaplib upgrade functions.'"""


__epilog__ = """basically a python wrapper for pip install --upgrade."""
"""...basically a python wrapper for pip install --upgrade."""


@remediation.error_handling
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
			str(__prog__).split(".")[-1], help=__description__
		)
	the_action = parser.add_mutually_exclusive_group()
	the_action.add_argument(
		'-u', '--upgrade', dest='upgrade_action', default='core', action='store_const',
		const='core', help='Upgrade the piaplib. This is the default.'
	)
	the_action.add_argument(
		'-P', '--upgrade-pip', dest='upgrade_action', action='store_const',
		const='pip', help='Upgrade the pip module. This is needed for piaplib dependencies.'
	)
	the_action.add_argument(
		'-W', '--upgrade-webroot', dest='upgrade_action', action='store_const',
		const='webroot', help='Upgrade the piaplib webroot module. EXPERIMENTAL.'
	)
	the_action.add_argument(
		'-S', '--upgrade-system', dest='upgrade_action', action='store_const',
		const='apt', help='Upgrade the underlying system. EXPERIMENTAL.'
	)
	the_action.add_argument(
		'-A', '--upgrade-all', dest='upgrade_action', action='store_const',
		const='all', help='Upgrade all of the piaplib.'
	)
	parser = utils._handleVersionArgs(parser)
	if calling_parser_group is None:
		calling_parser_group = parser
	return calling_parser_group


@remediation.error_handling
def parseargs(arguments=None):
	"""Parses the CLI arguments."""
	parser = generateParser(None)
	return parser.parse_known_args(arguments)


@remediation.error_passing
def upgradepip():
	"""Upgrade pip via pip."""
	try:
		pip.main(args=["install", "--upgrade", "pip"])
	except Exception as permErr:
		remediation.error_breakpoint(permErr)
		permErr = None
		del(permErr)
	return None


@remediation.error_passing
def upgradeAPT():
	"""Upgrade system via apt."""
	try:
		import apt
		import apt.cache
		cache = apt.Cache()
		cache.update()
		cache.open(None)
		cache.upgrade()
		for pkg in cache.get_changes():
			logs.log(str((pkg.name, pkg.isupgradeable)), "Info")
		raise NotImplementedError("[CWE-758] - Pocket upgrade upgradeAPT() not implemented. Yet.")
	except Exception as permErr:
		remediation.error_breakpoint(permErr, "upgradeAPT")
		permErr = None
		del(permErr)
	return None


@remediation.error_passing
def upgradePiAPlib():
	"""Upgrade piaplib via pip."""
	upsream_repo = str("git+https://github.com/reactive-firewall/PiAP-python-tools.git#egg=piaplib")
	pip.main(args=["install", "--upgrade", upsream_repo])
	return None


@remediation.error_passing
def upgradePiAPlib_depends():
	"""Upgrade piaplib via pip."""
	upsream_repo_depends = str(
		"https://raw.githubusercontent.com/reactive-firewall" +
		"/PiAP-python-tools/stable/requirements.txt"
	)
	utils.getFileResource(upsream_repo_depends, "temp_req.txt")
	pip.main(args=[
		"install", "--upgrade-strategy",
		"only-if-needed", "--upgrade",
		"-r", "temp_req.txt"
	])
	utils.cleanFileResource("temp_req.txt")
	return None


def wait_for_threads_to_drain(names=[]):
	main_thread = threading.currentThread()
	for t in threading.enumerate():
		if t is main_thread:
			continue
		elif names is not None and (len(names) > 0):
			if t.getName() in names:
				logs.log(str("joining {}").format(t.getName()), "Debug")
				t.join()
			else:
				continue
		else:
			logs.log(str("joining {}").format(t.getName()), "Debug")
			t.join()
	return None


@remediation.error_handling
def doPythonCommand(args=[None], stderr=None):
	"""function for backend subprocess shell command"""
	theOutput = None
	try:
		if args is None or args is [None]:
			theOutput = subprocess.check_output(["exit 1 ; #"])
		else:
			theOutput = subprocess.check_output(args, stderr=stderr)
	except Exception:
		theOutput = None
	try:
		if isinstance(theOutput, bytes):
			theOutput = theOutput.decode('utf8')
	except UnicodeDecodeError:
		theOutput = bytes(theOutput)
	return theOutput


# need something like:
# def createPathToDir(path, mode=751)
# os.mkdir(path=os.path.abspath(path), mode=751, dir_fd=None)
# if os.path.isdir(os.path.abspath("""/opt/PiAP/sbin/""")) is False:
# os.mkdir(path="""/opt""", mode=1777, dir_fd=None)
# os.chown("""/opt/""", 0, 0, dir_fd=None, follow_symlinks=True)
# os.mkdir(path="""/opt/PiAP/""", mode=751, dir_fd=None)
# os.chown("""/opt/PiAP/""", 0, 0, dir_fd=None, follow_symlinks=True)
# should test access

@remediation.error_passing
def upgradePiAPlib_webui():
	"""Upgrade PiAP version via update script."""
	upsream_repo_depends = str(
		"https://raw.githubusercontent.com/reactive-firewall" +
		"/Pocket-PiAP/stable/upgrade.sh"
	)
	script_prefix = str("""/opt/PiAP/sbin/""")
	if os.path.isdir(os.path.abspath("""/opt/PiAP/sbin/""")) is False:
		script_prefix = str("""/var/tmp/""")
	utils.getFileResource(upsream_repo_depends, str(script_prefix + "upgrade.sh"))
	# check script
	# lock state
	try:
		upgrade_thread = threading.Thread(
			name='PiAP Upgrade Thread',
			target=doPythonCommand,
			args=(["bash", str(script_prefix + "upgrade.sh")], None,)
		)
		upgrade_thread.start()
	except Exception:
		logs.log(str("PANIC - upgrade failed to start"), "CRITICAL")
	# not sure if this is needed utils.cleanFileResource("upgrade.sh")
	try:
		wait_for_threads_to_drain(['PiAP Upgrade Thread'])
	except Exception:
		logs.log(str("PANIC - upgrade failed to stop safely"), "CRITICAL")
	return None


@remediation.error_passing
def upgradeAll():
	"""Upgrade piaplib and requirements via pip."""
	upgradepip()
	upgradeAPT()
	upgradePiAPlib()
	upgradePiAPlib_depends()
	# upgradePiAPlib_webui()
	return None


_UPGRADE_ACTIONS = dict({
	'core': upgradePiAPlib,
	'pip': upgradepip,
	'webroot': upgradePiAPlib_webui,
	'apt': upgradeAPT,
	'all': upgradeAll
})
"""Posible upgrade actions."""


@remediation.bug_handling
def main(argv=None):
	"""The Main Event. Upgrade Time."""
	(args, extras) = parseargs(argv)
	theResult = 1
	if args.upgrade_action is not None:
		_UPGRADE_ACTIONS[args.upgrade_action]()
		theResult = 0
	return theResult


if __name__ in u'__main__':
	try:
		__name__ = __prog__
		if (sys.argv is not None and (sys.argv is not []) and (len(sys.argv) > 1)):
			exit(main(sys.argv[1:]))
		else:
			exit(main(["--help"]))
	except Exception:
		raise ImportError("Error running main")
	exit(3)

