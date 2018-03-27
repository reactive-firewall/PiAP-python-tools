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
	import argparse
except Exception:
	raise ImportError("Error Importing argparse tools")


try:
	import subprocess
	import threading
except Exception:
	raise ImportError("Error Importing threading tools")


try:
	import os
	import sys
except Exception:
	raise ImportError("Error Importing system tools")


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
		try:
			from piaplib.book.logs import logs as logs
		except Exception:
			raise ImportError("Error Importing logs")


"""
Upgrades are basically just done via pip right now.
"""


__prog__ = """piaplib.pku.upgrade"""
"""The name of this PiAPLib tool is Pocket Knife Upgrade Unit"""


@remediation.error_passing
def parseargs(arguments=None):
	"""Parse the arguments"""
	parser = argparse.ArgumentParser(
		prog=__prog__,
		description='Run piaplib upgrade functions.',
		epilog='basically a python wrapper for pip install --upgrade.'
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
		help='Upgrade the pip module. This is needed for piaplib dependencies. BETA FEATURE.'
	)
	the_action.add_argument(
		'-W',
		'--upgrade-webroot',
		dest='upgrade_web',
		default=False,
		action='store_true',
		help='Upgrade the piaplib webroot module. EXPERIMENTAL.'
	)
	the_action.add_argument(
		'-A',
		'--upgrade-all',
		dest='upgrade_all',
		default=False,
		action='store_true',
		help='Upgrade all of the piaplib.'
	)
	parser = utils._handleVersionArgs(parser)
	theResult = parser.parse_known_args(arguments)
	return theResult


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
		cache.open(None)
		for pkg in cache.get_changes():
			logs.log((pkg.sourcePackageName, pkg.isUpgradeable), "Info")
	except Exception as permErr:
		remediation.error_breakpoint(permErr, "upgradeAPT")
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
	elif args.upgrade_web is True:
		upgradePiAPlib_webui()
		return 0
	elif args.upgrade_all is True:
		upgradeAll()
		return 0
	return 3


if __name__ == u'__main__':
	try:
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

