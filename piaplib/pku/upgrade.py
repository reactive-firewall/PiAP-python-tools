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
	import pip
except Exception:
	raise ImportError("Error Importing pip tools")

try:
	import argparse
except Exception:
	raise ImportError("Error Importing argparse tools")


"""
Upgrades are basicly just done via pip right now.
"""


def parseargs(arguments=None):
	"""Parse the arguments"""
	parser = argparse.ArgumentParser(
		description='Run piaplib upgrade functions.',
		epilog='Basicly a python wrapper for pip install --upgrade.'
	)
	the_action = parser.add_mutually_exclusive_group(required=True)
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
		default=True,
		action='store_false',
		help='Upgrade the pip module. This is needed for hashes in the future. EXPEREMENTAL.'
	)
	the_action.add_argument(
		'-A',
		'--upgrade-all',
		dest='upgrade_all',
		default=True,
		action='store_false',
		help='Upgrade the piaplib. This is the default.'
	)
	theResult = parser.parse_args(arguments)
	return theResult


def upgradepip():
	"""Upgrade pip via pip."""
	try:
		pip.main(args=["install", "--upgrade", "pip"])
	except PermissionError as permErr:
		print(str(type(permErr)))
		print(str(permErr))
		print(str((permErr.args)))
		permErr = ""
		permErr = None
		del(permErr)
	return None


def upgradePiAPlib():
	"""Upgrade piaplib via pip."""
	try:
		upsream_repo = str("git+https://github.com/reactive-firewall/PiAP-python-tools.git")
		pip.main(args=["install", "--upgrade", upsream_repo])
	except Exception as permErr:
		print(str(type(permErr)))
		print(str(permErr))
		print(str((permErr.args)))
		permErr = ""
		permErr = None
		del(permErr)
	return None


def upgradeAll():
	"""Upgrade piaplib and requirements via pip."""
	try:
		upgradepip()
		upgradePiAPlib()
	except Exception as permErr:
		print(str(type(permErr)))
		print(str(permErr))
		print(str((permErr.args)))
		permErr = ""
		permErr = None
		del(permErr)
	return None


def main(argv=None):
	"""The Main Event. Upgrade Time."""
	args = parseargs(argv)
	try:
		if args.upgrade_core is True:
			upgradePiAPlib()
			exit(0)
		elif args.upgrade_pip is True:
			upgradepip()
			exit(0)
		elif args.upgrade_all is True:
			upgradeAll()
			exit(0)
	except Exception as main_err:
		print(str("upgrade: REALLY BAD ERROR: UPGRADE will not be compleated! ABORT!"))
		print(str(type(main_err)))
		print(str(main_err))
		print(str(main_err.args[0]))
		main_err = None
		del(main_err)
		exit(2)
	print(str("upgrade: You found a bug. Please report this to my creator."))
	exit(3)


if __name__ == u'__main__':
	try:
		import sys
		if (sys.argv is not None and (sys.argv is not []) and (len(sys.argv) > 1)):
			main(sys.argv[:1])
	except Exception as main_err:
		print(str("upgrade: REALLY BAD ERROR: PiAPLib Refused to upgrade! ABORT!"))
		print(str(type(main_err)))
		print(str(main_err))
		print(str(main_err.args[0]))
		main_err = None
		del(main_err)
		exit(3)

