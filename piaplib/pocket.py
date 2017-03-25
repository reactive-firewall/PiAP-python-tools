#! /usr/bin/env python

#
# Pocket PiAP
#
# Copyright (c) 2017, Kendrick Walls
#	
#	Licensed under the Apache License, Version 2.0 (the "License");
#		you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#	   
#	   http://www.apache.org/licenses/LICENSE-2.0
#   
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import argparse

POCKET_UNITS_OPTIONS=[u'pku', u'protector', u'blade', u'keyring', u'lint', u'fruitsnack']
""" The Pocket Knife Units available.
	pku - the pocket knife unit. The everything pocket tool.
	protector - the pocket protector. The defensive security tool.
	blade - the pocket blade. The offensive security tool. (FUTURE/RESERVED)
	keyring - the pocket keyring. The crypto tool. (FUTURE/RESERVED)
	lint - the extra pocket stuff tool. Small things always in the pocket.
	fruitsnack - the little Pi in the pocket. Wrapper for all things RaspberryPi.
	cargo - for storage and the like. (FUTURE/RESERVED)
	"""

PKU_OPTIONS=[u'config', u'backup', u'upgrade']
""" The Pocket Knife Unit actions.
	config -  (FUTURE/RESERVED)
	backup -  (FUTURE/RESERVED)
	upgrade -  (FUTURE/RESERVED)
	help -  (FUTURE/RESERVED)
	"""

PROTECTOR_OPTIONS=[u'fw', u'ids', u'acl']
""" The Pocket Knife Unit actions.
	fw - pocket firewall control.
	ids -  (FUTURE/RESERVED)
	acl -  (FUTURE/RESERVED)
	"""

LINT_OPTIONS=[u'check', u'ids', u'acl']
""" The Pocket Lint Unit actions.
	check - pocket checks.
	nrpe - nagios/sensu/etc. compatible checks (FUTURE/RESERVED)
	help -  (FUTURE/RESERVED)
	"""

def parseArgs():
	"""Parses the CLI arguments."""
	parser = argparse.ArgumentParser(prog="PiAP-util.py",
		description='Handles PiAP python tools', epilog="PiAP Controller for PiAP tools.")
	parser.add_argument('pocket_unit', choices=POCKET_UNITS_OPTIONS, help='the pocket service option.')
	parser.add_argument('-V', '--version', action='version', version='%(prog)s 0.2.3')
	return parser.parse_args()


# define the function blocks

def getTimeStamp():
	"""Returns the time stamp."""
	theDate=None
	try:
		import time
		theDate = time.strftime("%a %b %d %H:%M:%S %Z %Y", time.localtime())
	except Exception:
		theDate=str("")
	return str(theDate)

def doRunHandle(theInputStr):
	"""Handler for Error state."""
	try:
		import os
		import subprocess
		try:
			theResult=subprocess.check_output(str(theInputStr).split(' '))
		except Exception:
			timestamp = getTimeStamp()
			theResult = str(timestamp+" - WARNING - An error occured while handling the shell. Cascading failure.")
	except Exception:
		theResult = str("CRITICAL - An error occured while handling the cascading failure.")
		return theResult

# could do something per count too
#count_options = {1 : first_handler,
#	2 : second_handler,
#	3 : last_handler,
#	4 : error_handler
#}

def main():
	args = parseArgs()
	try:
		service_cmd = str(args.pocket_unit)
	except Exception as cerr:
		print(str(cerr))
		print(str(cerr.args))
		print(str(" UNKNOWN - An error occured while handling the arguments. Command failure."))
		exit(3)
	try:
		doRunHandle(POCKET_UNITS[service_cmd]);
	except Exception:
		print(str(" UNKNOWN - An error occured while handling the failure. Cascading failure."))
		exit(3)
	exit(0)


if __name__ == '__main__':
	main()
