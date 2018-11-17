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
	import sys
except Exception:
	raise ImportError("WTF, no system?!?!")

try:
	from . import remediation as remediation
except Exception:
	try:
		import remediation as remediation
	except Exception:
		raise ImportError("Error Importing remediation")

try:
	from . import utils as utils
except Exception:
	try:
		import utils as utils
	except Exception:
		raise ImportError("Error Importing utils")


__prog__ = """piaplib.pku.interfaces"""
"""The name of this PiAPLib tool is Pocket Knife Interfaces Unit"""

if sys.platform.startswith("linux"):
	try:
		import netifaces
	except Exception:
		raise ImportError("WTF, no netifaces?!?!")

	INTERFACE_CHOICES = netifaces.interfaces()
	"""whitelist of valid iface names"""
else:
	IFACE_PREFIXES = [
		str("lan"), str("wlan"), str("eth"), str("usb"),
		str("br"), str("mon"), str("enp0s"), str("eno"), str("en")
	]
	"""whitelist of valid iface prefixes"""

	INTERFACE_CHOICES = [str('{}{}').format(str(x), str(y)) for x in IFACE_PREFIXES for y in range(5)]
	"""whitelist of valid iface names"""


@remediation.error_handling
def parseargs(arguments=None):
	"""Parse the arguments"""
	import argparse
	theResult = None
	extras = None
	try:
		parser = argparse.ArgumentParser(
			prog=__prog__,
			description='Alter the state of a given interface.',
			epilog='Basicly a python wrapper for iface.'
		)
		parser.add_argument(
			'-i', '--interface', default=INTERFACE_CHOICES[0], choices=INTERFACE_CHOICES,
			help='The interface to use.'
		)
		the_action = parser.add_mutually_exclusive_group()
		the_action.add_argument(
			'-u', '--up', '--enable', dest='enable_action', default=False, action='store_true',
			help='Enable the given interface.'
		)
		the_action.add_argument(
			'-d', '--down', '--disable', dest='disable_action', default=False, action='store_true',
			help='Disable the given interface.'
		)
		the_action.add_argument(
			'-r', '--down-up', '--restart', dest='restart_action', default=True,
			action='store_true',
			help='Disable and then re-enable the given interface. (default)'
		)
		parser = utils._handleVersionArgs(parser)
		(theResult, extras) = parser.parse_known_args(arguments)
	except Exception as err:
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		err = None
		del(err)
	return (theResult, extras)


@remediation.error_handling
def taint_name(rawtxt):
	"""Checks the interface arguments."""
	theResult = None
	tainted_input = utils.literal_str(rawtxt).lower()
	if utils.isWhiteListed(tainted_input, INTERFACE_CHOICES):
		theResult = tainted_input
	return theResult


@remediation.error_handling
def enable_iface(iface_name=None):
	"""enable the given interface by calling ifup."""
	theResult = str("")
	try:
		tainted_name = taint_name(iface_name)
		import subprocess
		theResult = subprocess.check_output([str("ifup"), str(tainted_name)])
		if theResult is not None and isinstance(theResult, str) and len(theResult) <= 1:
			theResult = None
	except Exception as err:
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		err = None
		del(err)
	return theResult


@remediation.error_handling
def disable_iface(iface_name="lo", force=False):
	"""disable the given interface by calling ifdown."""
	tainted_name = taint_name(iface_name)
	import subprocess
	if force is False:
		theResult = subprocess.check_output(['ifdown', tainted_name])
	elif force is True:
		theResult = subprocess.check_output(['ifdown', '--force', tainted_name])
	return theResult


@remediation.error_handling
def restart_iface(iface_name="lo"):
	"""
	Disable the given interface by calling ifdown,
	THEN re-enable the given interface by calling ifup.
	"""
	tainted_name = taint_name(iface_name)
	disable_iface(tainted_name, True)
	enable_iface(tainted_name)
	return True


@remediation.bug_handling
def main(argv=None):
	try:
		theResult = 1
		args = None
		if (argv is not None and (argv is not []) and (len(argv) >= 1)):
			(args, extras) = parseargs(argv)
		if args is None:
			theResult = 3
		interface = args.interface
		if args.enable_action is True:
			enable_iface(interface)
			theResult = 0
		elif args.disable_action is True:
			disable_iface(interface, False)
			theResult = 0
		elif args.restart_action is True:
			restart_iface(interface)
			theResult = 0
	except Exception as err:
		print(str("interfaces: REALLY BAD ERROR: ACTION will not be completed! ABORT!"))
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		err = None
		del(err)
	return theResult


if __name__ in u'__main__':
	try:
		if (sys.argv is not None and (sys.argv is not []) and (len(sys.argv) > 1)):
			exit(main(sys.argv[1:]))
		else:
			exit(main(["--help"]))
	except Exception:
		raise ImportError("Error running main")
	exit(0)

