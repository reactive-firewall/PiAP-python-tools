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


IFACE_PREFIXES = [str("wlan"), str("eth"), str("usb"), str("br"), str("mon")]
"""whitelist of valid iface prefixes"""


INTERFACE_CHOICES = [str('{}{}').format(str(x), str(y)) for x in IFACE_PREFIXES for y in range(5)]
"""whitelist of valid iface names"""


def parseargs(arguments=None):
	"""Parse the arguments"""
	import argparse
	parser = argparse.ArgumentParser(
		description='Alter the state of a given interface.',
		epilog='Basicly a python wrapper for iface.'
	)
	parser.add_argument(
		'-i',
		'--interface',
		default=INTERFACE_CHOICES[1],
		choices=INTERFACE_CHOICES,
		help='The interface to use.'
	)
	the_action = parser.add_mutually_exclusive_group(required=True)
	the_action.add_argument(
		'-u',
		'--up',
		'--enable',
		dest='enable_action',
		default=False,
		action='store_true',
		help='Enable the given interface.'
	)
	the_action.add_argument(
		'-d',
		'--down',
		'--disable',
		dest='disable_action',
		default=False,
		action='store_true',
		help='Disable the given interface.'
	)
	the_action.add_argument(
		'-r',
		'--down-up',
		'--restart',
		dest='restart_action',
		default=True,
		action='store_true',
		help='Disable and then re-enable the given interface. (default)'
	)
	theResult = parser.parse_args(arguments)
	return theResult


def taint_name(rawtxt):
	"""Checks the interface arguments."""
	tainted_input = str(rawtxt).lower()
	for test_iface in INTERFACE_CHOICES:
		if tainted_input in test_iface:
			return test_iface
	return None


def enable_iface(iface_name=None):
	"""enable the given interface by calling ifup."""
	theResult = str("")
	try:
		tainted_name = taint_name(iface_name)
		import subprocess
		theResult = subprocess.check_output([str("ifup"), str(tainted_name)])
	except Exception as err:
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		err = None
		del(err)
	return theResult


def disable_iface(iface_name="lo", force=False):
	"""disable the given interface by calling ifdown."""
	tainted_name = taint_name(iface_name)
	import subprocess
	if force is False:
		theResult = subprocess.check_output(['ifdown', tainted_name])
	elif force is True:
		theResult = subprocess.check_output(['ifdown', '--force', tainted_name])
	return theResult


def restart_iface(iface_name="lo"):
	"""
	Disable the given interface by calling ifdown,
	THEN re-enable the given interface by calling ifup.
	"""
	tainted_name = taint_name(iface_name)
	disable_iface(tainted_name, True)
	enable_iface(tainted_name)
	return True


if __name__ == u'__main__':
	import sys
	if (sys.argv is not None and (sys.argv is not []) and (len(sys.argv) > 1)):
		args = parseargs(sys.argv[:1])
	try:
		interface = args.interface
		if args.enable_action is True:
			enable_iface(interface)
			exit(0)
		elif args.disable_action is True:
			disable_iface(interface, False)
			exit(0)
		elif args.restart_action is True:
			restart_iface(interface)
			exit(0)
	except Exception as err:
		print(str("interfaces: REALLY BAD ERROR: ACTION will not be compleated! ABORT!"))
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		err = None
		del(err)
	exit(1)

