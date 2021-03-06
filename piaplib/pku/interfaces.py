#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Pocket PiAP
# ......................................................................
# Copyright (c) 2017-2020, Kendrick Walls
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
	import argparse
except Exception:
	raise ImportError("WTF, no system?!?!")


try:
	if str("piaplib.pku.remediation") not in sys.modules:
		from piaplib.pku import remediation as remediation
	else:
		remediation = sys.modules[str("piaplib.pku.remediation")]
except Exception:
	try:
		import piaplib.pku.remediation as remediation
	except Exception as err:
		raise ImportError(err, "Error Importing remediation")


try:
	if str("piaplib.pku.utils") not in sys.modules:
		from piaplib.pku import utils as utils
	else:
		utils = sys.modules[str("piaplib.pku.utils")]
except Exception:
	try:
		import piaplib.pku.utils as utils
	except Exception as err:
		raise ImportError(err, "Error Importing piaplib.pku.utils")


__prog__ = """piaplib.pku.interfaces"""
"""The name of this PiAPLib tool is Pocket Knife Interfaces Unit"""


__description__ = """Alter the state of a given interface."""
"""The description of this PiAPLib tool is 'Alter the state of a given interface.'"""


__epilog__ = """Basicly a python wrapper for iface."""
"""...basically a python wrapper for iface."""


__ALTMODE = False
"""Flag to use alternate interface name resolution (without netifaces)"""


global INTERFACE_CHOICES


if sys.platform.startswith("linux") and (sys.version_info > (3, 3)):
	try:
		import netifaces

		INTERFACE_CHOICES = netifaces.interfaces()
		"""whitelist of valid iface names"""

		__ALTMODE = False
	except Exception:
		__ALTMODE = True
else:
	__ALTMODE = True


if __ALTMODE:
	IFACE_PREFIXES = [
		str("lan"), str("wlan"), str("eth"), str("usb"),
		str("br"), str("mon"), str("enp0s"), str("eno"), str("ens"), str("en")
	]
	"""whitelist of valid iface prefixes"""

	INTERFACE_CHOICES = [
		str("""{}{}""").format(str(x), str(y)) for x in IFACE_PREFIXES for y in range(5)
	]
	"""whitelist of valid iface names"""


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
	parser.add_argument(
		'-i', '--interface', dest='interface', default=INTERFACE_CHOICES[0],
		choices=INTERFACE_CHOICES,
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
	if calling_parser_group is None:
		calling_parser_group = parser
	return calling_parser_group


@remediation.error_handling
def parseargs(arguments=None):
	"""Parses the CLI arguments."""
	parser = generateParser(None)
	return parser.parse_known_args(arguments)


@remediation.error_handling
def taint_name(rawtxt):
	"""Checks the interface arguments."""

	def _inner_taint(bad_juju):
		"""Helper function for input tainting"""
		enc_text = utils.literal_code(bad_juju)
		if not isinstance(enc_text, type(None)):
			return enc_text
		return str("")

	theResult = None
	tainted_input = _inner_taint(rawtxt).lower()
	if utils.isWhiteListed(tainted_input, INTERFACE_CHOICES):
		theResult = tainted_input
	return theResult


@remediation.error_handling
def taint_enable_args(rawtxt):
	"""Checks the interface arguments."""
	theResult = []
	tainted_input = taint_name(rawtxt)
	if sys.platform.startswith("linux"):
		theResult = [str("ifup"), str(tainted_input)]
	elif sys.platform.startswith("darwin"):
		theResult = [str("ifconfig"), str(tainted_input), str("up")]
	return theResult


@remediation.error_handling
def taint_disable_args(rawtxt, force=False):
	"""Checks the interface arguments."""
	theResult = []
	tainted_input = taint_name(rawtxt)
	if sys.platform.startswith("linux"):
		if force is False:
			theResult = [str("ifdown"), str(tainted_input)]
		elif force is True:
			theResult = [str("ifdown"), str("--force"), str(tainted_input)]
	elif sys.platform.startswith("darwin"):
		theResult = [str("ifconfig"), str(tainted_input), str("down")]
	return theResult


@remediation.error_handling
def enable_iface(iface_name=None):
	"""enable the given interface by calling ifup."""
	theResult = str("")
	try:
		import subprocess
		theResult = subprocess.check_output(taint_enable_args(iface_name))
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
	import subprocess
	theResult = subprocess.check_output(taint_disable_args(iface_name, force))
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
		del args
		del extras
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

