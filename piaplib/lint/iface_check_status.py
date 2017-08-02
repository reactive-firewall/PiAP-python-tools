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
	import os
	import sys
	sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
	try:
		import piaplib as piaplib
	except Exception:
		from . import piaplib as piaplib
	try:
		from piaplib.book.logs import logs as logs
	except Exception:
		try:
			from book.logs import logs as logs
		except Exception as err:
			print(str(type(err)))
			print(str(err))
			print(str(err.args))
			print("")
			raise ImportError("Error Importing logs")
	try:
		from .. import utils as utils
	except Exception:
		import pku.utils as utils
	try:
		from .. import remediation as remediation
	except Exception:
		import pku.remediation as remediation
	try:
		from . import html_generator as html_generator
	except Exception as ImpErr:
		ImpErr = None
		del ImpErr
		import html_generator as html_generator
	try:
		from .. import interfaces as interfaces
	except Exception:
		import pku.interfaces as interfaces
	if utils.__name__ is None:
		raise ImportError("Failed to open PKU Utils")
	if remediation.__name__ is None:
		raise ImportError("Failed to open PKU Remediation")
	if interfaces.__name__ is None:
		raise ImportError("Failed to open PKU Interfaces")
	if html_generator.__name__ is None:
		raise ImportError("Failed to open HTML5 Pocket Lint")
except Exception as importErr:
	print(str(importErr))
	print(str(importErr.args))
	importErr = None
	del importErr
	raise ImportError("Failed to import " + str(__file__))
	exit(255)


__prog__ = str("""iface_check_status""")
"""The Program's name"""


def parseargs(arguments=None):
	"""Parse the arguments"""
	import argparse
	try:
		parser = argparse.ArgumentParser(
			prog=__prog__,
			description='Report the state of a given interface.',
			epilog='Basicly a python wrapper for ip addr show.'
		)
		parser.add_argument(
			'-i', '--interface',
			default=interfaces.INTERFACE_CHOICES[0], choices=interfaces.INTERFACE_CHOICES,
			help='The interface to show.'
		)
		parser.add_argument(
			'-l', '--list',
			default=False, action='store_true',
			help='List current interfaces.'
		)
		parser.add_argument(
			'--html', dest='output_html',
			default=False, action='store_true',
			help='output html.'
		)
		parser.add_argument(
			'-a', '--all',
			dest='show_all', default=False,
			action='store_true', help='show all interfaces.'
		)
		the_action = parser.add_mutually_exclusive_group(required=False)
		the_action.add_argument(
			'-v', '--verbose',
			dest='verbose_mode', default=False,
			action='store_true', help='Enable verbose mode.'
		)
		the_action.add_argument(
			'-q', '--quiet',
			dest='verbose_mode', default=False,
			action='store_false', help='Disable the given interface.'
		)
		parser.add_argument(
			'-V', '--version',
			action='version', version=str(
				"%(prog)s {}"
			).format(str(piaplib.__version__)))
		theResult = parser.parse_args(arguments)
	except Exception as parseErr:
		parser.error(str(parseErr))
	return theResult


@remediation.error_handling
def taint_name(rawtxt):
	"""check the interface arguments"""
	tainted_input = str(rawtxt).lower()
	for test_iface in interfaces.INTERFACE_CHOICES:
		if str(tainted_input) in str(test_iface):
			return str(test_iface)
	return None


def show_iface(iface_name=None, is_verbose=False, use_html=False):
	"""enable the given interface by calling ifup."""
	if is_verbose is True:
		theResult = str(get_iface_status_raw(iface_name))
	else:
		try:
			if use_html:
				format_pattern = str(u'{}{}{}{}')
			else:
				format_pattern = str(u'{} {} {} {}')
			theResult = str(format_pattern).format(
				get_iface_name(iface_name, use_html),
				get_iface_mac(iface_name, use_html),
				get_iface_ip_list(iface_name, use_html),
				get_iface_status(iface_name, use_html)
			)
			if use_html:
				theResult = html_generator.gen_html_tr(
					theResult,
					str(u'iface_status_row_{}').format(iface_name)
				)
		except Exception as cmdErr:
			logs.log(str(cmdErr), "Error")
			logs.log(str((cmdErr.args)), "Error")
			theResult = "UNKNOWN"
	return theResult


@remediation.error_handling
def get_iface_name(iface_name=None, use_html=False):
	if iface_name is None:
		return None
	if use_html is not True:
		return taint_name(iface_name)
	else:
		iface = str(get_iface_name(iface_name, False))
		return html_generator.gen_html_td(iface, str(u'iface_status_dev_{}').format(iface))


@remediation.error_handling
def get_iface_status_raw(interface=None):
	"""list the raw status of interfaces."""
	arguments = [str("ip"), str("addr")]
	if interface is not None:
		tainted_name = taint_name(interface)
		arguments = [str("ip"), str("addr"), str("show"), str(tainted_name)]
	theRawIfaceState = None
	import subprocess
	try:
		theRawIfaceState = subprocess.check_output(arguments, stderr=subprocess.STDOUT)
	except subprocess.CalledProcessError as subErr:
		logs.log(str("ERROR"), "Error")
		logs.log(str(type(subErr)), "Error")
		logs.log(str(subErr), "Error")
		logs.log(str(subErr.args), "Error")
		logs.log(str(""), "Error")
		subErr = None
		del subErr
		theRawIfaceState = None
	except Exception as cmdErr:
		logs.log(str(cmdErr), "Error")
		logs.log(str(cmdErr.args), "Error")
		cmdErr = None
		del cmdErr
		theRawIfaceState = None
	return theRawIfaceState


@remediation.error_handling
def get_iface_list():
	"""list the available interfaces."""
	theResult = []
	theRawIfaceState = get_iface_status_raw(None)
	for x in utils.extractIfaceNames(theRawIfaceState):
		if x in interfaces.INTERFACE_CHOICES:
			theResult.append(x)
	theResult = utils.compactList([x for x in theResult])
	"""while regex would probably work well here, best to whitelist. """
	return theResult


@remediation.error_handling
def get_iface_status(iface=u'lo', use_html=False):
	"""Generate the status"""
	theResult = None
	status_txt = get_iface_status_raw(iface)
	if use_html is False:
		if status_txt is not None:
			if (str(" DOWN") in str(status_txt)):
				theResult = str("DOWN")
			elif (str(" UP") in str(status_txt)):
				theResult = str("UP")
			else:
				theResult = str("UNKNOWN")
		else:
			theResult = str("UNKNOWN")
	else:
		if status_txt is not None:
			if (str(" DOWN") in str(status_txt)):
				theResult = html_generator.gen_html_td(
					html_generator.gen_html_label(str("DOWN"), u'danger'),
					str(u'iface_status_value_{}').format(iface)
				)
			elif (str(" UP") in str(status_txt)):
				theResult = html_generator.gen_html_td(
					html_generator.gen_html_label(str("UP"), u'success'),
					str(u'iface_status_value_{}').format(iface)
				)
			else:
				theResult = html_generator.gen_html_td(
					html_generator.gen_html_label(str("UNKNOWN"), u'default'),
					str(u'iface_status_value_{}').format(iface)
				)
		else:
			theResult = html_generator.gen_html_td(
				html_generator.gen_html_label(str("UNKNOWN"), u'default'),
				str(u'iface_status_value_{}').format(iface)
			)
	return theResult


@remediation.error_handling
def get_iface_mac(iface=u'lo', use_html=False):
	"""Generate output of the iface mac."""
	theResult = None
	mac_list_txt = utils.extractMACAddr(get_iface_status_raw(iface))
	if use_html is False:
		if mac_list_txt is not None and len(mac_list_txt) > 0:
			theResult = str(mac_list_txt[0])
		else:
			theResult = None
	else:
		if mac_list_txt is not None and len(mac_list_txt) > 0:
			theResult = html_generator.gen_html_td(
				str(mac_list_txt[0]),
				str(u'iface_status_mac_{}').format(iface)
			)
		else:
			theResult = html_generator.gen_html_td(
				"",
				str(u'iface_status_mac_{}').format(iface)
			)
	return theResult


@remediation.error_handling
def get_iface_ip_list(iface=u'lo', use_html=False):
	"""Generate output of the iface IP."""
	theResult = None
	ip_list_txt = utils.extractIPAddr(get_iface_status_raw(iface))
	if use_html is False:
		if ip_list_txt is not None and len(ip_list_txt) > 0:
			theResult = str(ip_list_txt)
		else:
			theResult = None
	else:
		if ip_list_txt is not None and len(ip_list_txt) > 0:
			theResult = html_generator.gen_html_td(
				html_generator.gen_html_ul(ip_list_txt),
				str(u'iface_status_ips_{}').format(iface)
			)
		else:
			theResult = html_generator.gen_html_td(
				html_generator.gen_html_label(u'No IP', html_generator.HTML_LABEL_ROLES[3]),
				str(u'iface_status_ips_{}').format(iface)
			)
	return theResult


@remediation.error_handling
def showAlliFace(verbose_mode, output_html):
	"""Used by main to show all. Not intended to be called directly"""
	if output_html:
		print(
			"<table class=\"table table-striped\">" +
			"<thead><th>Interface</th><th>MAC</th><th>IP</th><th>State</th></thead><tbody>"
		)
	for iface_name in get_iface_list():
		print(show_iface(iface_name, verbose_mode, output_html))
	if output_html:
		print("</tbody></table>")


def main(argv=None):
	"""The main function."""
	args = parseargs(argv)
	try:
		verbose = False
		output_html = False
		if args.verbose_mode is not None:
				verbose = args.verbose_mode
		if args.output_html is not None:
				output_html = args.output_html
		if args.show_all is True:
			showAlliFace(verbose, output_html)
		elif args.list is True:
			for iface_name in get_iface_list():
				print(str(iface_name))
		else:
			interface = args.interface
			print(show_iface(interface, verbose, output_html))
		return 0
	except Exception as main_err:
		logs.log(
			str("iface_check_status: REALLY BAD ERROR: ACTION will not be compleated! ABORT!"),
			"Error"
		)
		logs.log(str(main_err), "Error")
		logs.log(str(main_err.args), "Error")
	return 1


if __name__ == u'__main__':
	try:
		import sys
		exitcode = 3
		if (sys.argv is not None and len(sys.argv) > 0):
			exitcode = main(sys.argv[1:])
		exit(exitcode)
	except Exception as main_err:
		logs.log(
			str("iface_check_status: REALLY BAD ERROR: ACTION will not be compleated! ABORT!"),
			"Error"
		)
		logs.log(str(main_err), "Error")
		logs.log(str(main_err.args), "Error")
	exit(3)

