#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Pocket PiAP
# ......................................................................
# Copyright (c) 2017-2019, Kendrick Walls
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
	import subprocess
	import argparse
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
	import pku.utils as utils
	import pku.remediation as remediation
	import pku.interfaces as interfaces
	try:
		from . import html_generator as html_generator
	except Exception:
		import html_generator as html_generator
	for depend in [piaplib, utils, remediation, interfaces, html_generator]:
		if depend.__name__ is None:
			raise ImportError("Failed to import piaplib components.")
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
		parser = utils._handleVerbosityArgs(parser, default=False)
		parser = utils._handleVersionArgs(parser)
		theResult = parser.parse_args(arguments)
	except Exception as parseErr:
		parser.error(str(parseErr))
	return theResult


@remediation.error_handling
def taint_name(rawtxt):
	"""check the interface arguments"""
	tainted_input = str(rawtxt).lower()
	return interfaces.taint_name(tainted_input)


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
@utils.memoize
def get_iface_status_raw_cmd_args():
	"""Either ip addr or ifconfig depending on system."""
	theResult = [str("ip"), str("addr"), str("show")]
	try:
		if (str(sys.platform).lower().startswith(str("""darwin""")) is True):
			theResult = [str("ifconfig")]
	except Exception as someErr:
		logs.log(str(type(someErr)), "Error")
		logs.log(str(someErr), "Error")
		logs.log(str((someErr.args)), "Error")
	return theResult


@remediation.error_passing
def get_iface_status_raw(interface=None):
	"""list the raw status of interfaces."""
	cli_args = [x for x in get_iface_status_raw_cmd_args()]
	theRawIfaceState = None
	tainted_name = None
	if interface is not None:
		tainted_name = taint_name(interface)
	if tainted_name is not None and tainted_name not in cli_args:
		cli_args.append(str(tainted_name))
	try:
		theRawIfaceState = subprocess.check_output(
			cli_args, stderr=subprocess.STDOUT, shell=False
		)
	except subprocess.CalledProcessError as subErr:
		cli_args = None
		del cli_args
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


@remediation.error_passing
def get_iface_list():
	"""list the available interfaces."""
	theResult = []
	theRawIfaceState = get_iface_status_raw(None)
	if theRawIfaceState is None:
		return theResult
	for x in utils.extractIfaceNames(str(theRawIfaceState)):
		if utils.isWhiteListed(x, interfaces.INTERFACE_CHOICES):
			theResult.append(x)
	theResult = utils.compactList(theResult)
	"""while regex would probably work well here, best to whitelist. """
	return theResult


def _isMacOS():
	"""Simply returns a boolean stating if sys.platform is darwin."""
	return (str(sys.platform).lower().startswith(str("""darwin""")) is True)


def _extractIFaceStatus(status_txt=None):
	"""Simply returns a boolean stating if sys.platform is darwin."""
	theResult = str("UNKNOWN")
	if status_txt is not None:
		stat_checks = dict({str("DOWN"): str(" DOWN"), str("UP"): str(" UP")})
		if _isMacOS():
			stat_checks["UP"] = str("<UP")
		for check_string in stat_checks.keys():
			if (str(stat_checks[check_string]) in str(status_txt)):
				theResult = str(check_string)
	return theResult


@remediation.error_handling
def get_iface_status(iface=u'lo', use_html=False):
	"""Generate the status"""
	theResult = None
	if iface not in get_iface_list():
		return theResult
	status_txt = get_iface_status_raw(iface)
	if use_html is False:
		theResult = _extractIFaceStatus(status_txt)
	else:
		theResult = generate_iface_status_html(iface, status_txt)
	return theResult


@remediation.error_passing
def generate_iface_status_html(iface=u'lo', status_txt="UNKNOWN"):
	"""Generates the html for interface of given status. Status is UNKNOWN by default."""
	status = "UNKNOWN"
	valid_status = html_generator.HTML_LABEL_ROLES[0]
	if status_txt is not None:
		if (str(" DOWN") in str(status_txt)):
			status = "DOWN"
			valid_status = html_generator.HTML_LABEL_STATUS[u'CRITICAL']
		elif (str(" UP") in str(status_txt)):
			status = "UP"
			valid_status = html_generator.HTML_LABEL_STATUS[u'OK']
	return generate_iface_status_html_raw(iface, status, valid_status)


@remediation.error_passing
def generate_iface_status_html_raw(iface=u'lo', status="UNKNOWN", lable=None):
	"""Generates the raw html for interface of given status with the given lable"""
	if lable in html_generator.HTML_LABEL_ROLES:
		theResult = html_generator.gen_html_td(
			html_generator.gen_html_label(str(status), lable),
			str(u'iface_status_value_{}').format(iface)
		)
	else:
		theResult = generate_iface_status_html_raw(
			iface, "UNKNOWN", html_generator.HTML_LABEL_ROLES[0]
		)
	return theResult


@remediation.error_passing
def get_iface_mac(iface=u'lo', use_html=False):
	"""Generate output of the iface mac."""
	theResult = None
	mac_list_txt = utils.extractMACAddr(get_iface_status_raw(iface))
	if use_html is False:
		if mac_list_txt is not None and (len(mac_list_txt) > 0):
			theResult = str(mac_list_txt[0])
		else:
			theResult = None
	else:
		if mac_list_txt is not None and (len(mac_list_txt) > 0):
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


@remediation.error_passing
def get_iface_ip_list(iface=u'lo', use_html=False):
	"""Generate output of the iface IP."""
	theResult = None
	temp_buffer = get_iface_status_raw(iface)
	if temp_buffer is None:
		theResult = None
		ip_list_txt = None
	else:
		ip_list_txt_raw = utils.extractIPAddr(get_iface_status_raw(iface))
		ip_list_txt = [x for x in ip_list_txt_raw if not x.endswith(".255")]
		del ip_list_txt_raw
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
	theText = str("")
	if output_html:
		theText = str(
			"<table class=\"table table-striped\">" +
			"<thead><th>Interface</th><th>MAC</th><th>IP</th><th>State</th></thead><tbody>"
		)
	if (get_iface_list() is not None):
		for iface_name in get_iface_list():
			theText = str("{}{}\n").format(
				theText, str(show_iface(iface_name, verbose_mode, output_html))
			)
	elif output_html:
		theText = str("{}{}").format(
			theText,
			str("""<tr><td colspan="4"><span class=\"label label-danger\">\2<\/span></td></tr>""")
		)
	if output_html:
		theText = str("{}{}").format(
			theText, str("</tbody></table>")
		)
	print(str(theText).rstrip("\n"))


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
			try:
				for iface_name in get_iface_list():
					print(str(iface_name))
			except Exception as err:
				remediation.error_breakpoint(err)
		else:
			interface = args.interface
			print(show_iface(interface, verbose, output_html))
		return 0
	except Exception as main_err:
		logs.log(
			str("iface_check_status: REALLY BAD ERROR: ACTION will not be completed! ABORT!"),
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
			str("iface_check_status: REALLY BAD ERROR: ACTION will not be completed! ABORT!"),
			"Error"
		)
		logs.log(str(main_err), "Error")
		logs.log(str(main_err.args), "Error")
	exit(3)

