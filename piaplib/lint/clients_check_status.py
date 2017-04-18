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

# Imports
try:
	import os
	import sys
	sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
	try:
		from .. import utils as utils
	except Exception:
		import pku.utils as utils
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


__prog__ = str("""clients_check_status.py""")
"""The Program's name"""


def error_handling(func):
	"""Runs a function in try-except"""
	def helper(**kwargs):
		"""Wraps a function in try-except"""
		theOutput = None
		try:
			theOutput = func(kwargs)
		except Exception as err:
			print(str(err))
			print(str((err.args)))
			print(str(
				"{}: REALLY BAD ERROR: ACTION will not be compleated! ABORT!"
			).format(__prog__))
			theOutput = None
		return theOutput
	return helper


def parseargs(arguments=None):
	"""Parse the arguments"""
	import argparse
	try:
		parser = argparse.ArgumentParser(
			prog=__prog__,
			description='Report the state of a given client.',
			epilog='Basicly Arp meets WiFi.'
		)
		parser.add_argument('-i', '--ip', default=None, help='The client to show.')
		parser.add_argument(
			'-l', '--list',
			default=False, action='store_true',
			help='List current clients.'
		)
		parser.add_argument(
			'--html', dest='output_html',
			default=False, action='store_true',
			help='output html.'
		)
		parser.add_argument(
			'--interface', dest='interface',
			default=interfaces.INTERFACE_CHOICES[1], choices=interfaces.INTERFACE_CHOICES,
			help='The LAN interface.'
		)
		parser.add_argument(
			'-a', '--all',
			dest='show_all', default=False,
			action='store_true', help='show all clients.'
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
		parser.add_argument('-V', '--version', action='version', version='%(prog)s 0.2.3')
		theResult = parser.parse_args(arguments)
	except Exception as parseErr:
		parser.error(str("ERROR: parseargs"))
		parser.error(str(type(parseErr)))
		parser.error(str(parseErr))
	return theResult


def show_client(client_ip=None, is_verbose=False, use_html=False, lan_interface=None):
	"""show the given client."""
	try:
		if lan_interface not in interfaces.INTERFACE_CHOICES:
			lan_interface = interfaces.INTERFACE_CHOICES[1]
		if use_html:
			format_pattern = u'{}{}{}{}'
		else:
			format_pattern = u'{} {} {} {}'
		theResult = format_pattern.format(
			get_client_name(client_ip, use_html, lan_interface),
			get_client_mac(client_ip, use_html, lan_interface),
			get_client_ip(client_ip, use_html, lan_interface),
			get_client_status(
				get_client_mac(client_ip, False, lan_interface),
				use_html,
				lan_interface
			)
		)
		if use_html:
			theResult = html_generator.gen_html_tr(
				theResult,
				str(u'client_status_row_{}').format(client_ip)
			)
	except Exception as cmdErr:
		print(str("ERROR: show_client"))
		print(str(type(cmdErr)))
		print(str(cmdErr))
		print(str(cmdErr.args))
		theResult = "UNKNOWN"
	return theResult


def get_client_name(client_ip=None, use_html=False, lan_interface=None):
	if lan_interface not in interfaces.INTERFACE_CHOICES:
		lan_interface = interfaces.INTERFACE_CHOICES[1]
	if client_ip is None:
		return None
	if use_html is not True:
		return get_client_arp_status_raw(client_ip, lan_interface).split(u' ', 1)[0]
	else:
		client = str(get_client_name(client_ip, False))
		return html_generator.gen_html_td(client, str(u'client_status_{}').format(client))


# TODO: memoize this function
def get_client_sta_status_raw():
	"""list the raw status of client sta."""
	theRawClientState = None
	try:
		import subprocess
		try:
			# hard-coded white-list cmd
			output = subprocess.check_output(
				[str("/opt/PiAP/hostapd_actions/clients")],
				stderr=subprocess.STDOUT
			)
			if (output is not None) and (len(output) > 0):
				lines = [utils.literal_str(x) for x in output.splitlines() if x is not None]
				theRawClientState = str("")
				for line in lines:
					if (line is not None) and (len(line) > 0):
						theRawClientState = str("{}{}\n").format(str(theRawClientState), str(line))
				del lines
			else:
				theRawClientState = None
		except FileNotFoundError as depErr:
			print(str(type(depErr)))
			print(str(depErr))
			print(str(depErr.args))
			depErr = None
			del depErr
			theRawClientState = u'UNKNOWN'
		except subprocess.CalledProcessError as subErr:
			print(str(type(subErr)))
			print(str(subErr))
			print(str(subErr.args))
			subErr = None
			del subErr
			theRawClientState = u'UNKNOWN'
		except Exception as cmdErr:
			print(str("ERROR: get_client_sta_status_raw"))
			print(str(type(cmdErr)))
			print(str(cmdErr))
			print(str(cmdErr.args))
			cmdErr = None
			del cmdErr
			theRawClientState = None
	except Exception as importErr:
		print(str(importErr))
		print(str(importErr.args))
		theRawClientState = None
	return theRawClientState


def isLineForSTA(someLine=None, staname=None):
	"""determins if a raw output line is for a STA"""
	doesMatch = False
	try:
		doesMatch = utils.isLineForMatch(someLine, staname)
		if (doesMatch is False):
			if str(staname) in utils.extractIPv4(utils.literal_str(someLine)):
				doesMatch = True
			else:
				doesMatch = False
	except Exception as matchErr:
		print(str(type(matchErr)))
		print(str(matchErr))
		print(str(matchErr.args))
		matchErr = None
		del matchErr
		doesMatch = False
	return doesMatch


def get_client_arp_status_raw(client_ip=None, lan_interface=interfaces.INTERFACE_CHOICES[1]):
	"""list the raw status of client sta."""
	if lan_interface not in interfaces.INTERFACE_CHOICES:
		lan_interface = interfaces.INTERFACE_CHOICES[1]
	arguments = [str("arp"), str("-i"), str(lan_interface), str("-a")]
	theRawClientState = None
	try:
		import subprocess
		try:
			output = subprocess.check_output(arguments, stderr=subprocess.STDOUT)
			if (output is not None) and (len(output) > 0):
				lines = [
					utils.literal_str(x) for x in output.splitlines() if isLineForSTA(x, client_ip)
				]
				theRawClientState = str("")
				for line in lines:
					if (line is not None) and (len(line) > 0):
						theRawClientState = str("{}{}\n").format(str(theRawClientState), str(line))
				del lines
			else:
				theRawClientState = None
		except subprocess.CalledProcessError as subErr:
			subErr = None
			del subErr
			theRawClientState = None
		except Exception as cmdErr:
			print(str("ERROR: get_client_arp_status_raw - 403"))
			print(str(type(cmdErr)))
			print(str(cmdErr))
			print(str(cmdErr.args))
			theRawClientState = None
	except Exception as importErr:
		print(str(importErr))
		print(str(importErr.args))
		theRawClientState = None
	return theRawClientState


# TODO: memoize this function
def get_client_sta_status(client_mac=None):
	"""list the raw status of client sta."""
	theClientState = str("disassociated")
	if client_mac is not None:
		matches = []
		try:
			matches = utils.extractMACAddr(get_client_sta_status_raw())
			if str(client_mac) in utils.extractMACAddr(get_client_sta_status_raw()):
				theClientState = str("associated")
		except Exception as cmdErr:
			print(str("ERROR: get_client_sta_status"))
			print(str(type(cmdErr)))
			print(str(cmdErr))
			print(str(cmdErr.args))
			theClientState = u'UNKNOWN'
	return theClientState


# TODO: memoize this function
def get_client_list(lan_interface=None):
	"""list the availabel clients."""
	theResult = None
	try:
		theRawClientState = get_client_arp_status_raw(None, lan_interface)
		theResult = utils.compactList(
			[x for x in utils.extractIPv4(theRawClientState) if u'10.0.40.' in x]
		)
	except Exception as parseErr:
		print(str("ERROR: get_client_list"))
		print(str(type(parseErr)))
		print(str(parseErr))
		print(str(parseErr.args))
		theResult = None
	return theResult


def get_client_status(client=None, use_html=False, lan_interface=None):
	"""Generate the status"""
	theResult = None
	try:
		if lan_interface not in interfaces.INTERFACE_CHOICES:
			lan_interface = interfaces.INTERFACE_CHOICES[1]
		client_mac = get_client_mac(client, False, lan_interface)
		status_txt = get_client_sta_status(client_mac)
		if client_mac is not None:
			status_txt = None
			status_txt = get_client_sta_status(client_mac)
		if use_html is not True:
			if status_txt is not None:
				if (str("disassociated") in status_txt):
					theResult = u'disassociated'
				elif (str("associated") in status_txt):
					theResult = u'associated'
				else:
					theResult = u'UNKNOWN'
		else:
			if status_txt is not None:
				if (str("disassociated") in status_txt):
					theResult = html_generator.gen_html_td(
						html_generator.gen_html_label(u'disassociated', u'danger'),
						str(u'client_status_value_{}').format(client)
					)
				elif (str("associated") in status_txt):
					theResult = html_generator.gen_html_td(
						html_generator.gen_html_label(u'associated', u'success'),
						str(u'client_status_value_{}').format(client)
					)
				else:
					theResult = html_generator.gen_html_td(
						html_generator.gen_html_label(u'UNKNOWN', u'default'),
						str(u'client_status_value_{}').format(client)
					)
	except Exception as errcrit:
		print(str(errcrit))
		print(str(errcrit.args))
		theResult = None
	return theResult


def get_client_mac(client=None, use_html=False, lan_interface=None):
	"""Generate output of the client mac."""
	if client is None and use_html is not True:
		return None
	if lan_interface not in interfaces.INTERFACE_CHOICES:
		lan_interface = interfaces.INTERFACE_CHOICES[1]
	theResult = None
	try:
		mac_list_txt = utils.extractMACAddr(get_client_arp_status_raw(client, lan_interface))
		if use_html is not True:
			if (mac_list_txt is not None) and (len(mac_list_txt) > 0):
				theResult = str(mac_list_txt[0])
			else:
				theResult = None
		else:
			if mac_list_txt is not None and len(mac_list_txt) > 0:
				theResult = html_generator.gen_html_td(
					str(mac_list_txt[0]),
					str(u'client_status_macs_{}')
				).format(client)
			else:
				theResult = html_generator.gen_html_td(
					html_generator.gen_html_label(u'No IP', html_generator.HTML_LABEL_ROLES[3]),
					str(u'client_status_macs_{}').format(client)
				)
	except Exception as errcrit:
		print(str(errcrit))
		print(str(errcrit.args))
		theResult = None
	return theResult


def get_client_ip(client=None, use_html=False, lan_interface=None):
	"""Generate output of the client IP."""
	theResult = None
	try:
		if lan_interface not in interfaces.INTERFACE_CHOICES:
			lan_interface = interfaces.INTERFACE_CHOICES[1]
		ip_list_txt = utils.extractIPv4(get_client_arp_status_raw(client, lan_interface))
		if use_html is not True:
			if ip_list_txt is not None and len(ip_list_txt) > 0:
				theResult = str(ip_list_txt[0])
			else:
				theResult = None
		else:
			if ip_list_txt is not None and len(ip_list_txt) > 0:
				theResult = html_generator.gen_html_td(
					html_generator.gen_html_ul(ip_list_txt),
					str(u'client_status_ips_{}')
				).format(client)
			else:
				theResult = html_generator.gen_html_td(
					html_generator.gen_html_label(u'No IP', html_generator.HTML_LABEL_ROLES[3]),
					str(u'client_status_ips_{}').format(client)
				)
	except Exception as errcrit:
		print(str(errcrit))
		print(str(errcrit.args))
		theResult = None
	return theResult


def main(argv=None):
	"""The main function."""
	args = parseargs(argv)
	try:
		verbose = False
		client_interface = interfaces.INTERFACE_CHOICES[1]
		if args.verbose_mode is not None:
			verbose = args.verbose_mode
		if args.output_html is not None:
			output_html = args.output_html
		if args.interface is not None:
			client_interface = args.interface
		if args.show_all is True:
			if output_html:
				print(str(
					u'<table class=\"table table-striped\">' +
					u'<thead><th>Client</th><th>MAC</th><th>IP</th><th>Status</th></thead><tbody>'
				))
			for client_name in get_client_list(client_interface):
				print(show_client(str(client_name), verbose, output_html, client_interface))
			if output_html:
				print("</tbody></table>")
		else:
			if args.list is True:
				for client_name in get_client_list(client_interface):
					print(str(client_name))
			else:
				ip = args.ip
				print(show_client(ip, verbose, output_html, client_interface))
				return 0
			return 0
	except Exception as main_err:
		print(str("client_check_status: REALLY BAD ERROR: ACTION will not be compleated! ABORT!"))
		print(str(main_err))
		print(str(main_err.args))
	return 1


if __name__ == u'__main__':
	try:
		import sys
		exitcode = main(sys.argv[1:])
		exit(exitcode)
	except Exception as main_err:
		print(str("client_check_status: REALLY BAD ERROR: ACTION will not be compleated! ABORT!"))
		print(str(main_err))
		print(str(main_err.args))
	exit(1)

