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
	if utils.__name__ is None:
		raise ImportError("Failed to open PKU Utils")
except Exception as importErr:
	print(str(importErr))
	print(str(importErr.args))
	importErr = None
	del importErr
	raise ImportError("Failed to import " + str(__file__))
	exit(255)


__prog__ = str("""clients_check_status.py""")
"""The Program's name"""


HTML_LABEL_ROLES = [u'default', u'success', u'info', u'warning', u'danger']
"""the types of labels that can be used in html output"""


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
		parser.error(str(parseErr))
	return theResult


def show_client(client_ip=None, is_verbose=False, use_html=False):
	"""show the given client."""
	try:
		if use_html:
			format_pattern = u'{}{}{}{}'
		else:
			format_pattern = u'{} {} {} {}'
		theResult = format_pattern.format(
			get_client_name(client_ip, use_html),
			get_client_mac(client_ip, use_html),
			get_client_ip(client_ip, use_html),
			get_client_status(get_client_ip(client_ip, False), use_html)
		)
		if use_html:
			theResult = gen_html_tr(theResult, str(u'client_status_row_{}').format(client_ip))
	except Exception as cmdErr:
		print(str(cmdErr))
		print(str(cmdErr.args))
		theResult = "UNKNOWN"
	return theResult


def get_client_name(client_ip=None, use_html=False):
	if client_ip is None:
		return None
	if use_html is not True:
		return get_client_arp_status_raw(client_ip).split(u' ', 1)[0]
	else:
		client = str(get_client_name(client_ip, False))
		return gen_html_td(client, str(u'client_status_{}').format(client))


# TODO: move this function to utils
def extractRegexPattern(theInput_Str, theInputPattern):
	import re
	sourceStr = str(theInput_Str)
	prog = re.compile(theInputPattern)
	theList = prog.findall(sourceStr)
	return theList


def extractMACAddr(theInputStr):
	"""Extract the MAC addresses from a string."""
	return extractRegexPattern(
		theInputStr,
		"(?:(?:[[:print:]]*){0,1}(?P<Mac>(?:(?:[0-9a-fA-F]{1,2}[\:]{1}){5}" +
		"(?:[0-9a-fA-F]{1,2}){1}){1})+(?:[[:print:]]*){0,1})+"
	)


def extractIPv4(theInputStr):
	"""Extract the Ipv4 addresses from a string. Simple x.x.x.x matching, no checks."""
	return extractRegexPattern(
		theInputStr,
		"(?:(?:[[:print:]]*){0,1}(?P<IP>(?:[12]?[0-9]?[0-9]{1}[\.]{1}){3}" +
		"(?:[12]?[0-9]?[0-9]{1}){1}){1}(?:[[:print:]]*){0,1})+"
	)


def extractIPAddr(theInputStr):
	"""Extract the Ipv4 addresses from a string. Simple x.x.x.x matching, no checks."""
	return extractRegexPattern(
		theInputStr,
		"(?:(?:[[:print:]]*){0,1}(?P<IP>(?:[12]?[0-9]?[0-9]{1}[\.]{1}){3}" +
		"(?:[12]?[0-9]?[0-9]{1}){1}){1}(?:[/]{1}){1}(?:[[:print:]]*){0,1})+"
	)


# TODO: memoize this function
def get_client_sta_status_raw():
	"""list the raw status of client sta."""
	arguments = [u'/opt/PiAP/hostapd_actions/clients']
	theRawClientState = None
	try:
		import subprocess
		try:
			theRawClientState = subprocess.check_output(arguments, stderr=subprocess.STDOUT)
		except subprocess.CalledProcessError as subErr:
			subErr = None
			del subErr
			theRawClientState = None
		except Exception as cmdErr:
			# print(str(cmdErr))
			# print(str(cmdErr.args))
			cmdErr = None
			del cmdErr
			theRawClientState = None
	except Exception as importErr:
		print(str(importErr))
		print(str(importErr.args))
		theRawClientState = None
	return theRawClientState


# TODO: memoize this function
def get_client_arp_status_raw(client_ip=None):
	"""list the raw status of client sta."""
	arguments = [u'arp', u'-i', u'wlan0', u'-a']
	theRawClientState = None
	try:
		import subprocess
		try:
			theRawClientState = subprocess.check_output(arguments, stderr=subprocess.STDOUT)
			if (client_ip is not None):
				if (theRawClientState is not None) and (len(theRawClientState) > 0):
					lines = [x for x in theRawClientState.splitlines() if client_ip in x]
					theRawClientState = u''
					for line in lines:
						theRawClientState = str(u'{}{}\n').format(theRawClientState, line)
					del lines
				else:
					theRawClientState = theRawClientState.split(u'\n')
			else:
				theRawClientState = theRawClientState.split(u'\n')
		except subprocess.CalledProcessError as subErr:
			subErr = None
			del subErr
			theRawClientState = None
		except Exception as cmdErr:
			print(str(cmdErr))
			print(str(cmdErr.args))
			theRawClientState = None
	except Exception as importErr:
		print(str(importErr))
		print(str(importErr.args))
		theRawClientState = None
	return theRawClientState


# TODO: memoize this function
def get_client_sta_status(client=None):
	"""list the raw status of client sta."""
	theClientState = u'disassociated'
	if client is not None:
		try:
			if client in extractMACAddr(get_client_sta_status_raw()):
				theClientState = u'associated'
		except Exception as cmdErr:
			print(str(cmdErr))
			print(str(cmdErr.args))
			theClientState = u'Unknown'
	return theClientState


def compactList(list, intern_func=None):
	if intern_func is None:
		def intern_func(x):
			return x
	seen = {}
	result = []
	for item in list:
		marker = intern_func(item)
		if marker in seen:
			continue
		seen[marker] = 1
		result.append(item)
	return result


# TODO: memoize this function
def get_client_list():
	"""list the available clients."""
	theResult = None
	try:
		theRawClientState = get_client_arp_status_raw(None)
		theResult = compactList([x for x in extractIPv4(theRawClientState) if u'10.0.40.' in x])
	except Exception as parseErr:
		print(str(parseErr))
		print(str(parseErr.args))
		theResult = None
	return theResult


def get_client_status(client=None, use_html=False):
	"""Generate the status"""
	theResult = None
	try:
		client_mac = get_client_mac(client, False)
		status_txt = get_client_sta_status(client_mac)
		status_txt = None
		if client_mac is not None:
			status_txt = get_client_sta_status(client_mac)
		if use_html is not True:
			if status_txt is not None:
				if (" DOWN" in status_txt):
					theResult = u'disassociated'
				elif (" UP" in status_txt):
					theResult = u'associated'
				else:
					theResult = u'UNKNOWN'
		else:
			if status_txt is not None:
				if (u' DOWN' in status_txt):
					theResult = gen_html_td(
						gen_html_label(u'disassociated', u'danger'),
						str(u'client_status_value_{}').format(client)
					)
				elif (u' UP' in status_txt):
					theResult = gen_html_td(
						gen_html_label(u'associated', u'success'),
						str(u'client_status_value_{}').format(client)
					)
				else:
					theResult = gen_html_td(
						gen_html_label(u'UNKNOWN', u'default'),
						str(u'client_status_value_{}').format(client)
					)
	except Exception as errcrit:
		print(str(errcrit))
		print(str(errcrit.args))
		theResult = None
	return theResult


def get_client_mac(client=None, use_html=False):
	"""Generate output of the client mac."""
	if client is None and use_html is not True:
		return None
	theResult = None
	try:
		mac_list_txt = extractMACAddr(get_client_arp_status_raw(client))
		if use_html is not True:
			if (mac_list_txt is not None) and (len(mac_list_txt) > 0):
				theResult = str(mac_list_txt[0])
			else:
				theResult = None
		else:
			theResult = gen_html_td(
				get_client_mac(client, False),
				str(u'client_status_mac_{}').format(client)
			)
	except Exception as errcrit:
		print(str(errcrit))
		print(str(errcrit.args))
		theResult = None
	return theResult


def get_client_ip(client=None, use_html=False):
	"""Generate output of the client IP."""
	theResult = None
	try:
		ip_list_txt = extractIPv4(get_client_arp_status_raw(client))
		if use_html is not True:
			if ip_list_txt is not None and len(ip_list_txt) > 0:
				theResult = str(ip_list_txt[0])
			else:
				theResult = None
		else:
			if ip_list_txt is not None and len(ip_list_txt) > 0:
				theResult = gen_html_td(
					gen_html_ul(ip_list_txt),
					str(u'client_status_ips_{}')
				).format(client)
			else:
				theResult = gen_html_td(
					gen_html_label(u'No IP', HTML_LABEL_ROLES[3]),
					str(u'client_status_ips_{}').format(client)
				)
	except Exception as errcrit:
		print(str(errcrit))
		print(str(errcrit.args))
		theResult = None
	return theResult


# duplicate
def gen_html_tr(content=None, id=None, name=None):
	"""
	Generates a table row html tr taglet.
	param content -- The content of the tr taglet.
	param name -- The optional name of the tr taglet.
	param id -- The optional id of the tr taglet.
	Returns:
	str -- the html string of the tr taglet.
	"""
	if id is not None and has_special_html_chars(id) is not True:
		if name is not None and has_special_html_chars(name) is not True:
			return str(
				u'<tr name=\"{}\" id=\"{}\">{}</tr>'
			).format(str(name), str(id), str(content))
		else:
			return str(u'<tr id=\"{}\">{}</tr>').format(id, str(content))
	elif name is not None and has_special_html_chars(name) is not True:
		return str(u'<tr name=\"{}\">{}</tr>').format(id, str(content))
	else:
		return str(u'<tr>{}</tr>').format(str(content))


# duplicate
def has_special_html_chars(somestr=None):
	"""
	Determins if the string have special html charterers.
	param somestr -- The string to test.
	Returns:
	True -- if the string has special charterers.
	False -- otherwise.
	"""
	try:
		if somestr is None:
			return True
		badchars = [u'\"', u'\'', u'\\', u'%', u'>', u'<', u'=']
		for badchar in badchars:
			if badchar in somestr:
				return True
	except Exception as badinput:
		print(str("Bad html render string input."))
		del badinput
		return True
	return False


# duplicate
def gen_html_td(content=None, id=None, name=None):
	"""
	Generates a table data html td taglet.
	param content -- The content of the td taglet.
	param name -- The optional name of the td taglet.
	param id -- The optional id of the td taglet.
	Returns:
	str -- the html string of the td taglet.
	"""
	if id is not None and has_special_html_chars(id) is not True:
		if name is not None and has_special_html_chars(name) is not True:
			return str(
				u'<td name=\"{}\" id=\"{}\">{}</td>'
			).format(str(name), str(id), str(content))
		else:
			return str(u'<td id=\"{}\">{}</td>').format(id, str(content))
	elif name is not None and has_special_html_chars(name) is not True:
		return str(u'<td name=\"{}\">{}</td>').format(id, str(content))
	else:
		return str(u'<td>{}</td>').format(str(content))


# duplicate
def gen_html_ul(somelist=None, id=None, name=None):
	"""
	Generates a list html ul taglet.
	param somelist -- The content of the ul taglet.
	param name -- The optional name of the li taglet.
	param id -- The optional id of the li taglet.
	Returns:
	str -- the html string of the li taglet.
	"""
	if somelist is None or somelist is [None]:
		return None
	items = [gen_html_li(x) for x in somelist]
	theresult = None
	if id is not None and has_special_html_chars(id) is not True:
		if name is not None and has_special_html_chars(name) is not True:
			theresult = str(u'<ul name=\"{}\" id=\"{}\">').format(str(name), str(id))
			for item in items:
				theresult = str(theresult + item)
		else:
			theresult = str(u'<ul id=\"{}\">').format(str(id))
			for item in items:
				theresult = str(theresult + item)
	elif name is not None and has_special_html_chars(name) is not True:
		theresult = str(u'<ul name=\"{}\">').format(str(name))
		for item in items:
			theresult = str(theresult + item)
	else:
		theresult = str(u'<ul>')
		for item in items:
			theresult = str(theresult + item)
	theresult = str(theresult + u'</ul>')
	return theresult


# duplicate
def gen_html_li(item=None, id=None, name=None):
	"""
	Generates a list item html li taglet.
	param item -- The content of the li taglet.
	param name -- The optional name of the li taglet.
	param id -- The optional id of the li taglet.
	Returns:
	str -- the html string of the li taglet.
	"""
	if id is not None and has_special_html_chars(id) is not True:
		if name is not None and has_special_html_chars(name) is not True:
			return str(u'<li name=\"{}\" id=\"{}\">{}</li>').format(str(name), str(id), str(item))
		else:
			return str(u'<li id=\"{}\">{}</li>').format(id, str(item))
	elif name is not None and has_special_html_chars(name) is not True:
		return str(u'<li name=\"{}\">{}</li>').format(id, str(item))
	else:
		return str(u'<li>{}</li>').format(str(item))


# duplicate
def gen_html_label(content=None, role=HTML_LABEL_ROLES[0], id=None, name=None):
	"""
	Generates a table data html lable taglet.
	param content -- The content of the td taglet.
	param role -- The lable class of the span taglet.
	param name -- The optional name of the td taglet.
	param id -- The optional id of the td taglet.
	Returns:
	str -- the html string of the td taglet.
	"""
	# WARN:not ready for prod - check types, errors, etc,
	# security auditors: if you are reading this you found somthing
	# I forgot to make ready for prod. patches welcome.
	theResult = None
	if id is not None and has_special_html_chars(id) is not True:
		if name is not None and has_special_html_chars(name) is not True:
			theResult = str(
				u'<span class=\"lable lable-{}\" name=\"{}\" id=\"{}\">{}</span>'
			).format(role, str(name), str(id), str(content))
		else:
			theResult = str(
				u'<span class=\"lable lable-{}\" id=\"{}\">{}</span>'
			).format(role, id, str(content))
	elif name is not None and has_special_html_chars(name) is not True:
		theResult = str(
			u'<span class=\"lable lable-{}\" name=\"{}\">{}</span>'
		).format(role, id, str(content))
	else:
		theResult = str(u'<span class=\"lable lable-{}\">{}</span>').format(role, str(content))
	return theResult


def main(argv=None):
	"""The main function."""
	args = parseargs(argv)
	try:
		verbose = False
		if args.verbose_mode is not None:
			verbose = args.verbose_mode
		if args.output_html is not None:
			output_html = args.output_html
		if args.show_all is True:
			if output_html:
				print(str(
					u'<table class=\"table table-striped\">' +
					u'<thead><th>Client</th><th>MAC</th><th>IP</th><th>Status</th></thead><tbody>'
				))
			for client_name in get_client_list():
				print(show_client(client_name, verbose, output_html))
			if output_html:
				print("</tbody></table>")
		else:
			if args.list is True:
				for client_name in get_client_list():
					print(str(client_name))
			else:
				interface = args.interface
				print(show_client(interface, verbose, output_html))
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

