#! /usr/bin/env python
# -*- coding: utf-8 -*-

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

try:
	from . import html_generator as html_generator
except Exception as ImpErr:
	ImpErr = None
	del ImpErr
	import html_generator as html_generator


__prog__ = u'users_check_status'
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
			print(str("{}: REALLY BAD ERROR: ACTION will not be completed! ABORT!").format(__prog__))
			theOutput = None
		return theOutput
	return helper


def parseargs(arguments=None):
	"""Parse the arguments"""
	import argparse
	try:
		parser = argparse.ArgumentParser(
			prog=__prog__,
			description='Report the state of a given user.',
			epilog='Basically ps wrapper.'
			)
		parser.add_argument('-u', '--user', default=None, help='The user to show.')
		parser.add_argument('-l', '--list', default=False, action='store_true', help='List current users.')
		parser.add_argument('--html', dest='output_html', default=False, action='store_true', help='output HTML.')
		parser.add_argument('-a', '--all', dest='show_all', default=False, action='store_true', help='show all users.')
		the_action = parser.add_mutually_exclusive_group(required=False)
		the_action.add_argument('-v', '--verbose', dest='verbose_mode', default=False, action='store_true', help='Enable verbose mode.')
		the_action.add_argument('-q', '--quiet', dest='verbose_mode', default=False, action='store_false', help='Disable the given interface.')
		parser.add_argument('-V', '--version', action='version', version='%(prog)s 0.2.3')
		theResult = parser.parse_args(arguments)
	except Exception as parseErr:
		parser.error(str(parseErr))
	return theResult

def taint_name(rawtxt):
	"""check the interface arguments"""
	tainted_input = str(rawtxt).lower()
	for test_iface in INTERFACE_CHOICES:
		if tainted_input in test_iface:
			return test_iface
	return None

def show_user(user_name=None, is_verbose=False, use_html=False):
	"""show the given user."""
	try:
		if use_html:
			format_pattern = u'{}{}{}{}'
		else:
			format_pattern = u'{} {} {} {}'
		theResult = format_pattern.format(
				get_user_name(user_name, use_html),
				get_user_ttys(user_name, use_html),
				get_user_ip(user_name, use_html),
				get_user_status(get_user_name(user_name, False), use_html)
				)
		if use_html:
			theResult = html_generator.gen_html_tr(theResult, str(u'user_status_row_{}').format(get_user_name(user_name, False)))
	except Exception as cmdErr:
		print(str(cmdErr))
		print(str(cmdErr.args))
		theResult = "UNKNOWN"
	return theResult

def get_user_name(user_name=None, use_html=False):
	if user_name is None:
		return None
	if use_html is not True:
		temp = get_user_list()
		if literal_str(user_name) in temp:
			temp = None
			del temp
			return literal_str(user_name)
		else:
			temp = None
			del temp
			return None
	else:
		user = literal_str(get_user_name(user_name, False))
		return html_generator.gen_html_td(user, str(u'user_name_{}').format(user))

# TODO: move this function to utils
def extractRegexPattern(theInput_Str, theInputPattern):
	import re
	sourceStr = literal_str(theInput_Str)
	prog = re.compile(theInputPattern)
	theList = prog.findall(sourceStr)
	return theList


def literal_str(raw_input=None):
	try:
		if isinstance(unicode(raw_input).encode("utf-8"), basestring):
			return str(unicode(raw_input).encode("utf-8"))
		elif isinstance(raw_input, str):
			return str(unicode(raw_input.decode("utf-8")).encode("utf-8"))
	except Exception as malformErr:
		malformErr = None
		del malformErr
		return None
	return None


def compactSpace(theInput_Str):
	"""Try to remove the spaces from the input string."""
	import re
	sourceStr = str(theInput_Str)
	theList = re.sub(r' +', u' ', sourceStr)
	return theList


def extractTTYs(theInputStr):
	"""Extract the TTYs from a string."""
	return extractRegexPattern(theInputStr, """(?:(?:[[:print:]]*){0,1}(?P<TTYs>(?:(?:pts|tty|console|ptty){1}[\/]?[0-9]+){1})+(?:[[:print:]]*){0,1})+""")


def extractIPv4(theInputStr):
	"""Extract the Ipv4 addresses from a string. Simple x.x.x.x matching, no checks."""
	return extractRegexPattern(theInputStr, """(?:(?:[[:print:]]*){0,1}(?P<IP>(?:[12]?[0-9]?[0-9]{1}[\.]{1}){3}(?:[12]?[0-9]?[0-9]{1}){1}){1}(?:[[:print:]]*){0,1})+""")


def extractIPAddr(theInputStr):
	"""Extract the Ipv4 addresses from a string. Simple x.x.x.x matching, no checks."""
	return extractRegexPattern(theInputStr, """(?:(?:[[:print:]]*){0,1}(?P<IP>(?:[12]?[0-9]?[0-9]{1}[\.]{1}){3}(?:[12]?[0-9]?[0-9]{1}){1}){1}(?:[/]{1}){1}(?:[[:print:]]*){0,1})+""")


def get_system_work_status_raw(user_name=None):
	"""list the raw status of system work."""
	theuserState = None
	try:
		import subprocess
		try:
			theRawuserState = subprocess.check_output([str(get_test_path()+"/psutil.bash")], stderr=subprocess.STDOUT)
			if (theRawuserState is not None) and (len(theRawuserState) > 0):
				lines = [str(x) for x in theRawuserState.split(u'\n') if ((user_name is None) or (x.startswith(user_name) is True))]
				theuserState = str('')
				for line in lines:
					if (line is not None) and (len(line) > 0):
						theuserState = str(u'{}{}\n').format(theuserState, line)
				del lines
			else:
				theuserState = None
		except subprocess.CalledProcessError as subErr:
			theuserState = None
		except Exception as cmdErr:
			print(str(type(cmdErr)))
			print(str(cmdErr))
			print(str(cmdErr.args))
			theuserState = None
	except Exception as importErr:
		print(str(importErr))
		print(str(importErr.args))
		theuserState = None
	return theuserState

# TODO: memoize this function
def get_user_work_status_raw(user_name=None):
	"""list the raw status of user work."""
	theRawuserState = None
	try:
		import subprocess
		try:
			theRawuserState = subprocess.check_output(["w", "-his"], stderr=subprocess.STDOUT)
			if theRawuserState is not None and len(theRawuserState) > 0:
				lines = [str(x) for x in theRawuserState.split(u'\n') if ((user_name is None) or (x.startswith(user_name) is True))]
				theRawuserState = str('')
				for line in lines:
					if (line is not None) and (len(line) > 0):
						theRawuserState = str(u'{}{}\n').format(theRawuserState, compactSpace(line))
				del lines
			else:
				theRawuserState = None
		except subprocess.CalledProcessError as subErr:
			theRawuserState = None
		except Exception as cmdErr:
			print(str("user_check_status.get_user_work_status_raw: ERROR: ACTION will not be compleated! ABORT!"))
			print(str(cmdErr))
			print(str(cmdErr.args))
			theRawuserState = None
	except Exception as importErr:
		print(str(importErr))
		print(str(importErr.args))
		theRawuserState = None
	return theRawuserState

def compactList(list, intern_func=None):
   if intern_func is None:
       def intern_func(x): return x
   seen = {}
   result = []
   for item in list:
       marker = intern_func(item)
       if marker in seen: continue
       seen[marker] = 1
       result.append(item)
   return result

# TODO: memoize this function
def get_user_list():
	"""list the available users."""
	theResult = None
	try:
		theRawuserState = get_system_work_status_raw(None)
		if theRawuserState is None:
			return None
		try:
			theResult = compactList([x.split(u' ', 1)[0] for x in theRawuserState.split(u'\n') if u' ' in x])
		except Exception as cmdErr:
			print(str("user_check_status.get_user_list: ERROR: ACTION will not be compleated! DEBUG!"))
			print(str(cmdErr))
			print(str(cmdErr.args))
			theRawuserState = "FAILED"
		theResult = [x for x in theResult if u'xUIDx' not in str(u'x'+str(x)+u'x') and u'xmessage+x' not in str(u'x'+str(x)+u'x')]
	except Exception as parseErr:
		print(str("user_check_status.get_user_list: ERROR: ACTION will not be compleated! ABORT!"))
		print(str(parseErr))
		print(str(parseErr.args))
		theResult = None
	return theResult

def get_user_status(user_name=None, use_html=False):
	"""Generate the status"""
	theResult = None
	try:
		user_tty = None
		status_list = []
		if user_name is not None:
			user_tty = get_user_ttys(user_name, False)
		status_txt = get_system_work_status_raw(user_name)
		if (user_tty is not None) and (user_tty not in "console"):
			status_txt = get_user_work_status_raw(user_name)
			status_list = compactList([str(str(x).split(u' ', 4)[-1]) for x in status_txt.split(u'\n') if (x is not None) and (len(x) > 0)])
		elif status_txt is not None:
			if (str(u'root SYSTEM\n') not in status_txt):
				theWorks = compactList([str(str(x).split(u' ', 2)[-1]) for x in status_txt.split(u'\n') if (x is not None) and (len(x) > 0)])
				known_work_cases = dict({u'/usr/sbin/cron':u'SYSTEM AUTOMATION',
					u'/usr/sbin/ntpd':u'TIMEKEEPING SERVICES',
					u'/usr/sbin/rsyslogd':u'LOGGING SERVICES',
					u'wlan1':u'NETWORK SERVICES',
					u'usb0':u'NETWORK SERVICES',
					u'eth0':u'NETWORK SERVICES',
					u'wlan0':u'NETWORK SERVICES',
					u'wpa_supplicant':u'WPA SERVICES',
					u'/usr/sbin/hostapd':u'AP SERVICES',
					u'/sbin/dhcpcd':u'DHCP-CLIENT SERVICES',
					u'/usr/sbin/dnsmasq':u'DNS-DHCP-SERVER SERVICES',
					u'/usr/bin/freshclam':u'SYSTEM DEFENSE',
					u'/usr/bin/denyhosts.py':u'SYSTEM DEFENSE',
					u'/usr/bin/rkhunter':u'SYSTEM DEFENSE',
					u'/usr/bin/nmap':u'COUNTER OFFENSE',
					u'nginx: ':u'WEB SERVICES',
					u'php-fpm':u'WEB SERVICES'})
				for theWork in theWorks:
					temp_txt = u'UNKNOWN'
					if (theWork.startswith(u'SYSTEM')):
						temp_txt = "SYSTEM"
					else:
						for known_case in known_work_cases.keys():
							if (known_case in theWork):
								temp_txt = known_work_cases[known_case]
					if use_html is True:
						if (u'[priv]' in temp_txt):
							temp_txt = html_generator.gen_html_label(u'Admin Task', u'danger')
						elif (u'AUTOMATION' in temp_txt):
							temp_txt = html_generator.gen_html_label(u'Automation', u'info')
						elif (u'DEFENSE' in temp_txt):
							temp_txt = html_generator.gen_html_label(u'Defense', u'success')
						elif (u'OFFENSE' in temp_txt):
							temp_txt = html_generator.gen_html_label(u'Offense', u'default')
						elif (u'NETWORK SERVICES' in temp_txt):
							temp_txt = html_generator.gen_html_label(u'Network', u'info')
						elif (u'LOGGING SERVICES' in temp_txt):
							temp_txt = html_generator.gen_html_label(u'Logging', u'info')
						elif (u'DNS-DHCP-SERVER' in temp_txt):
							temp_txt = html_generator.gen_html_label(u'Local Domain', u'info')
						elif (u'SYSTEM' in temp_txt):
							temp_txt = html_generator.gen_html_label(u'System', u'info')
						elif (u'UNKNOWN' in temp_txt):
							temp_txt = html_generator.gen_html_label(u'UNKNOWN', u'warning')
						else:
							temp_txt = html_generator.gen_html_label(temp_txt, u'disabled')
					status_list.append(str(temp_txt))
				status_list = compactList(status_list)
			else:
				status_list = ["SYSTEM"]
		if use_html is not True:
			theResult = status_list
		else:
			theResult = html_generator.gen_html_td(html_generator.gen_html_ul(status_list), str(u'user_status_what_{}').format(user_name))
		status_list = None
		del status_list
		status_txt = None
		del status_txt
		user_tty = None
		del user_tty
	except Exception as errcrit:
		print(str("user_check_status.get_user_status: ERROR: ACTION will not be compleated! ABORT!"))
		print(str(type(errcrit)))
		print(str(errcrit))
		print(str(errcrit.args))
		theResult = None
	return theResult
	
def get_user_ttys(user=None, use_html=False):
	"""Generate output of the user mac."""
	if (user is None) and (use_html is not True):
		return None
	# otherwise
	theResult = None
	try:
		raw_data = get_user_work_status_raw(user)
		if raw_data is None:
			return u'UNKNOWN'
		tty_list_txt = extractTTYs(raw_data)
		if use_html is not True:
			if tty_list_txt is not None and len(tty_list_txt) > 0:
				theResult = str(tty_list_txt)
			else:
				theResult = u'console'
		else:
			theResult = html_generator.gen_html_td(html_generator.gen_html_ul(tty_list_txt), str(u'user_status_tty_{}').format(user))
	except Exception as errcrit:
		print(str("user_check_status.get_user_ttys: ERROR: ACTION will not be compleated! ABORT!"))
		print(str(errcrit))
		print(str(errcrit.args))
		theResult = None
	return theResult


def getLocalhostName():
	return str(u'Pocket')


def get_user_ip(user=None, use_html=False):
	"""Generate output of the user IP."""
	theResult = None
	try:
		ip_list_txt = extractIPv4(get_user_work_status_raw(user))
		if use_html is not True:
			if ip_list_txt is not None and len(ip_list_txt) > 0:
				theResult = str(ip_list_txt[0])
			else:
				theResult = getLocalhostName()
		else:
			if ip_list_txt is not None and len(ip_list_txt) > 0:
				theResult = html_generator.gen_html_td(html_generator.gen_html_ul(ip_list_txt), str(u'user_status_ips_{}').format(user))
			else:
				theResult = html_generator.gen_html_td(html_generator.gen_html_label(getLocalhostName(), u'disabled'), str(u'user_status_ips_{}').format(user))
	except Exception as errcrit:
		print(str("user_check_status.get_user_ip: ERROR: ACTION will not be compleated! ABORT!"))
		print(str(errcrit))
		print(str(errcrit.args))
		theResult = "UNKNOWN"
	return theResult


def get_test_path():
	"""list the raw status of user work."""
	theResult = u'./piaplib/lint/'
	try:
		import os
		try:
			theResult = str(os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))
			if 'lint' not in theResult:
				if 'piaplib' not in theResult:
					theResult = str(os.path.abspath(os.path.join(os.path.dirname(__file__), './piaplib/lint/.')))
				else:	
					raise NotImplementedError("ERROR: Oh NO, not sure what to do.")
				theResult = str(os.path.abspath(os.path.join(os.path.dirname(__file__), './lint/')))
		except subprocess.CalledProcessError as subErr:
			theResult = u'./piaplib/lint/'
		except Exception as cmdErr:
			print(str("user_check_status.get_user_work_status_raw: ERROR: ACTION will not be compleated! ABORT!"))
			print(str(cmdErr))
			print(str(cmdErr.args))
			theResult = u'./piaplib/lint/'
	except Exception as importErr:
		print(str(importErr))
		print(str(importErr.args))
		theResult = u'./piaplib/lint/'
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
				print("<table class=\"table table-striped\"><thead><th>User</th><th>TTYs</th><th>Host</th><th>Status</th></thead><tbody>")
			for user_name in get_user_list():
				print(show_user(user_name, verbose, output_html))
			if output_html:
				print("</tbody></table>")
		else:
			if args.list is True:
				for user_name in get_user_list():
					print(str(user_name))
			else:
				user = args.user
				print(show_user(user, verbose, output_html))
				return 0
			return 0
	except Exception as main_err:
		print(str("user_check_status: REALLY BAD ERROR: ACTION will not be compleated! ABORT!"))
		print(str(main_err))
		print(str(main_err.args))
	return 1

if __name__ == '__main__':
	try:
		import sys
		exitcode = main(sys.argv[1:])
		exit(exitcode)
	except Exception as main_err:
		print(str("user_check_status: REALLY BAD ERROR: ACTION will not be compleated! ABORT!"))
		print(str(main_err))
		print(str(main_err.args))
	exit(1)
