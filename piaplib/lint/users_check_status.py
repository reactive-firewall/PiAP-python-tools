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
	import argparse
	sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
	try:
		import piaplib as piaplib
	except Exception:
		from . import piaplib as piaplib
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
	if utils.__name__ is None:
		raise ImportError("Failed to open PKU Utils")
	if html_generator.__name__ is None:
		raise ImportError("Failed to open HTML5 Pocket Lint")
except Exception as importErr:
	print(str(importErr))
	print(str(importErr.args))
	importErr = None
	del importErr
	raise ImportError("Failed to import " + str(__file__))
	exit(255)


try:
	from piaplib.book.logs import logs as logs
except Exception:
	try:
		from book.logs import logs as logs
	except Exception:
		try:
			from piaplib.book.logs import logs as logs
		except Exception:
			raise ImportError("Error Importing logs")


__prog__ = """users_check_status"""
"""The Program's name"""


def parseargs(arguments=None):
	"""Parse the arguments"""
	try:
		parser = argparse.ArgumentParser(
			prog=__prog__,
			description='Report the state of a given user.',
			epilog='Basically ps wrapper.'
		)
		parser.add_argument(
			'-u', '--user',
			default=None, help='The user to show.'
		)
		parser.add_argument(
			'-l', '--list',
			default=False, action='store_true',
			help='List current users.'
		)
		parser.add_argument(
			'--html', dest='output_html',
			default=False, action='store_true',
			help='output HTML.'
		)
		parser.add_argument(
			'-a', '--all',
			dest='show_all', default=False,
			action='store_true', help='show all users.'
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


def taint_name(rawtxt):
	"""check the interface arguments"""
	tainted_input = str(rawtxt).lower()
	for test_username in get_user_list():
		if tainted_input in test_username:
			return test_username
	return None


def show_user(user_name=None, is_verbose=False, use_html=False):
	"""show the given user."""
	theResult = None
	try:
		if use_html is True:
			format_pattern = str(u'{}{}{}{}')
		else:
			format_pattern = str(u'{} {} {} {}')
		theResult = str(format_pattern).format(
			get_user_name(user_name, use_html),
			get_user_ttys(user_name, use_html),
			get_user_ip(user_name, use_html),
			get_user_status(get_user_name(user_name, False), use_html)
		)
		if use_html:
			the_temp_Result = html_generator.gen_html_tr(
				theResult,
				str(u'user_status_row_{}').format(get_user_name(user_name, False))
			)
			theResult = utils.literal_str(the_temp_Result)
	except Exception as cmdErr:
		logs.log(str(type(cmdErr)), "Error")
		logs.log(str(cmdErr), "Error")
		logs.log(str((cmdErr.args)), "Error")
		theResult = "UNKNOWN"
	return theResult


def get_user_name(user_name=None, use_html=False):
	if user_name is None:
		return None
	if use_html is not True:
		temp = get_user_list()
		if utils.literal_str(user_name) in temp:
			temp = None
			del temp
			return utils.literal_str(user_name)
		else:
			temp = None
			del temp
			return None
	else:
		user = utils.literal_str(get_user_name(user_name, False))
		return html_generator.gen_html_td(user, str(u'user_name_{}').format(user))


def isLineForUser(someLine=None, username=None):
	"""determins if a raw output line is for a user"""
	doesMatch = False
	try:
		doesMatch = utils.isLineForMatch(someLine, username)
	except Exception as matchErr:
		logs.log(str(type(matchErr)), "Error")
		logs.log(str(matchErr), "Error")
		logs.log(str((matchErr.args)), "Error")
		matchErr = None
		del matchErr
		doesMatch = False
	return doesMatch


def get_system_work_status_raw(user_name=None):
	"""list the raw status of system work."""
	theuserState = None
	try:
		import subprocess
		try:
			# hard-coded white-list cmds
			p1 = subprocess.Popen(
				[str("ps"), str("-eo"), str("user,command")],
				shell=False,
				stdout=subprocess.PIPE,
				stderr=None
			)
			p2 = subprocess.Popen(
				[
					str("tr"),
					str("-s"),
					utils.literal_str("""' '"""),
					utils.literal_str("""' '""")
				],
				shell=False,
				stdin=p1.stdout,
				stdout=subprocess.PIPE
			)
			p3 = subprocess.Popen(
				[
					str("sed"),
					str("-E"),
					str("-e"),
					str(utils.literal_str("""s/[\[\(]{1}[^]]+[]\)]{1}/SYSTEM/g"""))
				],
				shell=False,
				stdin=p2.stdout,
				stdout=subprocess.PIPE
			)
			p4 = subprocess.Popen(
				[utils.literal_str("""sort""")],
				shell=False,
				stdin=p3.stdout,
				stdout=subprocess.PIPE
			)
			p5 = subprocess.Popen(
				[utils.literal_str("""uniq""")],
				shell=False,
				stdin=p4.stdout,
				stdout=subprocess.PIPE
			)
			p4.stdout.close()  # Allow p4 to receive a SIGPIPE if p5 exits.
			(output, stderrors) = p5.communicate()
			if (isinstance(output, bytes)):
				output = output.decode('utf8')
			if (output is not None) and (len(output) > 0):
				lines = [
					utils.literal_str(x) for x in output.splitlines() if isLineForUser(x, user_name)
				]
				theuserState = str("")
				for line in lines:
					if (line is not None) and (len(line) > 0):
						theuserState = str("{}{}\n").format(str(theuserState), str(line))
				del lines
			else:
				theuserState = None
		except subprocess.CalledProcessError as subErr:
			subErr = None
			del subErr
			theuserState = None
		except Exception as cmdErr:
			logs.log(str(type(cmdErr)), "Error")
			logs.log(str(cmdErr), "Error")
			logs.log(str((cmdErr.args)), "Error")
			theuserState = None
	except Exception as importErr:
		logs.log(str(importErr), "Warning")
		logs.log(str((importErr.args)), "Warning")
		theuserState = None
	return theuserState


@utils.memoize
def get_w_cmd_args():
	"""Either -his or -wnh depending on system."""
	try:
		import sys
		if (str(sys.platform).lower().startswith(str("""darwin""")) is True):
			return str("""-hi""")
		else:
			return str("""-his""")
	except Exception as someErr:
		logs.log(str(type(someErr)), "Error")
		logs.log(str(someErr), "Error")
		logs.log(str((someErr.args)), "Error")
	return str("""-h""")


# TODO: memoize this function
def get_user_work_status_raw(user_name=None):
	"""list the raw status of user work."""
	theRawOutput = None
	try:
		import subprocess
		output = None
		try:
			# hard-coded white-list cmds
			p1 = subprocess.Popen(
				[str("w"), str(get_w_cmd_args())],
				shell=False,
				stdout=subprocess.PIPE,
				stderr=None
			)
			p2 = subprocess.Popen(
				[
					str("tr"),
					str("-s"),
					utils.literal_str("""' '"""),
					utils.literal_str("""' '""")
				],
				shell=False,
				stdin=p1.stdout,
				stdout=subprocess.PIPE
			)
			p1.stdout.close()  # Allow p1 to receive a SIGPIPE if p2 exits.
			(output, stderrors) = p2.communicate()
		except subprocess.CalledProcessError as subErr:
			subErr = None
			del(subErr)
			theRawOutput = None
		except Exception as cmdErr:
			logs.log(str(type(cmdErr)), "Error")
			logs.log(str(cmdErr), "Error")
			logs.log(str((cmdErr.args)), "Error")
			theRawOutput = None
		if (isinstance(output, bytes)):
			output = output.decode('utf8')
		if output is not None and len(output) > 0:
			lines = [
				utils.literal_str(x) for x in output.splitlines() if isLineForUser(x, user_name)
			]
			theRawOutput = str("")
			for line in lines:
				if (line is not None) and (len(line) > 0):
					theRawOutput = str("{}{}\n").format(str(theRawOutput), str(line))
			del(lines)
		else:
			theRawOutput = None
	except Exception as importErr:
		logs.log(str(type(importErr)), "Warning")
		logs.log(str(importErr), "Warning")
		logs.log(str((importErr.args)), "Warning")
		theRawOutput = None
	return theRawOutput


# TODO: memoize this function
def get_user_list():
	"""list the available users."""
	theResult = None
	try:
		theRawuserState = get_system_work_status_raw(None)
		if theRawuserState is None:
			theResult = []
			return theResult
		try:
			theResult = utils.compactList(
				[str(str(x).split(u' ', 1)[0]) for x in theRawuserState.split(u'\n') if (u' ' in x)]
			)
		except Exception as cmdErr:
			logs.log(str(type(cmdErr)), "Error")
			logs.log(str(cmdErr), "Error")
			logs.log(str((cmdErr.args)), "Error")
			theResult = []
		# while one line is probably faster here, two is more readable
		for reserved_lines in ["UID", "message+"]:
			theResult = [x for x in theResult if utils.xstr(reserved_lines) not in utils.xstr(x)]
	except Exception as parseErr:
		logs.log(
			str("user_check_status.get_user_list: ERROR: ACTION will not be compleated! ABORT!"),
			"Error"
		)
		logs.log(str(type(parseErr)), "Error")
		logs.log(str(parseErr), "Error")
		logs.log(str((parseErr.args)), "Error")
		theResult = []
	return theResult


def get_user_status(user_name=None, use_html=False):  # noqa C901
	"""Generate the status"""
	theResult = None
	try:
		user_tty = None
		status_list = []
		if user_name is not None:
			user_tty = get_user_ttys(user_name, False)
		status_txt = get_system_work_status_raw(user_name)
		if (user_tty is not None) and (str(user_tty).lower() not in str("console")):
			status_txt = get_user_work_status_raw(user_name)
			if status_txt is None:
				status_list = ["UNKNOWN"]
			else:
				status_list = utils.compactList(
					[str(
						str(x).split(u' ', 4)[-1]
					) for x in status_txt.split(u'\n') if (x is not None) and (len(x) > 0)]
				)
		elif status_txt is not None:
			if (str("root SYSTEM\n") not in status_txt):
				theWorks = utils.compactList(
					[str(
						str(x).split(u' ', 2)[-1]
					) for x in status_txt.split(u'\n') if (x is not None) and (len(x) > 0)]
				)
				known_work_cases = dict({
					u'/usr/sbin/cron': u'SYSTEM AUTOMATION',
					u'/usr/sbin/ntpd': u'TIMEKEEPING SERVICES',
					u'/usr/sbin/rsyslogd': u'LOGGING SERVICES',
					u'wlan1': u'NETWORK SERVICES',
					u'usb0': u'NETWORK SERVICES',
					u'eth0': u'NETWORK SERVICES',
					u'wlan0': u'NETWORK SERVICES',
					u'wlan2': u'NETWORK SERVICES',
					u'wpa_supplicant': u'WPA SERVICES',
					u'/usr/sbin/hostapd': u'AP SERVICES',
					u'/sbin/dhcpcd': u'DHCP-CLIENT SERVICES',
					u'/usr/sbin/dnsmasq': u'DNS-DHCP-SERVER SERVICES',
					u'/usr/bin/freshclam': u'SYSTEM DEFENSE',
					u'/usr/bin/denyhosts.py': u'SYSTEM DEFENSE',
					u'/usr/bin/rkhunter': u'SYSTEM DEFENSE',
					u'/usr/bin/nmap': u'COUNTER OFFENSE',
					u'piaplib': u'PiAP SERVICES',
					u'nginx: ': u'WEB SERVICES',
					u'php-fpm': u'WEB SERVICES'
				})
				for theWork in theWorks:
					temp_txt = "UNKNOWN"
					if ("SYSTEM" in theWork):
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
							temp_txt = html_generator.gen_html_label(u'Offense', u'primary')
						elif (u'NETWORK SERVICES' in temp_txt):
							temp_txt = html_generator.gen_html_label(u'Network', u'info')
						elif (u'LOGGING SERVICES' in temp_txt):
							temp_txt = html_generator.gen_html_label(u'Logging', u'info')
						elif (u'TIMEKEEPING SERVICES' in temp_txt):
							temp_txt = html_generator.gen_html_label(u'Clock', u'info')
						elif (u'DNS-DHCP-SERVER' in temp_txt):
							temp_txt = html_generator.gen_html_label(u'Local Domain', u'info')
						elif (u'SYSTEM' in temp_txt):
							temp_txt = html_generator.gen_html_label(u'System', u'info')
						elif (u'UNKNOWN' in temp_txt):
							temp_txt = html_generator.gen_html_label(u'UNKNOWN', u'warning')
						else:
							temp_txt = html_generator.gen_html_label(temp_txt, u'disabled')
					status_list.append(str(temp_txt))
				status_list = utils.compactList(status_list)
			else:
				if use_html is True:
					status_list = [str(html_generator.gen_html_label(u'System', u'info'))]
				else:
					status_list = ["SYSTEM"]
		if use_html is not True:
			theResult = status_list
		else:
			theResult = html_generator.gen_html_td(
				html_generator.gen_html_ul(status_list),
				str(u'user_status_what_{}').format(user_name)
			)
		status_list = None
		del status_list
		status_txt = None
		del status_txt
		user_tty = None
		del user_tty
	except Exception as errcrit:
		logs.log(
			str("user_check_status.get_user_status: ERROR: ACTION will not be compleated! ABORT!"),
			"Error"
		)
		logs.log(str(type(errcrit)), "Error")
		logs.log(str(errcrit), "Error")
		logs.log(str((errcrit.args)), "Error")
		theResult = None
	return theResult


def get_user_ttys(user=None, use_html=False):
	"""Generate output of the user mac."""
	if (user is None) and (use_html is not True):
		return None
	elif (user is None) and (use_html is True):
		return html_generator.gen_html_label(u'UNKNOWN', u'warning')
	# otherwise
	theResult = None
	try:
		raw_data = get_user_work_status_raw(user)
		if raw_data is None:
			return u'UNKNOWN'
		tty_list_txt = utils.extractTTYs(raw_data)
		if use_html is not True:
			if tty_list_txt is not None and len(tty_list_txt) > 0:
				theResult = str(tty_list_txt)
			else:
				theResult = u'console'
		else:
			theResult = html_generator.gen_html_td(
				html_generator.gen_html_ul(tty_list_txt),
				str(u'user_status_tty_{}').format(user)
			)
	except Exception as errcrit:
		logs.log(
			str("user_check_status.get_user_ttys: ERROR: ACTION will not be compleated! ABORT!"),
			"Error"
		)
		logs.log(str(type(errcrit)), "Error")
		logs.log(str(errcrit), "Error")
		logs.log(str((errcrit.args)), "Error")
		theResult = None
	return theResult


def getLocalhostName():
	"""What is my name?"""
	return str(u'Pocket')


def get_user_ip(user=None, use_html=False):
	"""Generate output of the user IP."""
	theResult = None
	try:
		raw_data = get_user_work_status_raw(user)
		if raw_data is not None:
			ip_list_txt = utils.extractIPv4(raw_data)
			if use_html is not True:
				if ip_list_txt is not None and len(ip_list_txt) > 0:
					theResult = str(ip_list_txt[0])
				else:
					theResult = getLocalhostName()
			else:
				if ip_list_txt is not None and len(ip_list_txt) > 0:
					theResult = html_generator.gen_html_td(
						html_generator.gen_html_ul(ip_list_txt),
						str(u'user_status_ips_{}').format(user)
					)
				else:
					theResult = html_generator.gen_html_td(
						html_generator.gen_html_label(getLocalhostName(), u'disabled'),
						str(u'user_status_ips_{}').format(user)
					)
		else:
			if (use_html is True):
				theResult = html_generator.gen_html_label(u'UNKNOWN', u'warning')
			else:
				theResult = "UNKNOWN"
	except Exception as errcrit:
		logs.log(
			str("user_check_status.get_user_ip: ERROR: ACTION will not be compleated! ABORT!"),
			"Error"
		)
		logs.log(str(type(errcrit)), "Error")
		logs.log(str(errcrit), "Error")
		logs.log(str((errcrit.args)), "Error")
		theResult = "UNKNOWN"
	return theResult


def main(argv=None):  # noqa C901
	"""The main function."""
	args = parseargs(argv)
	try:
		verbose = False
		if args.verbose_mode is not None:
				verbose = (args.verbose_mode is True)
		if args.output_html is not None:
				output_html = (args.output_html is True)
		if args.show_all is True:
			if output_html:
				print(
					"<table class=\"table table-striped\">" +
					"<thead><th>User</th><th>TTYs</th><th>Host</th><th>Activity</th></thead><tbody>"
				)
			try:
				for user_name in get_user_list():
					print(show_user(user_name, verbose, output_html))
			except Exception as content_err:
				if output_html:
					# might need to add error alert here
					content_err = None
					del(content_err)
				else:
					logs.log(str(type(content_err)), "Error")
					logs.log(str(content_err), "Error")
					logs.log(str((content_err.args)), "Error")
					content_err = None
					del(content_err)
			if output_html:
				print("</tbody></table>")
		else:
			if args.list is True:
				for user_name in get_user_list():
					print(user_name)
			else:
				user = args.user
				print(show_user(user, verbose, output_html))
				return 0
			return 0
	except Exception as main_err:
		logs.log(str(
			"{}: REALLY BAD ERROR: ACTION will not be completed! ABORT!"
		).format(__prog__), "Error")
		logs.log(str(main_err), "Error")
		logs.log(str((main_err.args)), "Error")
	return 1


if __name__ == '__main__':
	try:
		import sys
		exitcode = main(sys.argv[1:])
		exit(exitcode)
	except Exception as main_err:
		logs.log(str(
			"{}: REALLY BAD ERROR: ACTION will not be completed! ABORT!"
		).format(__prog__), "Error")
		logs.log(str(main_err), "Error")
		logs.log(str((main_err.args)), "Error")
	exit(1)

