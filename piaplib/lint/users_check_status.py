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

# Imports


try:
	import sys
	if sys.__name__ is None:
		raise ImportError("OMG! we could not import os. We're like in the matrix! ABORT. ABORT.")
except Exception as err:
	raise ImportError(err)


try:
	if 'os' not in sys.modules:
		import os
	else:  # pragma: no branch
		os = sys.modules["""os"""]
except Exception:
	raise ImportError("OS Failed to import.")


try:
	if 'argparse' not in sys.modules:
		import argparse
	else:  # pragma: no branch
		argparse = sys.modules["""argparse"""]
except Exception:
	raise ImportError("argparse Failed to import.")


try:
	if 'subprocess' not in sys.modules:
		import subprocess
	else:  # pragma: no branch
		subprocess = sys.modules["""subprocess"""]
except Exception:
	raise ImportError("subprocess Failed to import.")


try:
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


__prog__ = """piaplib.lint.check.users"""
"""The Program's name"""


__description__ = """Report the state of a given user."""
"""The Description"""


__epilog__ = """Basically ps wrapper."""
"""More Help Text."""


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
	parser.add_argument('-u', '--user', default=None, help='The user to show.')
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
	parser = utils._handleVerbosityArgs(parser, default=False)
	parser = utils._handleVersionArgs(parser)
	if calling_parser_group is None:
		calling_parser_group = parser
	return calling_parser_group


@remediation.error_handling
def parseArgs(arguments=None):
	"""Parses the CLI arguments."""
	parser = generateParser(None)
	return parser.parse_known_args(arguments)


@remediation.error_handling
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
		if not use_html:
			logs.log(str(type(cmdErr)), "Error")
			logs.log(str(cmdErr), "Error")
			logs.log(str((cmdErr.args)), "Error")
		theResult = "UNKNOWN"
	return theResult


@remediation.error_passing
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


@remediation.error_passing
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


@remediation.error_handling
@utils.memoize
def get_ps_cmd_path():
	"""Either /bin/ps or ps depending on system."""
	try:
		if (str(sys.platform).lower().startswith(str("""darwin""")) is True):
			return str("""/bin/ps""")
		else:
			return str("""ps""")
	except Exception as someErr:
		logs.log(str(type(someErr)), "Error")
		logs.log(str(someErr), "Error")
		logs.log(str((someErr.args)), "Error")
	return str("""ps""")


@remediation.error_handling
@utils.memoize
def get_sort_cmd_path():
	"""Either /usr/bin/sort or sort depending on system."""
	try:
		if (str(sys.platform).lower().startswith(str("""darwin""")) is True):
			return str("""/usr/bin/sort""")
		else:
			return str("""sort""")
	except Exception as someErr:
		logs.log(str(type(someErr)), "Error")
		logs.log(str(someErr), "Error")
		logs.log(str((someErr.args)), "Error")
	return str("""sort""")


@remediation.error_handling
def get_system_work_status_raw(user_name=None):
	"""list the raw status of system work."""
	theuserState = None
	try:
		import subprocess
		try:
			# hard-coded white-list cmds
			p1 = subprocess.Popen(
				[utils.literal_str(get_ps_cmd_path()), str("-eo"), str("user,command")],
				shell=False,
				stdout=subprocess.PIPE,
				stderr=None,
				close_fds=True
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
				stdout=subprocess.PIPE,
				close_fds=True
			)
			p3 = subprocess.Popen(
				[
					str("sed"),
					str("-E"),
					str("-e"),
					str(utils.literal_str("""s/[\\[\\(]{1}[^]]+[]\\)]{1}/SYSTEM/g"""))
				],
				shell=False,
				stdin=p2.stdout,
				stdout=subprocess.PIPE,
				close_fds=True
			)
			p4 = subprocess.Popen(
				[utils.literal_str(get_sort_cmd_path())],
				shell=False,
				stdin=p3.stdout,
				stdout=subprocess.PIPE,
				close_fds=True
			)
			p5 = subprocess.Popen(
				[utils.literal_str("""uniq""")],
				shell=False,
				stdin=p4.stdout,
				stdout=subprocess.PIPE,
				close_fds=True
			)
			p4.stdout.close()  # Allow p4 to receive a SIGPIPE if p5 exits.
			(output, stderrors) = p5.communicate()
			p3.stdout.close()  # Allow p4 to receive a SIGPIPE when p5 exits.
			p2.stdout.close()  # Allow p4 to receive a SIGPIPE when p5 exits.
			p1.stdout.close()  # Allow p4 to receive a SIGPIPE when p5 exits.
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


@remediation.error_handling
@utils.memoize
def get_w_cmd_args():
	"""Either -his or -wnh depending on system."""
	try:
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
@remediation.error_passing
def get_user_work_status_raw(user_name=None):
	"""list the raw status of user work."""
	theRawOutput = None
	try:
		import subprocess
		output = None
		stderrors = None
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
				stdout=subprocess.PIPE,
				close_fds=True
			)
			p1.stdout.close()  # Allow p1 to receive a SIGPIPE if p2 exits.
			(output, stderrors) = p2.communicate()
		except subprocess.CalledProcessError as subErr:
			p1.kill()
			p2.kill()
			subErr = None
			del(subErr)
			theRawOutput = None
		except Exception as cmdErr:
			p1.kill()
			p2.kill()
			logs.log(str(type(cmdErr)), "Error")
			logs.log(str(cmdErr), "Error")
			logs.log(str((cmdErr.args)), "Error")
			theRawOutput = None
		finally:
			p2.wait()
			p1.wait()
		if stderrors:
			output = None
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


@remediation.error_handling
def taint_name(rawtxt):
	"""check the interface arguments"""
	tainted_input = str(rawtxt).lower()
	for test_username in get_user_list():
		if tainted_input in test_username:
			return test_username
	return None


@remediation.error_passing
def get_user_list():
	"""list the available users."""
	theResult = None
	theRawuserState = get_system_work_status_raw(None)
	if theRawuserState is not None:
		theResult = format_raw_user_list(theRawuserState)
	return theResult


@remediation.error_passing
@utils.memoize
def format_raw_user_list(theRawuserState=None):
	"""formate raw list of the available users."""
	theResult = None
	try:
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
		for reserved_lines in ["UID", "message+", str("""USER""")]:
			theResult = [x for x in theResult if utils.xstr(reserved_lines) not in utils.xstr(x)]
	except Exception as parseErr:
		logs.log(
			str("{}.get_user_list: ERROR: ACTION will not be completed! ABORT!").fromat(__file__),
			"Error"
		)
		logs.log(str(type(parseErr)), "Error")
		logs.log(str(parseErr), "Error")
		logs.log(str((parseErr.args)), "Error")
		theResult = []
	return theResult


def getKnownProcessesTable():
	"""The list of known PiAP related processes to report"""
	return dict({
		u'/usr/sbin/cron': u'SYSTEM AUTOMATION',
		u'/usr/bin/dbus-daemon': u'SYSTEM',
		u'SYSTEM': u'SYSTEM',
		u'ntpd': u'TIMEKEEPING SERVICES',
		u'syslogd': u'LOGGING SERVICES',
		u'wlan1': u'NETWORK SERVICES',
		u'usb0': u'NETWORK SERVICES',
		u'eth0': u'NETWORK SERVICES',
		u'wlan0': u'NETWORK SERVICES',
		u'wlan2': u'NETWORK SERVICES',
		u'lan0': u'NETWORK SERVICES',
		u'lan1': u'NETWORK SERVICES',
		u'avahi-daemon:': u'mDNS-SERVER SERVICES',
		u'wpa_supplicant': u'WPA SERVICES',
		u'/usr/sbin/hostapd': u'AP SERVICES',
		u'/usr/sbin/afpd': u'STORAGE SERVICES',
		u'/usr/sbin/cnid_metad': u'STORAGE SERVICES',
		u'sshd:': u'CLI SERVICES',
		u'-bash:': u'CLI SERVICES',
		u'/sbin/dhcpcd': u'DHCP-CLIENT SERVICES',
		u'/usr/sbin/dnsmasq': u'DNS-DHCP-SERVER SERVICES',
		u'/lib/systemd/systemd-resolved': u'DNS-SERVER SERVICES',
		u'/usr/bin/freshclam': u'SYSTEM DEFENSE',
		u'denyhosts.py': u'SYSTEM DEFENSE',
		u'/usr/bin/rkhunter': u'SYSTEM DEFENSE',
		u'/usr/bin/nmap': u'COUNTER OFFENSE',
		u'pester_site': u'COUNTER OFFENSE',
		u'piaplib': u'PiAP SERVICES',
		u'nginx: ': u'WEB SERVICES',
		u'php-fpm': u'WEB SERVICES'
	})


@remediation.error_passing
@utils.memoize
def _util_generate_user_status_lable(input_txt, use_html=False):
	_LABEL_KEYS = {
		u'[priv]': html_generator.gen_html_label(u'Admin Task', u'danger'),
		u'AUTOMATION': html_generator.gen_html_label(u'Automation', u'info'),
		u'DEFENSE': html_generator.gen_html_label(u'Defense', u'success'),
		u'OFFENSE': html_generator.gen_html_label(u'Offense', u'primary'),
		u'NETWORK SERVICES': html_generator.gen_html_label(u'Network', u'info'),
		u'LOGGING SERVICES': html_generator.gen_html_label(u'Logging', u'info'),
		u'TIMEKEEPING SERVICES': html_generator.gen_html_label(u'Clock', u'info'),
		u'SYSTEM': html_generator.gen_html_label(u'System', u'info'),
		u'UNKNOWN': html_generator.gen_html_label(u'UNKNOWN', u'warning')
	}
	found_match = False
	if use_html is True:
		for somekey in _LABEL_KEYS.keys():
			if found_match is True:
				continue
			elif (somekey in input_txt):
				found_match = True
				input_txt = _LABEL_KEYS[somekey]
		if found_match is False:
			if u'DNS' in input_txt and u'SERVICES' in input_txt:
				input_txt = html_generator.gen_html_label(u'Local Domain', u'info')
			else:
				input_txt = html_generator.gen_html_label(input_txt, u'disabled')
	return input_txt


def get_user_status(user_name=None, use_html=False):  # noqa C901
	"""Generate the status"""
	theResult = None
	try:
		user_tty = None
		status_list = []
		t_user_name = taint_name(user_name)
		if taint_name(user_name) is not None:
			user_tty = get_user_ttys(t_user_name, False)
		status_txt = get_system_work_status_raw(t_user_name)
		if (user_tty is not None) and (str(user_tty).lower() not in str("console")):
			status_txt = get_user_work_status_raw(t_user_name)
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
						str(x).split(u' ', 1)[1:]
					) for x in status_txt.split("""\n""") if (x is not None) and (len(x) > 0)]
				)
				known_work_cases = getKnownProcessesTable()
				for theWork in theWorks:
					temp_txt = "UNKNOWN"
					if ("SYSTEM" in theWork):
						temp_txt = "SYSTEM"
					else:
						for known_case in known_work_cases.keys():
							if (known_case in theWork):
								temp_txt = known_work_cases[known_case]
					status_list.append(str(_util_generate_user_status_lable(temp_txt, use_html)))
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
				str(u'user_status_what_{}').format(t_user_name)
			)
		status_list = None
		del status_list
		status_txt = None
		del status_txt
		user_tty = None
		del user_tty
	except Exception as errcrit:
		if not use_html:
			logs.log(
				str("user_check_status.get_user_status: ERROR: ACTION will not be completed! ABORT!"),
				"Error"
			)
			logs.log(str(type(errcrit)), "Error")
			logs.log(str(errcrit), "Error")
			logs.log(str((errcrit.args)), "Error")
		theResult = None
	return theResult


def get_user_ttys(user=None, use_html=False):
	"""Generate output of the user ttys."""
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
		if not use_html:
			logs.log(
				str("user_check_status.get_user_ttys: ERROR: ACTION will not be completed! ABORT!"),
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
				if (ip_list_txt is not None) and (len(ip_list_txt) > 0):
					theResult = str(ip_list_txt[0])
				else:
					theResult = getLocalhostName()
			else:
				if (ip_list_txt is not None) and (len(ip_list_txt) > 0):
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
		if not use_html:
			logs.log(
				str("user_check_status.get_user_ip: ERROR: ACTION will not be completed! ABORT!"),
				"Error"
			)
			logs.log(str(type(errcrit)), "Error")
			logs.log(str(errcrit), "Error")
			logs.log(str((errcrit.args)), "Error")
		theResult = "UNKNOWN"
	return theResult


@remediation.bug_handling
def main(argv=None):  # noqa C901
	"""The main function."""
	(args, extras) = parseArgs(argv)
	try:
		verbose = False
		if args.verbose_mode is not None:
				verbose = (args.verbose_mode is True)
		if args.output_html is not None:
				output_html = (args.output_html is True)
		if args.show_all is True:
			output = str("")
			if output_html:
				output = str("<table class=\"table table-striped\">")
				output += str("<thead><th>User</th><th>TTYs</th><th>Host</th>")
				output += str("<th>Activity</th></thead><tbody>")
			try:
				for user_name in get_user_list():
					output += str(show_user(user_name, verbose, output_html))
					output += str("""\n""")
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
			print(output)
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

