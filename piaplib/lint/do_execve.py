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

"""
	The PiAP equivalent of the execve call.
	while probably the point of failure for the security of PiAP, this function
	does attempt to add some security to the workflow of calling other tools.
	considerations:
	CWE-20
	CWE-242
	POSIX.1-2008 Sec. 11.2.3
	With great power comes great responsibility. This is the only command that
	should be called to run sudo. Oh and fear the CWE-20.
"""

# Imports
try:
	import os
	import os.path
	import sys
	import argparse
	import subprocess
	sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
	try:
		import piaplib as piaplib
	except Exception:
		from .. import piaplib as piaplib
	try:
		from ..pku import remediation as remediation
	except Exception:
		try:
			import pku.remediation as remediation
		except Exception:
			raise ImportError("Error Importing remediation")
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
	raise ImportError("Failed to import do_execve")
	exit(255)

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
		raise ImportError("Failed to import logs for do_execve")
		exit(255)

__prog__ = str("""do_execve.py""")
"""This tool is called do_execve.py."""


@remediation.error_handling
def taint_int(raw_input):
	"""Ensure the input makes some sense. Always expect CWE-20."""
	finalResult = False
	try:
		if raw_input is None:
			finalResult = False
		elif isinstance(utils.literal_str(raw_input), str) and int(raw_input, 10) > 2:
			finalResult = True
		elif isinstance(raw_input, int) and int(raw_input) > 2:
			finalResult = True
		else:
			finalResult = False
	except ValueError as junk:
		junk = None
		del junk
		finalResult = False
	return finalResult


@remediation.error_handling
def parseargs(tainted_arguments=None):
	"""Parse the given arguments."""
	try:
		parser = argparse.ArgumentParser(
			prog=__prog__,
			description=u'Run an untrusted plugin or command.',
			epilog=u'This is for all the dirty work. So unpoetic.'
		)
		parser.add_argument(
			'-u', '--uid',
			default=os.geteuid(), type=int,
			required=False, help='the uid to use.'
		)
		parser.add_argument(
			'-g', '--gid',
			default=os.getegid(), type=int,
			required=False, help='the gid to use.'
		)
		parser.add_argument(
			'--chroot', dest='chroot_path',
			default=None, type=str, required=False,
			help='the sandbox to play in.'
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
			action='store_false', help='Disable the verbose mode.'
		)
		parser.add_argument(
			'-c', '--cmd',
			dest='unsafe_input', action='append',
			help='The command.'
		)
		parser.add_argument(
			'-a', '--args',
			dest='unsafe_input', action='append',
			help='The command arguments.'
		)
		parser.add_argument(
			'-o', '--out',
			dest='unsafe_output', default=False, action='store_true',
			help='Return the command output.'
		)
		parser.add_argument(
			'-V', '--version',
			action='version', version=str(
				"%(prog)s {}"
			).format(str(piaplib.__version__)))
		theResult = parser.parse_args(tainted_arguments)
	except Exception as parseErr:
		try:
			parser.error(str(parseErr))
		except Exception as junk:
			junk = None
			del junk
			print(str(u'CWE-20. Mighty creator help us.'))
		finally:
			parseErr = None
			del parseErr
			theResult = False
	return theResult


@remediation.error_handling
def runUnsafeCommand(arguments, error_fd=None):
	"""Run the actual Unsafe command. Mighty creator help us."""
	theRawOutput = None
	err_fd = None
	try:
		WHTLIST = [
			str("""exit"""),
			str("""which"""),
			str("""/bin/echo""")
		]
		if arguments is None or isinstance(arguments, list) is not True:
			arguments = [WHTLIST[0], u'0']
		elif (not os.access(arguments[0], os.X_OK)) and (not utils.isWhiteListed(arguments[0], WHTLIST)):
			arguments = [WHTLIST[0], u'1']
		try:
			err_fd = subprocess.STDOUT
			if error_fd is not None:
				err_fd = error_fd
		except Exception as fdErr:
			print(str(fdErr))
			print(str(fdErr.args))
			fdErr = None
			del fdErr
			theRawOutput = None
		try:
			# print(literal_str(arguments))
			theRawOutput = subprocess.check_output(arguments, stderr=err_fd)
		except subprocess.CalledProcessError as subErr:
			print(str(subErr))
			print(str(subErr.args))
			subErr = None
			del subErr
			theRawOutput = None
		except Exception as cmdErr:
			print(str(cmdErr))
			print(str(cmdErr.args))
			cmdErr = None
			del cmdErr
			theRawOutput = None
	except Exception as importErr:
		print(str(importErr))
		print(str(importErr.args))
		importErr = None
		del importErr
		theRawOutput = None
	return theRawOutput


@remediation.error_handling
def unsafe_main(unsafe_input=None, chrootpath=None, uid=None, gid=None, passOutput=False):
	"""
	The main unsafe work.
	Fork and drop privileges try to chroot. Then run unsafe input.
	"""
	try:
		pid = os.fork()
		if pid is not None and pid > 0:
			# this is the parent process... do whatever needs to be done as the parent
			logs.log(
				str(u'OK - PiAP Launched pid {} as SANDBOXED COMMAND.').format(pid),
				"Debug"
			)
		else:
			# we are the child process... lets do that plugin thing!
			if chrootpath is not None:
				try:
					if os.geteuid() > 0:
						os.chdir(str(os.path.abspath(chrootpath)))
					else:
						os.chroot(str(os.path.abspath(chrootpath)))
				except OSError as badChrootErr:
					remediation.error_breakpoint(badChrootErr)
					badChrootErr = None
					del badChrootErr
					try:
						os.chdir(str(os.path.abspath(chrootpath)))
					except Exception:
						os.kill(pid)
						return None
			if taint_int(uid):
				os.seteuid(int(uid))
			if taint_int(gid):
				os.setegid(int(gid))
			# POSIX.1-2008 Sec. 11.2.3 - refork
			tainted_pid = os.fork()
			if tainted_pid is not None and tainted_pid > 0:
				# this is the parent process... do whatever needs to be done as the parent
				logs.log(
					str(u'OK - PiAP Launched pid {} as TAINTED COMMAND.').format(tainted_pid),
					"Warn"
				)
			else:
				tainted_output = runUnsafeCommand(unsafe_input)
				if (passOutput is not None and passOutput is True):
					return tainted_output
	except Exception as unsafeErr:
		remediation.error_breakpoint(unsafeErr)
		unsafeErr = None
		del unsafeErr
		os.abort()
	return None


@remediation.error_handling
def main(argv=None):
	"""The main event."""
	try:
		args = parseargs(argv)
		tainted_input = None
		chroot_path = str(u'/tmp')
		tainted_uid = os.geteuid()
		tainted_gid = os.getegid()
		os.umask(137)
		if args.uid is not None and taint_int(args.uid):
			tainted_uid = args.uid
		if args.gid is not None:
			tainted_gid = args.gid
		if args.chroot_path is not None:
			chroot_path = args.chroot_path
		if args.unsafe_input is not None:
			tainted_input = [utils.literal_str(x) for x in args.unsafe_input]
		if args.unsafe_output is not False:
			print(unsafe_main(tainted_input, chroot_path, tainted_uid, tainted_gid, True))
		else:
			unsafe_main(tainted_input, chroot_path, tainted_uid, tainted_gid, False)
	except Exception as mainErr:
		print(str(u'MAIN FAILED DURING UNSAFE COMMAND. ABORT.'))
		print(str(type(mainErr)))
		print(str(mainErr))
		print(str(mainErr.args))
		mainErr = None
		del mainErr
	return False


if __name__ in u'__main__':
	try:
		if (sys.argv is not None and len(sys.argv) > 1):
			unsafe_pid = main(sys.argv[1:])
		else:
			raise Exception("MAIN FAILED WHEN FOUND TO BE CWE-20 UNSAFE. ABORT.")
	except Exception as err:
		print(str(u'MAIN FAILED DURING UNSAFE COMMAND. ABORT.'))
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		err = None
		del err
		print(str(u'MAIN FAILED DURING UNSAFE COMMAND. ABORT.'))
		exit(255)
	finally:
		exit(0)

