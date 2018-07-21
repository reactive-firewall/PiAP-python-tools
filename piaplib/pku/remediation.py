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


# try:
# 	from . import config as config
# except Exception:
# 	import config as config


try:
	import os
	import sys
	import functools
	for someModule in [os, sys, functools]:
		if someModule.__name__ is None:
			raise ImportError(str("OMG! we could not import {}. ABORT. ABORT.").format(someModule))
except Exception as err:
	raise ImportError(err)
	exit(3)


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


class PiAPError(RuntimeError):
	"""An Error class for PiAP errors"""
	cause = None
	msg = None

	def __init__(self, cause=None, msg=None):
		if cause is not None and isinstance(cause, Exception):
			self.cause = cause
			self.msg = str(cause)
		elif cause is not None and isinstance(cause, str):
			self.msg = str(cause)
			self.cause = None
		if msg is not None and isinstance(msg, str):
			self.msg = str(msg)

	def __del__(self):
		del self.msg
		del self.cause
		del self


def getTimeStamp():
	"""Returns the time stamp."""
	theDate = None
	try:
		import time
		theDate = time.strftime("%a %b %d %H:%M:%S %Z %Y", time.localtime())
	except Exception:
		theDate = str("")
	return str(theDate)


def error_breakpoint(error, context=None):
	"""Just logs the error and returns None"""
	timestamp = getTimeStamp()
	logs.log(str("=" * 40), "Warning")
	logs.log(str("An error occurred at {}").format(timestamp), "Error")
	logs.log(str(context), "Debug")
	logs.log(str(type(error)), "Debug")
	logs.log(str(error), "Error")
	if isinstance(error, PiAPError):
		logs.log(str("=" * 40), "Warning")
		logs.log(str("Caused by:"), "Warning")
		logs.log(str(error.cause), "Error")
		logs.log(str(type(error.cause)), "Debug")
		logs.log(str((error.args)), "Error")
	else:
		logs.log(str((error.args)), "Error")
	return None


def error_passing(func):
	"""Runs a function in try-except"""

	@functools.wraps(func)
	def safety_func(*args, **kwargs):
			"""Wraps a function in try-except"""
			theOutput = None
			try:
				theOutput = func(*args, **kwargs)
			except Exception as err:
				theOutput = error_breakpoint(err, context=func)
				baton = PiAPError(err, str("An error occurred in {}.").format(str(func)))
				err = None
				del err
				raise baton
			return theOutput

	return safety_func


def error_handling(func):
	"""Runs a function in try-except"""

	@functools.wraps(func)
	def safety_func(*args, **kwargs):
		"""Wraps a function in try-except"""
		theOutput = None
		try:
			theOutput = func(*args, **kwargs)
		except Exception as err:
			theOutput = error_breakpoint(error=err, context=func)
			err = None
			del err
		return theOutput

	return safety_func


def special_error_handling(func, errorReturnValue=None):
	"""Runs a function in try-except"""
	if errorReturnValue is None:
		errorReturnValue = None
	
	@functools.wraps(func)
	def safety_func(*args, **kwargs):
		"""Wraps a function in try-except"""
		theOutput = None
		try:
			theOutput = func(*args, **kwargs)
		except Exception as err:
			error_breakpoint(error=err, context=func)
			theOutput = errorReturnValue
			err = None
			del err
		return theOutput
	
	return safety_func


def bug_handling(func):
	"""Runs a function in try-except"""

	@functools.wraps(func)
	def main_func(*args, **kwargs):
		"""Wraps a function in try-except"""
		theOutput = 5
		try:
			theOutput = func(*args, **kwargs)
		except Exception as err:
			error_breakpoint(error=err, context=func)
			logs.log(str("Action will not be completed! ABORT!"), "CRITICAL")
			logs.log(str("You found a bug. Please report this to my creator."), "CRITICAL")
			logs.log(str(""), "CRITICAL")
			err = None
			del err
			theOutput = 3
		return theOutput

	return main_func


def warning_handling(func):
	"""
		Runs a function in try-except.
		Exceptions will be logged only as warnings.
		func - a function to call.
	"""

	@functools.wraps(func)
	def warned_func(*args, **kwargs):
		"""Wraps a function in try-except"""
		theOutput = None
		try:
			theOutput = func(*args, **kwargs)
		except Exception as err:
			timestamp = getTimeStamp()
			logs.log(str("An error occurred at {}").format(timestamp), "Warning")
			logs.log(str(func), "Debug")
			logs.log(str(type(err)), "Warning")
			logs.log(str(err), "Warning")
			logs.log(str((err.args)), "Warning")
			logs.log(str(""), "Warning")
			# sys.exc_clear()
			err = None
			del err
			theOutput = None
		return theOutput

	return warned_func


@bug_handling
def main(argv=None):
	"""The Main Event makes no sense to remediation."""
	raise NotImplementedError("Warning - PKU remediation main() not implemented. yet?")


if __name__ in u'__main__':
	try:
		exit(main(sys.argv[1:]))
	except Exception:
		exit(3)


