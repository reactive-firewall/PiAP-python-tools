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

# try:
# 	from . import config as config
# except Exception:
# 	import config as config


try:
	import os
	if os.__name__ is None:
		raise NotImplementedError("OMG! We could not import the os. We're like in the matrix!")
except Exception as err:
	raise ImportError(err)
	exit(3)

try:
	import sys
	if sys.__name__ is None:
		raise NotImplementedError("OMG! We could not import the sys. We're like in the matrix!")
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


def getTimeStamp():
	"""Returns the time stamp."""
	theDate = None
	try:
		import time
		theDate = time.strftime("%a %b %d %H:%M:%S %Z %Y", time.localtime())
	except Exception:
		theDate = str("")
	return str(theDate)


def error_passing(func):
	"""Runs a function in try-except-raise"""
	import functools

	@functools.wraps(func)
	def helper_func(*args, **kwargs):
		"""Wraps a function in try-except"""
		theOutput = None
		try:
			theOutput = func(*args, **kwargs)
		except Exception as err:
			timestamp = getTimeStamp()
			logs.log(str("An error occured at {}").format(timestamp), "Error")
			logs.log(str(func), "Debug")
			baton = PiAPError(err, str("An error occured."))
			# sys.exc_clear()
			err = None
			del err
			theOutput = None
			raise baton
		return theOutput

	return helper_func


def error_breakpoint(error, context=None):
	"""Just logs the error and returns None"""
	timestamp = getTimeStamp()
	logs.log(str("An error occured at {}").format(timestamp), "Error")
	logs.log(str(context), "Debug")
	logs.log(str(type(error)), "Error")
	logs.log(str(error), "Error")
	logs.log(str((error.args)), "Error")
	if isinstance(error, PiAPError):
		logs.log(str(error.cause), "Error")
		logs.log(str(type(error.cause)), "Error")
		logs.log(str((error.args)), "Error")
	return None


def error_handling(func):
	"""Runs a function in try-except"""
	import functools

	@functools.wraps(func)
	def safety_func(*args, **kwargs):
		"""Wraps a function in try-except"""
		theOutput = None
		try:
			theOutput = func(*args, **kwargs)
		except Exception as err:
			theOutput = error_breakpoint(error=err, context=func)
			# sys.exc_clear()
			err = None
			del err
		return theOutput

	return safety_func


def bug_handling(func):
	"""Runs a function in try-except"""
	import functools

	@functools.wraps(func)
	def main_func(*args, **kwargs):
		"""Wraps a function in try-except"""
		theOutput = 5
		try:
			theOutput = func(*args, **kwargs)
		except Exception as err:
			timestamp = getTimeStamp()
			logs.log(str("An error occured at {}").format(timestamp), "CRITICAL")
			logs.log(str(func), "Debug")
			logs.log(str(type(err)), "CRITICAL")
			logs.log(str(err), "CRITICAL")
			logs.log(str((err.args)), "CRITICAL")
			logs.log(str(""), "CRITICAL")
			logs.log(str("Action will not be compleated! ABORT!"), "CRITICAL")
			logs.log(str("You found a bug. Please report this to my creator."), "CRITICAL")
			logs.log(str(""), "CRITICAL")
			# sys.exc_clear()
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
	import functools

	@functools.wraps(func)
	def warned_func(*args, **kwargs):
		"""Wraps a function in try-except"""
		theOutput = None
		try:
			theOutput = func(*args, **kwargs)
		except Exception as err:
			timestamp = getTimeStamp()
			logs.log(str("An error occured at {}").format(timestamp), "Warning")
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
	raise NotImplementedError("CRITICAL - PKU remediation main() not implemented. yet?")


if __name__ in u'__main__':
	try:
		import sys
		exit(main(sys.argv[1:]))
	except Exception:
		exit(3)


