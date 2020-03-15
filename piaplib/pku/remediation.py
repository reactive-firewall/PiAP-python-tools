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


# beware of PEP-3130 issues


# try:
# 	from . import config as config
# except Exception:
# 	import config as config


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
	if 'functools' not in sys.modules:
		import functools
	else:  # pragma: no branch
		functools = sys.modules["""functools"""]
except Exception:
	raise ImportError("functools Failed to import.")


try:
	if 'time' not in sys.modules:
		import time
	else:  # pragma: no branch
		time = sys.modules["""time"""]
except Exception:
	raise ImportError("time Failed to import.")


try:
	if 'warnings' not in sys.modules:
		import warnings
	else:  # pragma: no branch
		warnings = sys.modules["""warnings"""]
except Exception:
	raise ImportError("warnings Failed to import.")


try:
	if 'piaplib' not in sys.modules:
		raise ImportError("Pocket Book failed to import.")  # import piaplib as piaplib
	piaplib = sys.modules["""piaplib"""]
except Exception:
	raise ImportError("Pocket Book failed to import.")


try:
	for someModule in [sys, os, functools, time, warnings]:
		if someModule.__name__ is None:
			raise ImportError(str("OMG! we could not import {}. ABORT. ABORT.").format(someModule))
except Exception as err:
	raise ImportError(err)


try:
	if str("piaplib.book.logs.logs") not in sys.modules:
		from piaplib.book.logs import logs as logs
	else:
		logs = sys.modules[str("piaplib.book.logs.logs")]
except Exception:
	try:
		import piaplib.book.logs.logs as logs
	except Exception as err:
		raise ImportError(err, "Error Importing piaplib.book.logs.logs")


__prog__ = """piaplib.pku.remediation"""
"""The name of this PiAPLib tool is Pocket Knife Remediation Unit"""


class PiAPError(RuntimeError):
	"""An Error class for PiAP errors"""

	def __init__(self, cause=None, message=None):
		if cause is not None and isinstance(cause, Exception):
			super(PiAPError, self).__setattr__("""cause""", cause)
			super(PiAPError, self).__setattr__("""message""", str(cause))
		elif cause is not None and isinstance(cause, str):
			super(PiAPError, self).__setattr__("""message""", str(cause))
			super(PiAPError, self).__setattr__("""cause""", None)
		if message is not None and isinstance(message, str):
			super(PiAPError, self).__setattr__("""message""", str(message))
		super(PiAPError, self).__init__(self)

	def __len__(self):
		if self.cause is not None:
			if isinstance(self.cause, PiAPError):
				return (1 + len(self.cause))
			return 1
		return 0

	def __getitem__(self, key):
		if not isinstance(key, int):
			raise TypeError(key)
		if (self.cause is not None) and (key >= 1):
			if isinstance(self.cause, PiAPError) and key > 1:
				return self.cause[key - 1]
			return self.cause
		raise KeyError(key)

	def __getattr__(self, name):
		super(PiAPError, self).__getattr__(name)

	def __setattr__(self, name, value):
		if name == """message""":
			msgval = None
			if isinstance(value, str):
				msgval = value
			else:
				msgval = str(value)
			super(PiAPError, self).__setattr__("""message""", str(msgval))
		else:
			super(PiAPError, self).__setattr__(name, value)

	def __delattr__(self, name):
		if name == """message""":
			super(PiAPError, self).__setattr__("""message""", str(""))
		else:
			super(PiAPError, self).__delattr__(name)

	def __del__(self):
		super(PiAPError, self).__delattr__("""cause""")
		super(PiAPError, self).__delattr__("""message""")

	def __str__(self):
		return str(self.message)

	def __unicode__(self):
		return self.__str__()


def getTimeStamp():
	"""Returns the time stamp."""
	theDate = None
	try:
		theDate = time.strftime("%a %b %d %H:%M:%S %Z %Y", time.localtime())
	except Exception:
		theDate = str("")
	return str(theDate)


def suppress_warning(func):
	"""Runs a function with warnings suppressed"""

	@functools.wraps(func)
	def bad_func(*args, **kwargs):
		"""Wraps a function in try-except"""
		theOutput = None
		with warnings.catch_warnings():
			warnings.filterwarnings("ignore", message=".*", module="piaplib*")
			theOutput = func(*args, **kwargs)
		return theOutput

	return bad_func


def error_failsafe(func):
	"""Runs a function in bare try-except"""

	@functools.wraps(func)
	def unsafe_func(*args, **kwargs):
		"""Wraps a function in try-except"""
		theOutput = None
		try:
			with warnings.catch_warnings():
				warnings.filterwarnings("ignore", message=".*", module="piaplib*")
				theOutput = func(*args, **kwargs)
		except BaseException as berr:
			theOutput = None
			baton = PiAPError(berr, str("[CWE-431] An abrupt unexpected error occurred."))
			raise baton
		return theOutput

	return unsafe_func


@error_failsafe
def error_breakpoint(error, context):
	"""Just logs the error and returns None"""
	timestamp = getTimeStamp()
	logs.log(str("=" * 40), "Warning")
	logs.log(str("An error occurred at {}").format(timestamp), "Error")
	if context is not None:
		logs.log(str(context), "Debug")
	logs.log(str(type(error)), "Debug")
	logs.log(str(error), "Error")
	if isinstance(error, PiAPError):
		logs.log(str("=" * 40), "Warning")
		logs.log(str("Caused by:"), "Warning")
		logs.log(str(error.cause), "Error")
		logs.log(str(type(error.cause)), "Debug")
	else:
		if isinstance(error, Exception):
			logs.log(str((error.args)), "Error")
		else:
			logs.log(str("[CWE-209] Cause Redacted!"), "Debug")
	return None


def error_passing(func):
	"""Runs a function in try-except"""

	@functools.wraps(func)
	@suppress_warning
	def proxy_safety_func(*args, **kwargs):
		"""Wraps a function in try-except"""
		theOutput = None
		try:
			theOutput = func(*args, **kwargs)
		except Exception as err:
			theOutput = error_breakpoint(error=err, context=func)
			baton = PiAPError(err, str("An error occurred in {}.").format(str(func)))
			err = None
			del err
			raise baton
		return theOutput

	return proxy_safety_func


def error_handling(func):
	"""Runs a function in try-except"""

	@functools.wraps(func)
	@suppress_warning
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
			logs.log(str("[CWE-691] Action will not be completed! ABORT!"), "CRITICAL")
			logs.log(str("[CWE-209] You found a bug. Please report this to my creator."), "Error")
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
			logs.log(str("An exception occurred at {}").format(timestamp), "Warning")
			logs.log(str(func), "Debug")
			logs.log(str(type(err)), "Debug")
			logs.log(str(err), "Warning")
			logs.log(str((err.args)), "Debug")
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
	raise NotImplementedError("[CWE-758] - PKU remediation main() not implemented. yet?")


if __name__ in u'__main__':
	try:
		exit(main(sys.argv[1:]))
	except Exception:
		exit(3)


