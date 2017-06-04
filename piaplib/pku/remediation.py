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
	from piaplib.pku.logs import logs as logs
except Exception:
	try:
		from .logs import logs as logs
	except Exception as err:
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		print("")
		raise ImportError("Error Importing logs")


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
			tb = sys.exc_info()[2]
			timestamp = getTimeStamp()
			print(str("{}: {}").format(str(timestamp), str(func)))
			sys.exc_clear()
			err = None
			del err
			raise RuntimeError("Passing error up").with_traceback(tb)
			theOutput = None
		return theOutput

	return helper_func


def error_handling(func):
	"""Runs a function in try-except"""
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
			logs.log(str(func), "Error")
			logs.log(str(type(err)), "Error")
			logs.log(str(err), "Error")
			logs.log(str(err.args), "Error")
			logs.log(str(""), "Critical")
			sys.exc_clear()
			err = None
			del err
			theOutput = None
		return theOutput

	return helper_func


@error_handling
def main(argv=None):
	"""The Main Event makes no sense to utils."""
	raise NotImplementedError("CRITICAL - PKU remediation main() not implemented. yet?")
	exit(3)


if __name__ in u'__main__':
	try:
		import sys
		main(sys.argv[1:])
	except Exception:
		exit(3)


