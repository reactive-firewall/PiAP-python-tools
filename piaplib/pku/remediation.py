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


def getTimeStamp():
	"""Returns the time stamp."""
	theDate = None
	try:
		import time
		theDate = time.strftime("%a %b %d %H:%M:%S %Z %Y", time.localtime())
	except Exception:
		theDate = str("")
	return str(theDate)


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
			print(str("{}: {}").format(str(timestamp), str(func)))
			print(str("{}: {}").format(str(timestamp), str(type(err))))
			print(str("{}: {}").format(str(timestamp), str(err)))
			print(str("{}: {}").format(str(timestamp), str(err.args)))
			print(str(""))
			err = None
			del err
			theOutput = None
		return theOutput

	return helper_func


@error_handling
def main(argv=None):
	"""The Main Event makes no sense to utils."""
	raise NotImplementedError("CRITICAL - PKU Uitls main() not implemented. yet?")
	exit(3)


if __name__ in u'__main__':
	try:
		import sys
		main(sys.argv[1:])
	except Exception:
		exit(3)


