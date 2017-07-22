#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Pocket PiAP (Modifications)
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


# Third-party Acknowlegement:
# ..........................................
# Some code (namely: class timewith, @do_cprofile, @do_line_profile) was modified/derived from:
# https://github.com/zapier/profiling-python-like-a-boss/tree/1ab93a1154
# Copyright (c) 2013, Zapier Inc. All rights reserved.
# which was under BSD-3 Clause license.
# see https://github.com/zapier/profiling-python-like-a-boss/blob/1ab93a1154/LICENSE.md for details
# ..........................................
# NO ASSOCIATION


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
	import time
	if time.__name__ is None:
		raise NotImplementedError("OMG! We could not import time. We're like in the speed-force!")
except Exception as err:
	raise ImportError(err)
	exit(3)


try:
	import cProfile
	if cProfile.__name__ is None:
		raise NotImplementedError("OMG! We could not import cProfile. ABORT!")
except Exception as err:
	raise ImportError(err)
	exit(3)


try:
	try:
		sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), str('..'))))
		sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), str('.'))))
	except Exception as ImportErr:
		print(str(''))
		print(str(type(ImportErr)))
		print(str(ImportErr))
		print(str((ImportErr.args)))
		print(str(''))
		ImportErr = None
		del ImportErr
		raise ImportError(str("Profile module failed completely."))
except Exception:
	raise ImportError("Failed to import test profiling")


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


class timewith():
	"""Basic timer for do_time_profile."""
	def __init__(self, name=''):
		self.name = name
		self.start = time.time()

	@property
	def elapsed(self):
		return time.time() - self.start

	def checkpoint(self, name=''):
		logs.log(
			str("{timer} {checkpoint} took {elapsed} seconds").format(
				timer=self.name,
				checkpoint=name,
				elapsed=self.elapsed,
			).strip(),
			"Debug"
		)

	def __enter__(self):
		return self

	def __exit__(self, type, value, traceback):
		self.checkpoint(str("finished"))
		pass


def do_time_profile(func, timer_name="time_profile"):
	"""Runs a function with a timer"""
	import functools

	@functools.wraps(func)
	def timer_profile_func(*args, **kwargs):
		"""Wraps a function in timewith()"""
		theOutput = None
		with timewith(timer_name) as timer:
			timer.checkpoint(str("Start Timer"))
			theOutput = func(*args, **kwargs)
			timer.checkpoint(str("Stop Timer"))
		return theOutput

	return timer_profile_func


def do_cprofile(func):
	"""use built-in profiler to profile."""
	def profiled_func(*args, **kwargs):
		profile = cProfile.Profile()
		try:
			profile.enable()
			result = func(*args, **kwargs)
			profile.disable()
			return result
		finally:
			profile.print_stats()
	return profiled_func


try:  # noqa
	from line_profiler import LineProfiler

	def do_profile(follow=[]):
		def inner(func):
			def profiled_func(*args, **kwargs):
				try:
					profiler = LineProfiler()
					profiler.add_function(func)
					for f in follow:
						profiler.add_function(f)
					profiler.enable_by_count()
					return func(*args, **kwargs)
				finally:
					profiler.print_stats()
			return profiled_func
		return inner

except ImportError:
	def do_profile(follow=[]):
		"Helpful if you accidentally leave in production!"
		def inner(func):
			def nothing(*args, **kwargs):
				return func(*args, **kwargs)
			return nothing
		return inner


def main(argv=None):
	"""The Main Event makes no sense to remediation."""
	raise NotImplementedError("CRITICAL - test profiling main() not implemented. yet?")


if __name__ in u'__main__':
	try:
		exit(main(sys.argv[1:]))
	except Exception:
		exit(3)


