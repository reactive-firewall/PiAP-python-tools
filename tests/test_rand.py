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

import unittest

try:
	try:
		import sys
		import os
		import functools
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
		raise ImportError(str("Test module failed completely."))
except Exception:
	raise ImportError("Failed to import test context")


def _test_try_or_fail(func):
	""" decorator for try-except wrapping tests """
	@functools.wraps(func)
	def helper_func(*args, **kwargs):
		theResult = False
		try:
			func(*args, **kwargs)
			theResult = True
		except Exception as failErr:
			print(str(""))
			print(str(type(failErr)))
			print(str(failErr))
			print(str((failErr.args)))
			print(str(""))
			failErr = None
			del failErr
			theResult = False
		return theResult
	return helper_func


class SaltTestSuite(unittest.TestCase):
	"""Basic test cases."""

	def test_absolute_truth_and_meaning(self):
		"""Insanitty Test."""
		assert True

	def test_syntax(self):
		"""Test case importing code."""
		theResult = False
		try:
			from .context import piaplib
			if piaplib.__name__ is None:
				theResult = False
			from piaplib import keyring
			if keyring.__name__ is None:
				theResult = False
			theResult = True
		except Exception as impErr:
			print(str(type(impErr)))
			print(str(impErr))
			theResult = False
		assert theResult

	def test_actual_depends(self):
		"""Test case importing depends."""
		theResult = True
		try:
			import sys
			if sys.__name__ is None:
				theResult = False
			import os
			if os.__name__ is None:
				theResult = False
		except Exception as impErr:
			print(str(""))
			print(str(type(impErr)))
			print(str(impErr))
			print(str((impErr.args)))
			print(str(""))
			theResult = False
		assert theResult

	def test_before_case_rand(self):
		"""Test before test-case saltify."""
		theResult = True
		try:
			from piaplib import keyring as keyring
			if keyring.__name__ is None:
				theResult = False
			from keyring import rand as rand
			if rand.__name__ is None:
				theResult = False
		except Exception as err:
			print(str(""))
			print(str(type(err)))
			print(str(err))
			print(str((err.args)))
			print(str(""))
			err = None
			del err
			theResult = False
		assert theResult

	def test_keyring_rand_test(self):
		theResult = True
		try:
			temp = None
			from .context import piaplib
			if piaplib.__name__ is None:
				theResult = False
			from piaplib import keyring as keyring
			if keyring.__name__ is None:
				theResult = False
			from keyring import rand as rand
			if rand.__name__ is None:
				theResult = False
			temp = rand.rand(256)
			if temp is not None:
				theResult = True
			del temp
		except Exception as impErr:
			print(str(""))
			print(str(type(impErr)))
			print(str(impErr))
			print(str((impErr.args)))
			print(str(""))
			theResult = False
		assert theResult


if __name__ == '__main__':
	unittest.main()
