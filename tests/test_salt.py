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


class StringsTestSuite(unittest.TestCase):
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
			from piaplib import pocket
			if pocket.__name__ is None:
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
			import re
			if re.__name__ is None:
				theResult = False
			import hashlib
			if hashlib.__name__ is None:
				theResult = False
			import hmac
			if hmac.__name__ is None:
				theResult = False
		except Exception as impErr:
			print(u'')
			print(str(type(impErr)))
			print(str(impErr))
			print(str((impErr.args)))
			print(u'')
			theResult = False
		assert theResult

	def test_before_case_saltify(self):
		"""Test before test-case saltify."""
		theResult = True
		try:
			from piaplib import keyring as keyring
			if keyring.__name__ is None:
				theResult = False
			from keyring import saltify as saltify
			if saltify.__name__ is None:
				theResult = False
		except Exception as err:
			print(u'')
			print(str(type(err)))
			print(str(err))
			print(str((err.args)))
			print(u'')
			err = None
			del err
			theResult = False
		assert theResult

	def _test_try_or_fail(f):
		""" decorator for try-except wrapping tests """
		def helper(self):
			theResult = False
			try:
				f(self)
				theResult = True
			except Exception as failErr:
				failErr = None
				del failErr
				theResult = False
			assert theResult
		return helper

	@_test_try_or_fail
	def _test_keyring_salt_test_salt(self):
		theResult = True
		try:
			from .context import piaplib
			if piaplib.__name__ is None:
				theResult = False
			from piaplib import keyring as keyring
			if keyring.__name__ is None:
				theResult = False
			from keyring import saltify as saltify
			if saltify.__name__ is None:
				theResult = False
			test_salt_one = str(
				u'7a9356011e7f6bc42105deee6d49983e0cfa7650c7fce5d' +
				u'5d3b19aacca91605199ee017707f627087f8376143f368b17ed927d918eecfe100a7b1b6e39dd3c8a'
			)
			theResult = (str(saltify.saltify("Test Message", "testSalt")) is str(test_salt_one))
			del test_salt_one
		except Exception as impErr:
			print(u'')
			print(str(type(impErr)))
			print(str(impErr))
			print(str((impErr.args)))
			print(u'')
			theResult = False
		assert theResult


if __name__ == '__main__':
	unittest.main()
