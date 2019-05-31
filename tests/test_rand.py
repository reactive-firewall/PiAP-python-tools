#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Pocket PiAP
# ......................................................................
# Copyright (c) 2017-2019, Kendrick Walls
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


class RandTestSuite(unittest.TestCase):
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
		"""Test before test-case rand."""
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
		"""Test generate random output test-case."""
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

	def test_keyring_rand_int_test(self):
		"""Test generate random output test-case."""
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
			temp = rand.randInt(256)
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

	def test_keyring_rand_bad_min_test(self):
		"""Test generate random output test-case."""
		theResult = True
		try:
			from .context import piaplib
			if piaplib.__name__ is None:
				theResult = False
			from piaplib import keyring as keyring
			if keyring.__name__ is None:
				theResult = False
			from keyring import rand as rand
			if rand.__name__ is None:
				theResult = False
			self.assertIsNotNone(rand.randInt(32, None, 512))
			self.assertIsNotNone(rand.randInt(32, -256, 512))
			self.assertIsNotNone(rand.randInt(32, 0, 512))
			self.assertIsNotNone(rand.randInt(32, 256, 512))
		except Exception as impErr:
			print(str(""))
			print(str(type(impErr)))
			print(str(impErr))
			print(str((impErr.args)))
			print(str(""))
			theResult = False
		assert theResult

	def test_keyring_rand_bad_max_test(self):
		"""Test generate random output test-case."""
		theResult = True
		try:
			from .context import piaplib
			if piaplib.__name__ is None:
				theResult = False
			from piaplib import keyring as keyring
			if keyring.__name__ is None:
				theResult = False
			from keyring import rand as rand
			if rand.__name__ is None:
				theResult = False
			self.assertIsNotNone(rand.randInt(32, 0, None))
			self.assertIsNotNone(rand.randInt(32, 50, 12))
			self.assertIsNotNone(rand.randInt(32, 0, -256))
			self.assertIsNotNone(rand.randInt(32, 1, 512))
		except Exception as impErr:
			print(str(""))
			print(str(type(impErr)))
			print(str(impErr))
			print(str((impErr.args)))
			print(str(""))
			theResult = False
		assert theResult

	def test_keyring_rand_bool_test(self):
		"""Test generate random output test-case."""
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
			temp = rand.randBool(256)
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

	def test_keyring_rand_str_test(self):
		"""Test generate random output test-case."""
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
			temp = rand.randStr(256)
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

	def test_keyring_rand_Char_test(self):
		"""Test generate random output test-case."""
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
			temp = rand.randChar(256)
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

	def test_keyring_rand_bad_count_test(self):
		"""Test generate random output test-case."""
		theResult = True
		try:
			from .context import piaplib
			if piaplib.__name__ is None:
				theResult = False
			from piaplib import keyring as keyring
			if keyring.__name__ is None:
				theResult = False
			from keyring import rand as rand
			if rand.__name__ is None:
				theResult = False
			the_list = [
				rand.fastrandInt,
				rand.randInt,
				rand.rand,
				rand.randBool,
				rand.randStr,
				rand.randChar,
				rand.randPW,
				rand.randSSID,
				rand.randIP,
				rand.randPW
			]
			for theTest in the_list:
				self.assertIsNotNone(theTest(None))
				self.assertIsNotNone(theTest())
		except Exception as impErr:
			print(str("Bad count"))
			print(str(""))
			print(str(type(impErr)))
			print(str(impErr))
			print(str((impErr.args)))
			print(str(""))
			theResult = False
		assert theResult

	def test_keyring_rand_each_count_test(self):
		"""Test generate random output test-case of multi-counts."""
		theResult = True
		try:
			from .context import piaplib
			if piaplib.__name__ is None:
				theResult = False
			from piaplib import keyring as keyring
			if keyring.__name__ is None:
				theResult = False
			from keyring import rand as rand
			if rand.__name__ is None:
				theResult = False
			the_list = [
				rand.fastrandInt,
				rand.randInt,
				rand.rand,
				rand.randBool,
				rand.randStr,
				rand.randChar,
				rand.randPW,
				rand.randSSID,
				rand.randIP,
				rand.randPW
			]
			for theTest in the_list:
				for theCount in range(1, 20, 5):
					self.assertIsNotNone(theTest(theCount))
		except Exception as impErr:
			print(str("Bad count"))
			print(str(""))
			print(str(type(impErr)))
			print(str(impErr))
			print(str((impErr.args)))
			print(str(""))
			theResult = False
		assert theResult

	def test_keyring_rand_SSID_count_test(self):
		"""Test generate random output test-case of multi-counts."""
		theResult = True
		try:
			from .context import piaplib
			if piaplib.__name__ is None:
				theResult = False
			from piaplib import keyring as keyring
			if keyring.__name__ is None:
				theResult = False
			from keyring import rand as rand
			if rand.__name__ is None:
				theResult = False
			for theCount in range(64):
				thetest = rand.randSSID(theCount)
				self.assertIsNotNone(thetest)
				self.assertIsInstance(thetest, str)
		except Exception as impErr:
			print(str("Bad count"))
			print(str(""))
			print(str(type(impErr)))
			print(str(impErr))
			print(str((impErr.args)))
			print(str(""))
			theResult = False
		assert theResult

	def test_keyring_rand_test_bias(self):
		"""Test generate random output of multiple domains in 10000 tries test-case."""
		theResult = True
		seen_alpha = False
		seen_digit = False
		seen_space = False
		seen_special = False
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
			temp = str(rand.rand(1))
			for rand_roll in range(10000):
				seen_alpha = ((seen_alpha is True) or str(temp).isalpha())
				seen_digit = ((seen_digit is True) or str(temp).isdigit())
				seen_space = ((seen_space is True) or (str(temp).isspace() is True))
				seen_special = ((seen_special is True) or (str(temp).isalnum() is False))
				temp = str(rand.rand(1))
				self.assertIsNotNone(temp)
			if seen_alpha and seen_digit and seen_special and seen_space:
				theResult = (theResult is True)
			temp = None
			del(temp)
		except Exception as impErr:
			print(str(""))
			print(str(type(impErr)))
			print(str(impErr))
			print(str((impErr.args)))
			print(str(""))
			theResult = False
		assert theResult

	def test_z_case_rand_insane_none(self):
		"""Tests the imposible state for rand given bad tools"""
		theResult = True
		try:
			from piaplib.keyring import rand as rand
			if rand.__name__ is None:
				raise ImportError("Failed to import rand")
			self.assertIsNone(rand.useRandTool("NoSuchTool"))
			self.assertIsNone(rand.useRandTool(None))
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


if __name__ == '__main__':
	unittest.main()
