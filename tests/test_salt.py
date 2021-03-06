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


try:
	try:
		import context
	except Exception as ImportErr:  # pragma: no branch
		ImportErr = None
		del ImportErr
		from . import context
	if context.__name__ is None:
		raise ImportError("[CWE-758] Failed to import context")
	else:
		from context import unittest as unittest
		from context import piaplib as piaplib
		if piaplib.__name__ is None:  # pragma: no branch
			raise ImportError("[CWE-758] Failed to import piaplib")
except Exception:
	raise ImportError("[CWE-758] Failed to import test context")


class SaltTestSuite(unittest.TestCase):
	"""Basic test cases."""

	def test_absolute_truth_and_meaning(self):
		"""Insanity Test."""
		assert True

	def test_syntax(self):
		"""Test case importing code."""
		theResult = False
		try:
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
			print(str(""))
			print(str(type(impErr)))
			print(str(impErr))
			print(str((impErr.args)))
			print(str(""))
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
			print(str(""))
			print(str(type(err)))
			print(str(err))
			print(str((err.args)))
			print(str(""))
			err = None
			del err
			theResult = False
		assert theResult

	def test_keyring_salt_test_salt(self):
		"""test that hash is correct for known value"""
		theResult = True
		try:
			from piaplib import keyring as keyring
			if keyring.__name__ is None:
				theResult = False
			from keyring import saltify as saltify
			if saltify.__name__ is None:
				theResult = False
			test_salt_one = str(
				"7a9356011e7f6bc42105deee6d49983e0cfa7650c7fce5d5d3b19aacca91605199ee" +
				"017707f627087f8376143f368b17ed927d918eecfe100a7b1b6e39dd3c8a"
			)
			a = (str(saltify.saltify("Test Message", "testSalt")) in str(test_salt_one))
			b = (str(test_salt_one) in str(saltify.saltify("Test Message", "testSalt")))
			theResult = (a and b)
			del test_salt_one
		except Exception as impErr:
			print(str(""))
			print(str(type(impErr)))
			print(str(impErr))
			print(str((impErr.args)))
			print(str(""))
			theResult = False
		assert theResult

	def test_keyring_salt_test_entropy(self):
		"""Test deversity of saltify hashes."""
		theResult = True
		try:
			from piaplib import keyring as keyring
			from keyring import saltify as saltify
			from keyring import rand as rand
			for depends in [keyring, saltify, rand]:
				if depends.__name__ is None:
					theResult = False
			randomSalt = str(rand.randStr(10))
			space = str(""" """)
			randomSalt_shift1 = randomSalt + space
			randomSalt_shift2 = randomSalt_shift1 + space
			randomSalt_shift3 = randomSalt_shift2 + space
			randomSalt_shift4 = randomSalt_shift3 + space
			randomSalt_shift5 = randomSalt_shift4 + space
			randomSalt_shift6 = randomSalt_shift5 + space
			randomSalt_shift7 = randomSalt_shift6 + space
			randomSalt_shift8 = randomSalt_shift7 + space
			randomSalt_shift9 = randomSalt_shift8 + space
			randomSalt_shiftX = randomSalt_shift9 + space
			salt_list = [
				randomSalt, randomSalt_shift1,
				randomSalt_shift2, randomSalt_shift3,
				randomSalt_shift4, randomSalt_shift5,
				randomSalt_shift6, randomSalt_shift7,
				randomSalt_shift8, randomSalt_shift9,
				randomSalt_shiftX
			]
			if theResult is not True:
				self.assertTrue(theResult)
			for someRandomTest in range(10000):
				this_test = str(rand.randStr(10))
				that_test = str(rand.randStr(10))
				try:
					with self.subTest(i=someRandomTest, this_test=that_test, that_test=that_test):
						self.assertIsNotNone(that_test)
						self.assertIsNotNone(this_test)
						self.assertNotEqual(this_test, that_test)
						for test_salt in salt_list:
							a = saltify.saltify(str(this_test), str(randomSalt))
							b = saltify.saltify(str(that_test), str(test_salt))
							self.assertIsNotNone(a)
							self.assertIsInstance(a, str)
							self.assertIsNotNone(b)
							self.assertIsInstance(b, str)
							self.assertNotEqual(a, b)
				except Exception:
					raise unittest.SkipTest()
		except unittest.SkipTest:
			raise unittest.SkipTest("Testing Framework does not allow subTest()")
		except Exception as testErr:
			print(str("Entropy - Fuzzing Crash Found new test"))
			print(str(""))
			print(str(type(testErr)))
			print(str(testErr))
			print(str((testErr.args)))
			print(str(""))
			testErr = None
			del(testErr)
			theResult = False
		assert theResult

	def test_keyring_salt_bad_main(self):
		"""test that salt garbage in garbage out for saltify.main"""
		theResult = True
		try:
			from piaplib import keyring as keyring
			if keyring.__name__ is None:
				theResult = False
			from keyring import saltify as saltify
			if saltify.__name__ is None:
				theResult = False
			for junk_input in [str("--bad"), str("--junk")]:
				output = saltify.main([str("--msg=a"), str("--salt=b"), junk_input])
				self.assertEqual(int(output), int(0))
			try:
				output = saltify.main([None])
				self.assertEqual(int(output), int(2))
			except SystemExit as err:
				self.assertEqual(int(err.code), int(2))
			theResult = True
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
