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
			print(str(""))
			print(str(type(impErr)))
			print(str(impErr))
			print(str((impErr.args)))
			print(str(""))
			theResult = False
		assert theResult

	def test_case_utils_test_a_literal_str(self):
		"""Tests the literal string functions"""
		theResult = True
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			u_test = str(u'test')
			try:
				b_test = b'test'
			except Exception:
				b_test = str(b'test')
			theResult = utils.literal_str(b_test) in utils.literal_str(u_test)
			theResult = (
				(theResult is True) and (
					utils.literal_str(u_test) in utils.literal_str(b_test)
				)
			)
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

	def test_case_utils_test_b_literal_str(self):
		"""Tests the literal string functions with u\'butter\'"""
		theResult = True
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			theResult = (
				utils.literal_str(b'u\'butter\'') in utils.literal_str(str(u'u\'butter\''))
			)
			theResult_temp = (
				utils.literal_str(str(u'u\'butter\'')) in utils.literal_str(b'u\'butter\'')
			)
			theResult = (theResult is True) and (theResult_temp is True)
			theResult_temp = None
			del theResult_temp
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

	def test_case_utils_Pangram_literal_str(self):
		"""Tests the literal string functions with a Pangram"""
		theResult = True
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			theResult = utils.literal_str(b'The quick brown fox jumps over the lazy dog') in utils.literal_str(str(u'The quick brown fox jumps over the lazy dog'))  # noqa
			theResult = (theResult is True) and (utils.literal_str(str(u'The quick brown fox jumps over the lazy dog')) in utils.literal_str(b'The quick brown fox jumps over the lazy dog'))  # noqa
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

	def test_case_utils_test_empty_literal_str(self):
		"""Tests the literal string functions with blank equal to blank"""
		theResult = True
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			u_test = str(u'')
			try:
				b_test = b''
			except Exception:
				b_test = str(b'')
			theResult = (
				utils.literal_str(b_test) in utils.literal_str(u_test)
			)
			theResult_temp = (
				utils.literal_str(u_test) in utils.literal_str(b_test)
			)
			theResult = (theResult is True) and (theResult_temp is True)
			theResult_temp = None
			del theResult_temp
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

	def test_case_utils_base_literal_str(self):
		"""Tests the literal string functions with ABC"""
		theResult = True
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			the_test_cases = [
				(utils.literal_str(b'a'), utils.literal_str(str(u'a'))),
				(utils.literal_str(b'A'), utils.literal_str(str(u'A'))),
				(utils.literal_str(b'b'), utils.literal_str(str(u'b'))),
				(utils.literal_str(b'B'), utils.literal_str(str(u'B'))),
				(utils.literal_str(b'c'), utils.literal_str(str(u'c'))),
				(utils.literal_str(b'C'), utils.literal_str(str(u'C'))),
				(utils.literal_str(b'a'), utils.literal_str("a")),
				(utils.literal_str(b'A'), utils.literal_str("A")),
				(utils.literal_str(b'b'), utils.literal_str("b")),
				(utils.literal_str(b'B'), utils.literal_str("B")),
				(utils.literal_str(b'c'), utils.literal_str("c")),
				(utils.literal_str(b'C'), utils.literal_str("C")),
				(utils.literal_str(b'\x1f'), utils.literal_str(str(u'\x1f'))),
				(utils.literal_str(b'\x1f'), utils.literal_str("\x1f"))
			]
			for testcase in the_test_cases:
				if theResult is True:
					if testcase[0] is None or testcase[1] is None:
						continue
					else:
						theResult = (
							testcase[0] in testcase[1]
						)
					if utils.literal_str(testcase[0]) is None:
						continue
					if utils.literal_str(testcase[1]) is not None:
						theResult_temp = (
							utils.literal_str(testcase[0]) in utils.literal_str(testcase[1])
						)
						theResult = (theResult is True) and (theResult_temp is True)
						theResult_temp = None
						del(theResult_temp)
		except Exception as err:
			print(str(""))
			print(str(type(err)))
			print(str(err))
			print(str((err.args)))
			print(str(""))
			err = None
			del(err)
			theResult = False
		assert theResult

	def test_case_utils_bad_literal_str(self):
		"""Tests the literal string functions with ABC"""
		theResult = True
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			the_test_cases = [
				(utils.literal_str(bytes(int('0x1f', 0))), utils.literal_str(bytes(int('0x1f', 0)))),
				(utils.literal_str(bytes(int('0xee', 0))), utils.literal_str(bytes(int('0xee', 0)))),
				(utils.literal_str(bytes(int('0x05', 0))), utils.literal_str(bytes(int('0x05', 0))))
			]
			for testcase in the_test_cases:
				if theResult is True:
					if testcase[0] is None:
						continue
					if utils.literal_str(testcase[0]) is None:
						continue
					if utils.literal_str(testcase[1]) is not None:
						self.assertEqual(
							utils.literal_str(testcase[0]),
							utils.literal_str(testcase[1])
						)
		except Exception as err:
			print(str(""))
			print(str(type(err)))
			print(str(err))
			print(str((err.args)))
			print(str(""))
			err = None
			del(err)
			theResult = False
		assert theResult

	def test_case_utils_fuzz_literal_str(self):  # noqa
		"""Tests the literal string functions with a fuzzed input"""
		theResult = True
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from piaplib import keyring as keyring
			if keyring.__name__ is None:
				raise ImportError("Failed to import keyring")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			from keyring import rand as rand
			if rand.__name__ is None:
				raise ImportError("Failed to import rand")
			the_test_cases = []
			for test_count in range(300):
				temp = rand.randChar(1)
				the_test_cases.append((utils.literal_str(temp), utils.literal_str(str(temp))))
			for testcase in the_test_cases:
				if theResult is True:
					if testcase[0] is not None:
						if testcase[1] is not None:
							theResult = (
								testcase[0] in testcase[1]
							)
						if utils.literal_str(testcase[1]) is not None:
							theResult_temp = (
								testcase[0] in testcase[1]
							)
							theResult = (theResult is True) and (theResult_temp is True)
							theResult_temp = None
							del theResult_temp
					if theResult is not True:
						print("NEW test")
						print(str(testcase))
						print(repr(testcase))
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

	def test_case_utils_fuzz_x_str(self):  # noqa
		"""Tests the literal string functions with a fuzzed input"""
		theResult = True
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from piaplib import keyring as keyring
			if keyring.__name__ is None:
				raise ImportError("Failed to import keyring")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			from keyring import rand as rand
			if rand.__name__ is None:
				raise ImportError("Failed to import rand")
			the_test_cases = []
			for test_count in range(300):
				temp = rand.randChar(1)
				the_test_cases.append((utils.literal_str(temp), utils.literal_str(str(temp))))
			for testcase in the_test_cases:
				if theResult is True:
					if testcase[0] is not None:
						if testcase[1] is not None:
							theResult = (
								utils.xstr(testcase[0]) in utils.xstr(testcase[1])
							)
						if utils.literal_str(testcase[1]) is not None:
							theResult_temp = (
								utils.xstr(testcase[0]) in utils.xstr(testcase[1])
							)
							theResult = (theResult is True) and (theResult_temp is True)
							if theResult is not True:
								print("NEW test")
								print(str(testcase))
								print(repr(testcase))
							theResult_temp = None
							del theResult_temp
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

	def _test_case_utils_super_fuzz_literal_str(self):
		"""Tests the literal string functions with random strings"""
		theResult = True
		try:
			from piaplib import pku as pku
			from pku import utils as utils
			import os
			for depends in [os, utils, pku]:
				if depends.__name__ is None:
					raise ImportError("Failed to import dependancy")
			for testrun in range(1000):
				randomTest = os.urandom(10)
				testcase = [str(randomTest), utils.literal_str(randomTest)]
				if theResult is True:
					if testcase[1] is not None:
						theResult = (
							testcase[0] in testcase[1]
						)
					if utils.literal_str(testcase[1]) is not None:
						theResult_temp = (
							testcase[0] in testcase[1]
						)
						theResult = (theResult is True) and (theResult_temp is True)
						theResult_temp = None
						del theResult_temp
						if theResult is not True:
							print("NEW test")
							print(str(testcase))
							print(repr(testcase))
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
