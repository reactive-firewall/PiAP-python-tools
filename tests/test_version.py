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

import unittest


class VersionTestSuite(unittest.TestCase):
	"""More Unit test cases for piaplib.lint.check_clients_status."""

	def test_absolute_truth_and_meaning(self):
		"""Insanitty Test."""
		assert True

	def test_syntax(self):
		"""Test case importing code."""
		theResult = False
		try:
			from .context import piaplib
			from piaplib import pocket
			from piaplib import book as book
			from book import version as version
			for depends in [piaplib, pocket, book, version]:
				if depends.__name__ is None:
					theResult = False
			theResult = True
		except Exception as impErr:
			print(str(type(impErr)))
			print(str(impErr))
			theResult = False
		assert theResult

	def test_version_loop(self):
		"""Test case for piaplib.book.version(*)"""
		from .context import piaplib
		from piaplib import book as book
		from book import version as version
		theResult = True
		for depends in [piaplib, book, version]:
				if depends.__name__ is None:
					theResult = False
		try:
			for test_case_input in version.VERSION_UNITS.keys():
				temp = version.main([
					str(test_case_input),
					str("-v")
				])
				self.assertIsNotNone(temp)
				self.assertIsInstance(temp, str, "Version output should be a string")
				theResult = (theResult and isinstance(temp, str))
				temp = None
				temp = version.main([str(test_case_input)])
				self.assertIsNotNone(temp)
				self.assertIsInstance(temp, str, "Version output should be a string")
				theResult = (theResult and isinstance(temp, str))
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

	def test_version_bad_loop(self):
		"""Test case for bad input of piaplib.book.version(JUNK)"""
		from .context import piaplib
		from piaplib import book as book
		from book import version as version
		theResult = True
		for depends in [piaplib, book, version]:
				if depends.__name__ is None:
					theResult = False
		try:
			with self.assertRaises(BaseException):
				for test_case_input in [str("JUNK"), None]:
					temp = version.main([
						str(test_case_input),
						str("-v")
					])
					self.assertIsNotNone(temp)
					temp = None
			temp = version.getRunVersion(None, False)
			self.assertIsNotNone(temp)
			theResult = True
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
