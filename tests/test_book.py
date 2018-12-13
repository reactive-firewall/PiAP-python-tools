#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Pocket PiAP
# ......................................................................
# Copyright (c) 2017, Kendrick Walls
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


class BookTestSuite(unittest.TestCase):
	"""Special Pocket Book test cases."""

	def test_absolute_truth_and_meaning(self):
		"""Insanitty Test."""
		assert True
		self.assertIsNone(None)

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

	def test_y_case_book_valid_main(self):
		"""Tests the imposible state for book given future tools"""
		theResult = True
		try:
			import piaplib.book.__main__
			self.assertIsNotNone(piaplib.book.__main__.useBookTool("version", ["all"]))
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

	def test_z_case_book_valid_main(self):
		"""Tests the imposible state for book given bad tools"""
		theResult = True
		try:
			import piaplib.book.__main__
			self.assertIsNotNone(piaplib.book.__main__.main(["logs"]))
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

	def test_z_case_book_insane_none(self):
		"""Tests the imposible state for book given bad tools"""
		theResult = True
		try:
			import piaplib.book.__main__
			self.assertIsNotNone(piaplib.book.__main__.useBookTool("NoSuchTool"))
			self.assertIsNotNone(piaplib.book.__main__.useBookTool(None))
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


if __name__ == u'__main__':
	unittest.main()
