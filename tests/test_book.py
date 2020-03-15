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
except Exception:
	raise ImportError("[CWE-758] Failed to import test context")


import piaplib.book.__main__


class BookTestSuite(unittest.TestCase):
	"""Special Pocket Book test cases."""

	def test_book_insane_none(self):
		"""Tests the imposible state for book given bad tools"""
		theResult = True
		try:
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
		self.assertTrue(theResult, str("""piaplib.book.__main__.useBookTool(JUNK) == error"""))

	def test_book_version_main(self):
		"""Tests the version state for book given future tools"""
		theResult = True
		try:
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
		self.assertTrue(theResult)

	def test_book_invalid_main(self):
		"""Tests the logs state for book given bad tools"""
		theResult = True
		try:
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
		self.assertTrue(theResult)


if __name__ == u'__main__':
	unittest.main()
