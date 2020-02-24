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


class PKUTestSuite(unittest.TestCase):
	"""Special Pocket PKU test cases."""

	def test_syntax(self):
		"""Test case importing code."""
		theResult = False
		try:
			from piaplib import pku
			if pku.__name__ is None:
				theResult = False
			theResult = True
		except Exception as impErr:
			print(str(type(impErr)))
			print(str(impErr))
			theResult = False
		assert theResult

	def test_z_case_pku_insane_none(self):
		"""Tests the imposible state for pku given bad tools"""
		theResult = False
		try:
			import piaplib.pku.__main__
			self.assertIsNotNone(piaplib.pku.__main__.usePKUTool("NoSuchTool"))
			self.assertIsNotNone(piaplib.pku.__main__.usePKUTool(None))
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
		self.assertTrue(theResult, "Error leaked while testing piaplib.pku.__main__.usePKUTool()")


if __name__ == u'__main__':
	unittest.main()
