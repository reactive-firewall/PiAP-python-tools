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


class LintTestSuite(unittest.TestCase):
	"""Special Lint test cases."""

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

	def test_case_lint_insane_none(self):
		"""Tests the imposible state for lint given bad tools"""
		theResult = False
		try:
			from piaplib import lint as lint
			if lint.__name__ is None:
				raise ImportError("Failed to import lint")
			from piaplib.lint import __main__
			for testInput in [str("NoSuchTool"), None]:
				self.assertIsNotNone(lint.__main__.useLintTool(testInput))
				self.assertIsInstance(lint.__main__.useLintTool(testInput), int)
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

	def test_case_lint_check_insane_none(self):
		"""Tests the imposible state for lint given bad tools"""
		theResult = True
		try:
			from piaplib import lint as lint
			if lint.__name__ is None:
				raise ImportError("Failed to import lint (and thus lint.check)")
			from piaplib.lint import check as check
			self.assertIsNone(check.useCheckTool("NoSuchCheck"))
			self.assertIsNone(check.useCheckTool(None))
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
