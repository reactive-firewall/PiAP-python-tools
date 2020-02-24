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
	import sys
	if sys.__name__ is None:  # pragma: no branch
		raise ImportError("[CWE-758] OMG! we could not import sys! ABORT. ABORT.")
except Exception as err:  # pragma: no branch
	raise ImportError(err)


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


class logsTestSuite(unittest.TestCase):
	"""Special Pocket logbook test cases."""

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
			from piaplib import book as book
			if book.__name__ is None:
				theResult = False
			theResult = True
		except Exception as impErr:
			print(str(type(impErr)))
			print(str(impErr))
			theResult = False
		assert theResult

	@unittest.skipUnless((sys.version_info >= (3, 4)), "Requires Python 3.4+")
	def test_a_case_log_call(self):
		"""Tests the odd state for logs called as class"""
		theResult = True
		try:
			from piaplib import book as book
			if book.__name__ is None:
				raise ImportError("Failed to import book")
			from book.logs import logs as logs
			if logs.__name__ is None:
				raise ImportError("Failed to import logs")
			with self.assertLogs(None, level='INFO') as cm:
				logobj = logs()
				logobj(msg=str("test log call"), loglevel="INFO")
				self.assertIsNotNone(cm)
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

	@unittest.skipUnless((sys.version_info >= (3, 4)), "Requires Python 3.4+")
	def test_b_case_log_call(self):
		"""Tests the imposible state for logs missing input"""
		theResult = True
		try:
			from piaplib import book as book
			if book.__name__ is None:
				raise ImportError("Failed to import book")
			from book.logs import logs as logs
			if logs.__name__ is None:
				raise ImportError("Failed to import logs")
			with self.assertLogs(None, level='INFO') as cm:
				logs.log(str("test log call"), 'INFO')
				with self.assertRaises(Exception):
					logs.log(None, 'INFO')
				with self.assertRaises(Exception):
					logs.log(None, None)
					logs.log(str("test log None"), None)
				self.assertIsNotNone(cm)
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

	def test_c_case_log_call(self):
		"""Tests the imposible state for logs given junk input"""
		theResult = True
		try:
			from piaplib import book as book
			if book.__name__ is None:
				raise ImportError("Failed to import book")
			from book.logs import logs as logs
			if logs.__name__ is None:
				raise ImportError("Failed to import logs")
			with self.assertRaises(Exception):
				logs.log(["test log call"], 'INFO')
			with self.assertRaises(Exception):
				logs.log("test log call", ['INFO'])
			with self.assertRaises(Exception):
				logs.log("test log call", 'JUNK_VALUE')
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

	def test_d_case_log_bad_main(self):
		"""Tests the imposible state for logs main"""
		theResult = True
		try:
			from piaplib import book as book
			if book.__name__ is None:
				raise ImportError("Failed to import book")
			from book.logs import logs as logs
			if logs.__name__ is None:
				raise ImportError("Failed to import logs")
			with self.assertRaises(Exception):
				logs.main(["test log call"])
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
