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


try:
	import sys
	if sys.__name__ is None:  # pragma: no branch
		raise ImportError("[CWE-758] OMG! we could not import sys! ABORT. ABORT.")
except Exception as err:  # pragma: no branch
	raise ImportError(err)


try:
	if 'piaplib' not in sys.modules:
		from .context import piaplib as piaplib
	else:  # pragma: no branch
		piaplib = sys.modules["""piaplib"""]
except Exception:  # pragma: no branch
	raise ImportError("[CWE-758] piaplib Failed to import.")


class KeyringTestSuite(unittest.TestCase):
	"""Keyring test cases."""

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

	def test_before_case_keyring(self):
		"""Test before test-case keyring."""
		theResult = True
		try:
			from piaplib import keyring as keyring
			if keyring.__name__ is None:
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

	def test_keyring_salt_bad_tools(self):
		"""test that keyring garbage in garbage out for keyring.useKeyTool"""
		theResult = True
		try:
			import piaplib.keyring.__main__
			for junk_input in [str("BADTOOL"), None]:
				self.assertIsNone(piaplib.keyring.__main__.useKeyTool(junk_input, [str("--help")]))
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
