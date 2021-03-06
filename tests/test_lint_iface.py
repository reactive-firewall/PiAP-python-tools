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


class LintiFaceTestSuite(unittest.TestCase):
	"""pocket.lint iFace test cases."""

	def setup(self):
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

	def test_case_iface_status_insane_none(self):
		"""Tests the imposible state for iface status given bad values"""
		theResult = True
		try:
			from lint import iface_check_status as iface_check_status
		except Exception:
			import lint.iface_check_status as iface_check_status
		if iface_check_status.__name__ is None:
			theResult = False
		else:
			try:
				self.assertIsNotNone(
					iface_check_status.generate_iface_status_html_raw("lo", "UNKNOWN", None)
				)
				self.assertIsNotNone(
					iface_check_status.generate_iface_status_html("lo", "UNKNOWN")
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

	def test_case_iface_name_insane_none(self):
		"""Tests the imposible state for iface name given None values"""
		theResult = True
		try:
			from lint import iface_check_status as iface_check_status
		except Exception:
			import lint.iface_check_status as iface_check_status
		if iface_check_status.__name__ is None:
			theResult = False
		else:
			try:
				self.assertIsNone(
					iface_check_status.get_iface_name(None, False)
				)
				self.assertIsNone(
					iface_check_status.get_iface_name(None, True)
				)
				self.assertIsNone(
					iface_check_status.get_iface_name("junk", True)
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

	def test_case_iface_list_output(self):
		"""Tests the normal state for iface list given values"""
		theResult = False
		try:
			from lint import iface_check_status as iface_check_status
		except Exception:
			import lint.iface_check_status as iface_check_status
		if iface_check_status.__name__ is not None:
			try:
				iface_list = [
					str("eth0"), str("en0"), str("enp0s0"), str("ens0"), str("en1"),
					str("ens1"), str("ens2"), str("ens3"), str("ens4"), str("ens5")
				]
				for test_iface in iface_list:
					theOutput = iface_check_status.get_iface_ip_list(test_iface, False)
					if theResult is True:
						continue
					elif (theOutput is not None) and (len(theOutput) > 0):
						self.assertIsNotNone(theOutput)
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

	def test_case_iface_list_insane_none(self):
		"""Tests the imposible state for iface list given None values"""
		theResult = True
		try:
			from lint import iface_check_status as iface_check_status
		except Exception:
			import lint.iface_check_status as iface_check_status
		if iface_check_status.__name__ is None:
			theResult = False
		else:
			try:
				self.assertIsNotNone(
					iface_check_status.get_iface_ip_list(None, True)
				)
				self.assertIsNotNone(
					iface_check_status.get_iface_ip_list("junk", True)
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


if __name__ == u'__main__':
	unittest.main()
