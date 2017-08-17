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


class MoreClientChecksTestSuite(unittest.TestCase):
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
			from piaplib import lint as lint
			from piaplib import pku as pku
			from pku import interfaces as interfaces
			from lint import check as check
			from lint import clients_check_status as clients_check_status
			for depends in [piaplib, pocket, pku, interfaces, lint, check, clients_check_status]:
				if depends.__name__ is None:
					theResult = False
			theResult = True
		except Exception as impErr:
			print(str(type(impErr)))
			print(str(impErr))
			theResult = False
		assert theResult

	def test_clients_check_status_aa(self):
		"""Test case for piaplib.lint.clients_check_status
		with show_client("1.2.3.4", False, False, "eth0")"""
		theResult = False
		from .context import piaplib
		from piaplib import lint as lint
		from piaplib import pku as pku
		from pku import interfaces as interfaces
		from lint import clients_check_status as clients_check_status
		for depends in [piaplib, pku, interfaces, lint, clients_check_status]:
			if depends.__name__ is None:
				theResult = False
		try:
			temp = clients_check_status.show_client(
				"1.2.3.4",
				False,
				False,
				interfaces.INTERFACE_CHOICES[0]
			)
			self.assertIsNotNone(temp)
			self.assertIsInstance(temp, str, "Test output is string")
			theResult = isinstance(temp, str)
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

	def test_clients_check_status_ab(self):
		"""Test case for piaplib.lint.clients_check_status
		with show_client("1.2.3.4", True, False, "eth0")"""
		theResult = False
		from .context import piaplib
		from piaplib import lint as lint
		from piaplib import pku as pku
		from pku import interfaces as interfaces
		from lint import clients_check_status as clients_check_status
		for depends in [piaplib, pku, interfaces, lint, clients_check_status]:
			if depends.__name__ is None:
				theResult = False
		try:
			temp = clients_check_status.show_client(
				"1.2.3.4",
				True,
				False,
				interfaces.INTERFACE_CHOICES[0]
			)
			self.assertIsNotNone(temp)
			self.assertIsInstance(temp, str, "Test output is string")
			theResult = isinstance(temp, str)
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

	def test_clients_check_status_ac(self):
		"""Test case for piaplib.lint.clients_check_status
		with show_client("1.2.3.4", True, True, "eth0")"""
		theResult = False
		from .context import piaplib
		from piaplib import lint as lint
		from piaplib import pku as pku
		from pku import interfaces as interfaces
		from lint import clients_check_status as clients_check_status
		for depends in [piaplib, pku, interfaces, lint, clients_check_status]:
			if depends.__name__ is None:
				theResult = False
		try:
			temp = clients_check_status.show_client(
				"1.2.3.4",
				True,
				True,
				interfaces.INTERFACE_CHOICES[0]
			)
			self.assertIsNotNone(temp)
			self.assertIsInstance(temp, str, "Test output is string")
			theResult = isinstance(temp, str)
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

	def test_clients_check_status_ad(self):
		"""Test case for piaplib.lint.clients_check_status
		with show_client("1.2.3.4", False, True, "eth0")"""
		theResult = False
		from .context import piaplib
		from piaplib import lint as lint
		from piaplib import pku as pku
		from pku import interfaces as interfaces
		from lint import clients_check_status as clients_check_status
		for depends in [piaplib, pku, interfaces, lint, clients_check_status]:
			if depends.__name__ is None:
				theResult = False
		try:
			temp = clients_check_status.show_client(
				"1.2.3.4",
				False,
				True,
				interfaces.INTERFACE_CHOICES[0]
			)
			self.assertIsNotNone(temp)
			self.assertIsInstance(temp, str, "Test output is string")
			theResult = isinstance(temp, str)
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

	def test_clients_check_status_ae(self):
		"""Test case for piaplib.lint.clients_check_status
		with show_client("1.2.3.4", *, *, "JUNK")"""
		theResult = False
		from .context import piaplib
		from piaplib import lint as lint
		from lint import clients_check_status as clients_check_status
		for depends in [piaplib, lint, clients_check_status]:
			if depends.__name__ is None:
				theResult = False
		try:
			self.assertIsNotNone(clients_check_status.show_client("1.2.3.4", False, False, "JUNK"))
			self.assertIsNotNone(clients_check_status.show_client("1.2.3.4", False, True, "JUNK"))
			self.assertIsNotNone(clients_check_status.show_client("1.2.3.4", True, False, "JUNK"))
			temp = clients_check_status.show_client("1.2.3.4", True, True, "JUNK")
			self.assertIsNotNone(temp)
			self.assertIsInstance(temp, str, "Test output is string")
			theResult = isinstance(temp, str)
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

	def test_clients_check_status_ba(self):
		"""Test case for piaplib.lint.clients_check_status.get_client_name(None IP)"""
		theResult = False
		from .context import piaplib
		from piaplib import lint as lint
		from piaplib import pku as pku
		from pku import interfaces as interfaces
		from lint import clients_check_status as clients_check_status
		for depends in [piaplib, pku, interfaces, lint, clients_check_status]:
			if depends.__name__ is None:
				theResult = False
		try:
			temp = clients_check_status.get_client_name(
				None,
				False,
				interfaces.INTERFACE_CHOICES[0]
			)
			self.assertIsNone(temp)
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

	def test_clients_check_status_bb(self):
		"""Test case for piaplib.lint.clients_check_status.get_client_name(None Iface)"""
		theResult = False
		from .context import piaplib
		from piaplib import lint as lint
		from piaplib import pku as pku
		from pku import interfaces as interfaces
		from lint import clients_check_status as clients_check_status
		for depends in [piaplib, pku, interfaces, lint, clients_check_status]:
			if depends.__name__ is None:
				theResult = False
		try:
			temp = clients_check_status.get_client_name(
				"1.2.3.4",
				False,
				None
			)
			self.assertEqual(temp, str("UNKNOWN"))
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