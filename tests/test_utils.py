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


class UtilsTestSuite(unittest.TestCase):
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
			import subprocess
			if subprocess.__name__ is None:
				theResult = False
		except Exception as impErr:
			print(str(""))
			print(str(type(impErr)))
			print(str(impErr))
			print(str((impErr.args)))
			print(str(""))
			theResult = False
		assert theResult

	def test_case_utils_compact_list_safe(self):
		"""Tests the compact list logic"""
		theResult = True
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			TEST_LIST = [
				[x for x in range(5)],
				[x for x in range(50)],
			]
			theResult = utils.compactList(TEST_LIST[0] + TEST_LIST[1]) in TEST_LIST
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

	def test_case_utils_regex_ipv4_quick(self):
		"""Tests the ipv4 regex logic quickly"""
		theResult = True
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			validIPv4 = ["0.0.0.0", "255.255.255.255", "10.0.40.1"]
			temp = utils.extractIPv4("""0.0.0.0, 255.255.255.255, 10.0.40.1, 300.1.2.3""")
			for x in temp:
				if x in validIPv4:
					theResult = (theResult is True)
				else:
					theResult = False
					print(str(""))
					print(str(x))
					print(str(""))
			if (theResult is False):
				print(str(""))
				print(str(temp))
				print(str(""))
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

	def test_case_utils_regex_ipv4_full(self):
		"""Tests the ipv4 regex logic fully"""
		theResult = True
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			validIPv4 = ["0.0.0.0", "255.255.255.255", "10.0.40.1"]
			temp = utils.extractIPv4("""0.0.0.0, 255.255.255.255, 10.0.40.1, 300.1.2.3""")
			theResult = (len(validIPv4) is len(temp))
			for x in temp:
				if x in validIPv4:
					theResult = (theResult is True)
				else:
					theResult = False
					print(str(""))
					print(str(x))
					print(str(""))
			if (theResult is False):
				print(str(""))
				print(str(temp))
				print(str(""))
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

	def test_case_utils_regex_ipv4_arp_output(self):
		"""Tests the ipv4 regex logic on arp output"""
		theResult = True
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			validIPv4 = ["10.20.30.40"]
			temp = utils.extractIPv4(
				"""test.PiAP.local (10.20.30.40) at 00:FF:00:FF:00:FF [ether] on wlan5"""
			)
			theResult = (len(validIPv4) is len(temp))
			for x in temp:
				if x in validIPv4:
					theResult = (theResult is True)
				else:
					theResult = False
					print(str(""))
					print(str(x))
					print(str(""))
			if (theResult is False):
				print(str(""))
				print(str(temp))
				print(str(""))
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

	def test_case_utils_regex_mac_clients_output(self):
		"""Tests the mac addr regex logic on clients output"""
		theResult = True
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			validMAC = ["00:FF:00:FF:00:FF"]
			temp = utils.extractMACAddr(
				"""00:FF:00:FF:00:FF"""
			)
			theResult = (len(validMAC) is len(temp))
			for x in temp:
				if x in validMAC:
					theResult = (theResult is True)
				else:
					theResult = False
					print(str(""))
					print(str(x))
					print(str(""))
			if (theResult is False):
				print(str(""))
				print(str(temp))
				print(str(""))
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

	def test_case_utils_regex_tty_clients_output(self):
		"""Tests the tty name regex logic on user output"""
		theResult = True
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			validMAC = ["tty2", "pts2", "tty1"]
			temp = utils.extractTTYs(
				"""the ptty2 terminal is a tty like the pts2 session but unlike the tty1 console"""
			)
			theResult = (len(validMAC) is len(temp))
			for x in temp:
				if x in validMAC:
					theResult = (theResult is True)
				else:
					theResult = False
					print(str(""))
					print(str(x))
					print(str(""))
			if (theResult is False):
				print(str(""))
				print(str(temp))
				print(str(""))
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

	def test_case_utils_none_ext(self):
		"""Tests the addExtension when input is None"""
		theResult = True
		try:
			from .context import piaplib as piaplib
			if piaplib.__name__ is None:
				raise ImportError("Failed to import pku")
			from piaplib import pocket as pocket
			if pocket.__name__ is None:
				raise ImportError("Failed to import utils")
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			self.assertIsNone(utils.addExtension(None, None))
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

	def test_case_utils_file_with_none_ext(self):
		"""Tests the addExtension when input is (test, None)"""
		theResult = True
		try:
			from .context import piaplib as piaplib
			if piaplib.__name__ is None:
				raise ImportError("Failed to import pku")
			from piaplib import pocket as pocket
			if pocket.__name__ is None:
				raise ImportError("Failed to import utils")
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			test = None
			test_name = str("test_no_dot")
			self.assertIsNone(test)
			test = utils.addExtension(test_name, None)
			self.assertIsNotNone(test)
			self.assertEqual(test, test_name)
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

	def test_case_utils_file_with_short_ext(self):
		"""Tests the addExtension when input is (test, txt)"""
		theResult = True
		try:
			from .context import piaplib as piaplib
			if piaplib.__name__ is None:
				raise ImportError("Failed to import pku")
			from piaplib import pocket as pocket
			if pocket.__name__ is None:
				raise ImportError("Failed to import utils")
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			test = None
			test_name = str("test_no_dot")
			test_ext = str("txt")
			self.assertIsNone(test)
			test = utils.addExtension(test_name, test_ext)
			self.assertIsNotNone(test)
			self.assertNotEqual(test, test_name)
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

	def test_case_utils_file_with_long_ext(self):
		"""Tests the addExtension when input is (test, much_longer_extension)"""
		theResult = True
		try:
			from .context import piaplib as piaplib
			if piaplib.__name__ is None:
				raise ImportError("Failed to import pku")
			from piaplib import pocket as pocket
			if pocket.__name__ is None:
				raise ImportError("Failed to import utils")
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			test = None
			test_name = str("test")
			test_ext = str("much_longer_extension")
			self.assertIsNone(test)
			test = utils.addExtension(test_name, test_ext)
			self.assertIsNotNone(test)
			self.assertNotEqual(test, test_name)
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

	def test_case_utils_read_write_file(self):
		"""Tests the read and write functions"""
		theResult = False
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			theBlob = str("""This will test writes,
and this will test reads.""")
			somefile = str("the_test_file.txt")
			if (utils.writeFile(somefile, theBlob) is True):
				readback = utils.readFile(somefile)
				if (theBlob in readback) and (readback in theBlob):
					theResult = (len(readback) is len(theBlob))
				else:
					theResult = False
				if (theResult is False):
					print(str("wrote"))
					print(str(theBlob))
					print(str(""))
					print(str("read"))
					print(str(readback))
					print(str(""))
			else:
				theResult = False
			if (theResult is False):
				print(str("write failed"))
				print(str(theBlob))
				print(str(""))
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

	def test_case_utils_read_ammend_file(self):
		"""Tests the read and write functions"""
		theResult = False
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			theBlob = str("""This will test writes,
and this will test reads.""")
			theBlobtail = str("""This will test ammends.""")
			somefile = str("the_test_file.txt")
			if (utils.writeFile(somefile, theBlob) is True):
				if (utils.appendFile(somefile, theBlobtail) is True):
					readback = utils.readFile(somefile)
					if (theBlobtail in readback) and (readback not in theBlob):
						theResult = (len(readback) is not len(theBlob))
					else:
						theResult = False
					if (theResult is False):
						print(str("wrote"))
						print(str(theBlob))
						print(str(""))
						print(str("read"))
						print(str(readback))
						print(str(""))
				else:
					theResult = False
			else:
				theResult = False
			if (theResult is False):
				print(str("write failed"))
				print(str(theBlob))
				print(str(""))
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

	def test_case_utils_missing_file(self):
		"""Tests the read and write functions on missing files"""
		theResult = False
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			from keyring import rand as rand
			if rand.__name__ is None:
				raise ImportError("Failed to import rand")
			theBlob = str("""This is just a test for failure.""")
			somefile = str(os.path.join(
				os.path.join(
					os.path.join(os.path.dirname(__file__), str('..')),
					str('some_long')
				),
				os.path.join(
					os.path.join(
						os.path.join(str('very'), str('long')),
						os.path.join(
							os.path.join(str(rand.randInt(1)), str('blahblah')),
							str(rand.randInt(1))
						)
					),
					str('filename.tmp')
				)
			))
			if (utils.writeFile(somefile, theBlob) is False):
				if (utils.appendFile(somefile, theBlob) is False):
					readback = utils.readFile(somefile)
					if readback is None:
						theResult = True
					else:
						theResult = False
					if (theResult is False):
						print(str("wrote"))
						print(str(theBlob))
						print(str(""))
						print(str("read"))
						print(str(readback))
						print(str(""))
				else:
					theResult = False
					print(str("append worked"))
			else:
				theResult = False
				print(str("write worked"))
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

	def test_case_utils_read_url_file(self):
		"""Tests the fetch url and clean functions"""
		theResult = False
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			someURL = str(
				"https://raw.githubusercontent.com/reactive-firewall" +
				"/PiAP-python-tools/master/requirements.txt"
			)
			somefile = str("the_test_url_file.txt")
			if (utils.getFileResource(someURL, somefile) is True):
				utils.cleanFileResource(somefile)
				theResult = True
			else:
				theResult = False
			if (theResult is False):
				print(str("fetch failed"))
				print(str(""))
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

	def test_case_utils_remediation_error_pass(self):
		"""Tests the tty name regex logic on user output"""
		theResult = True
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import remediation as remediation
			if remediation.__name__ is None:
				raise ImportError("Failed to import remediation")

			@remediation.error_passing
			def force_error():
				raise ValueError("False Error")
				return True

			with self.assertRaises(RuntimeError):
				force_error()
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

	def test_case_utils_str_lit(self):
		"""Tests the literal string with a string as input"""
		theResult = True
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			validMAC = str("00:FF:00:FF:00:FF")
			self.assertEqual(utils.literal_str(validMAC), validMAC)
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

	def test_case_utils_none_lit(self):
		"""Tests the literal string with a None as input"""
		theResult = True
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			self.assertIsNone(utils.literal_str(None))
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

	def test_case_utils_str_lit_code(self):
		"""Tests the literal code with a string as input"""
		theResult = True
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			validMAC = str("00:FF:00:FF:00:FF")
			self.assertEqual(utils.literal_code(validMAC), validMAC)
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

	def test_case_utils_none_lit_code(self):
		"""Tests the literal code with a None as input"""
		theResult = True
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			self.assertIsNone(utils.literal_code(None))
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

	def test_case_utils_compact_space(self):
		"""Tests the compactSpace with a multispace value as input"""
		theResult = True
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			self.assertEqual(len(utils.compactSpace(str("""   """))), int(1))
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

	def test_case_utils_extractInt(self):
		"""Tests the extractInt with an int value as input"""
		theResult = True
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			for i in range(100):
				self.assertEqual(
					int(utils.extractInt(str("The number is {}").format(str(i)))),
					int(i)
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

	def test_case_utils_lit_code_bytes(self):
		"""Tests the literal_code with an byte value as input"""
		theResult = True
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			self.assertEqual(
				utils.literal_code(bytes(str("test").encode("utf-8"))),
				str("test")
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

	@unittest.skipUnless((sys.version_info < (3, 0)), "unicode class is not used in python 3")
	def test_case_utils_lit_str_unicode(self):
		"""Tests the literal_str with an unicode value as input"""
		theResult = True
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			self.assertEqual(
				utils.literal_str(unicode(str("test"))),  # noqa
				str("test")
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

	def test_case_utils_match_whitelist(self):
		"""Tests the isWhiteListed with a valid value as input"""
		theResult = True
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			match_value = str("This will match")
			white_values = [
				str("This will match"),
				str("This will not match"),
				str("This will never match"),
				str("that will match"),
				str("thIs wIll match")
			]
			self.assertTrue(utils.isWhiteListed(match_value, white_values))
			for test_value in white_values:
				self.assertIsInstance(
					utils.isWhiteListed(test_value, [match_value]),
					bool
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

	def test_case_utils_miss_whitelist(self):
		"""Tests the isWhiteListed with an invalid value as input"""
		theResult = True
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			match_value = str("This will NOT match")
			white_values = [
				str("This will match"),
				str("This will not match"),
				str("This will never match"),
				str("that will match"),
				str("thIs wIll match")
			]
			self.assertFalse(utils.isWhiteListed(match_value, white_values))
			junk_list = [match_value, str("JUNK")]
			for test_value in white_values:
				self.assertIsInstance(
					utils.isWhiteListed(test_value, junk_list),
					bool
				)
				self.assertFalse(utils.isWhiteListed(test_value, junk_list))
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
