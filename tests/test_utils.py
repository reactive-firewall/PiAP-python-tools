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
		from context import piaplib as piaplib
		if piaplib.__name__ is None:  # pragma: no branch
			raise ImportError("[CWE-758] Failed to import piaplib")
except Exception:
	raise ImportError("[CWE-758] Failed to import test context")


try:
	if 'os' not in sys.modules:
		import os
	else:  # pragma: no branch
		os = sys.modules["""os"""]
except Exception:  # pragma: no branch
	raise ImportError("[CWE-758] OS Failed to import.")


class UtilsTestSuite(unittest.TestCase):
	"""Utility (piaplib.pku.util) test cases."""

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
		self.assertTrue(theResult)

	def test_actual_depends(self):
		"""Test case re-importing depends."""
		theResult = True
		try:
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
		self.assertTrue(theResult)

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
		self.assertTrue(theResult)

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
		self.assertTrue(theResult)

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
		self.assertTrue(theResult)

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
		self.assertTrue(theResult)

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
		self.assertTrue(theResult)

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
			validMAC = ["ptty2", "pts2", "tty1"]
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
		self.assertTrue(theResult)

	def test_case_utils_none_ext(self):
		"""Tests the addExtension when input is None"""
		theResult = True
		try:
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
		self.assertTrue(theResult)

	def test_case_utils_file_with_none_ext(self):
		"""Tests the addExtension when input is (test, None)"""
		theResult = True
		try:
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
		self.assertTrue(theResult)

	def test_case_utils_file_with_short_ext(self):
		"""Tests the addExtension when input is (test, txt)"""
		theResult = True
		try:
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
			self.assertIsInstance(test, str, str("""Result is not a string"""))
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
		self.assertTrue(theResult)

	def test_case_utils_file_with_long_ext(self):
		"""Tests the addExtension when input is (test, much_longer_extension)"""
		theResult = True
		try:
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
			self.assertIsInstance(test, str, str("""Result is not a string"""))
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
		self.assertTrue(theResult)

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
				if (sys.version_info >= (3, 2)):
					self.assertIsInstance(readback, str, str("""Result is not a string"""))
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
		self.assertTrue(theResult)

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
		self.assertTrue(theResult)

	@unittest.skipUnless((sys.version_info >= (3, 4)), "log testing is not posible in old pythons")
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
			with self.assertLogs('piaplib') as cm:
				self.assertFalse(utils.writeFile(somefile, theBlob), str("""write worked"""))
				self.assertFalse(utils.appendFile(somefile, theBlob), str("""append worked"""))
				self.assertIsNone(utils.readFile(somefile))
			test_mesg = str(cm.output)
			for test_error in [str("""[CWE-73]"""), str("""File could not be opened""")]:
				self.assertIn(
					test_error, test_mesg,
					str("""Wrong Error Messages (missing test case error)""")
				)
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
		self.assertTrue(theResult)

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
				if sys.platform.startswith("linux"):
					print(str("fetch failed"))
					print(str(""))
				else:
					raise unittest.SkipTest("BETA. Experemental feature not ready yet.")
		except unittest.SkipTest as skiper:
			skiper = None
			del skiper
			raise unittest.SkipTest("BETA. Experemental feature not ready yet.")
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

	def test_case_utils_remediation_error_pass(self):
		"""Tests the remediation.error_passing logic on false error"""
		theResult = False
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
		self.assertTrue(theResult)

	def test_case_utils_get_set_handler(self):
		"""Tests the get/set handler with a string as input"""
		theResult = True
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			validHandler = utils.xisfile
			self.assertIsNotNone(utils.getHandle(validHandler), str("utils.xisfile"))
			self.assertIsNotNone(utils.getHandler(utils.getHandle(validHandler)))
			self.assertEqual(utils.getHandler(utils.getHandle(validHandler)), utils.xisfile)
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
		self.assertTrue(theResult)

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
		self.assertTrue(theResult)

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
		self.assertTrue(theResult)

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
		self.assertTrue(theResult)

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
		self.assertTrue(theResult)

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
					int(i),
					str("""Failed to extract the number""")
				)
				self.assertEqual(
					int(utils.extractInt(str("The number {} is not 1234").format(str(i)))),
					int(i),
					str("""Extracted the wrong number""")
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
		self.assertTrue(theResult)

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
		self.assertTrue(theResult)

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
		self.assertTrue(theResult)

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
		self.assertTrue(theResult)

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
					bool,
					"""Result is NOT a Boolean!"""
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
		self.assertTrue(theResult)

	@unittest.skipUnless((sys.version_info >= (3, 4)), "log testing is not posible in old pythons")
	def test_case_utils_miss_arg_verbose(self):
		"""Tests the utils._handleVerbosityArgs with an invalid value as input"""
		theResult = False
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			test_error = str("""__init__() missing 1 required positional argument: 'message'""")
			with self.assertLogs('piaplib') as cm:
				with self.assertRaises(RuntimeError):
					utils._handleVerbosityArgs(argParser=None, default=True)
			self.assertIsNotNone(cm.output, str("""No Error Message Logged"""))
			test_mesg = str(cm.output)
			self.assertIn(
				test_error, test_mesg,
				str("""Wrong Error Messages (missing test case error)""")
			)
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
		self.assertTrue(theResult)

	@unittest.skipUnless((sys.version_info >= (3, 4)), "log testing is not posible in old pythons")
	def test_case_utils_miss_arg_version(self):
		"""Tests the utils._handleVersionArgs with an invalid value as input"""
		theResult = False
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			test_error = str("""__init__() missing 1 required positional argument: 'message'""")
			with self.assertLogs('piaplib') as cm:
				with self.assertRaises(RuntimeError):
					utils._handleVersionArgs(argParser=None)
			self.assertIsNotNone(cm.output, str("""No Error Message Logged"""))
			test_mesg = str(cm.output)
			self.assertIn(
				test_error, test_mesg,
				str("""Wrong Error Messages (missing test case error)""")
			)
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
		self.assertTrue(theResult)

	def test_case_utils_miss_xisfile_func(self):
		"""Tests the utils.xisfile(None) with an invalid value as input"""
		theResult = False
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			theResult = (utils.xisfile(somefile=None) is False)
			self.assertIsInstance(
				theResult,
				bool,
				"""Result is NOT a Boolean!"""
			)
			self.assertTrue(theResult)
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

	def test_case_utils_miss_xisdir_func(self):
		"""Tests the utils.xisdir(None) with an invalid value as input"""
		theResult = False
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			theResult = (utils.xisdir(None) is False)
			self.assertIsInstance(
				theResult,
				bool,
				"""Result is NOT a Boolean!"""
			)
			self.assertTrue(theResult)
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

	def test_case_utils_miss_ensuredir_func(self):
		"""Tests the utils.xisdir(None) with an invalid value as input"""
		theResult = False
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			theResult = (utils.ensureDir(None) is False)
			self.assertIsInstance(
				theResult,
				bool,
				"""Result is NOT a Boolean!"""
			)
			self.assertTrue(theResult)
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
