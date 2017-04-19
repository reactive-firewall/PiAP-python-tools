#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Pocket PiAP
# ..................................
# Copyright (c) 2017, Kendrick Walls
# ..................................
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# ..........................................
# http://www.apache.org/licenses/LICENSE-2.0
# ..........................................
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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


if __name__ == '__main__':
	unittest.main()