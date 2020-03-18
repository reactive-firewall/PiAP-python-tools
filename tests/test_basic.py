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


class BasicTestSuite(unittest.TestCase):
	"""Basic test cases."""

	@unittest.skipUnless(True, "Insanitty Test. Good luck debugging.")
	def test_absolute_truth_and_meaning(self):
		"""Test case 1: Insanitty Test."""
		assert True
		self.assertTrue(True, "Insanitty Test Failed")

	def test_actual_depends_import_code(self):
		"""Test case 2: Tests importing actual dependancies of PiAPLib."""
		theResult = True
		try:
			import sys
			import os
			import argparse
			import subprocess
			import time
			import re
			import hashlib
			import hmac
			for depends in [sys, os, argparse, subprocess, time, re, hashlib, hmac]:
				if depends.__name__ is None:
					theResult = False
		except Exception as impErr:  # pragma: no branch
			print(str(""))
			print(str(type(impErr)))
			print(str(impErr))
			print(str((impErr.args)))
			print(str(""))
			theResult = False
		self.assertTrue(theResult, "[CWE-758] Import failed")

	def test_a_which_command_installed(self):
		"""Test case 3: Tests for backend exsistance of the which command."""
		theResult = False
		try:
			import subprocess
			theOutputtext = subprocess.check_output(["which", "which"])
			try:
				if (str("/which") in str(theOutputtext)):
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
		except Exception as othererr:  # pragma: no branch
			print(str(""))
			print(str(type(othererr)))
			print(str(othererr))
			print(str((othererr.args)))
			print(str(""))
			othererr = None
			del othererr
			theResult = False
		self.assertTrue(theResult)

	def test_load_piaplib_syntax(self):
		"""Test case 4: importing code for syntax errors."""
		theResult = False
		try:
			from .context import piaplib
			if piaplib.__name__ is None:
				theResult = False
			from piaplib import pocket
			if pocket.__name__ is None:
				theResult = False
			theResult = True
		except Exception as impErr:  # pragma: no branch
			print(str(type(impErr)))
			print(str(impErr))
			theResult = False
		self.assertTrue(theResult)

	def test_python_cli_command(self):
		"""Test case 5: Test case for backend library. (command lookups)"""
		theResult = False
		try:
			import subprocess
			theOutputtext = subprocess.check_output(["which", "python"])
			if (str("/python") in str(theOutputtext)):
				theResult = True
		except Exception:
			theResult = False
			try:
				theOutputtext = subprocess.check_output(["which", "which"])
				if (str("/which") in str(theOutputtext)):
					theResult = True
			except Exception:  # pragma: no branch
				theResult = False
		self.assertTrue(theResult)

	def test_y_error_handler_decorator(self):
		"""Test case 6: Basic Test case for backend library for error handling."""
		theResult = False
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				theResult = False
			from pku import remediation as remediation
			if remediation.__name__ is None:
				theResult = False
			with self.assertRaises(Exception):
				raise remediation.PiAPError(cause="This is a test")
			with self.assertRaises(Exception):
				temp = remediation.PiAPError("This is a test")
				raise remediation.PiAPError(cause=temp, msg="This is also a test")
			theResult = True
		except Exception:  # pragma: no branch
			theResult = False
		self.assertTrue(theResult)


if __name__ == '__main__':
	unittest.main()
