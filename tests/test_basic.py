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
		import context
	except Exception as ImportErr:
		ImportErr = None
		del ImportErr
		from . import context
	if context.__name__ is None:
		raise ImportError("Failed to import context")
except Exception:
	raise ImportError("Failed to import test context")


class BasicTestSuite(unittest.TestCase):
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
		except Exception as impErr:
			print(str(""))
			print(str(type(impErr)))
			print(str(impErr))
			print(str((impErr.args)))
			print(str(""))
			theResult = False
		assert theResult

	def test_a_which_command(self):
		"""Test case for backend which."""
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
		except Exception as othererr:
			print(str(""))
			print(str(type(othererr)))
			print(str(othererr))
			print(str((othererr.args)))
			print(str(""))
			othererr = None
			del othererr
			theResult = False
		assert theResult

	def test_z_remote_command(self):
		"""Test case for backend library."""
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
			except Exception:
				theResult = False
		assert theResult

	def test_y_remote_command(self):
		"""Test case for backend library."""
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
		except Exception:
			theResult = False
		assert theResult


if __name__ == '__main__':
	unittest.main()
