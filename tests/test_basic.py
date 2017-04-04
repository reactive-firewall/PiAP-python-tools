#! /usr/bin/env python
# -*- coding: utf-8 -*-

#
# Pocket PiAP
#
# Copyright (c) 2017, Kendrick Walls
#	
#	Licensed under the Apache License, Version 2.0 (the "License");
#		you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#	   
#	   http://www.apache.org/licenses/LICENSE-2.0
#   
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#

import unittest


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
			from piaplib import pocket
			theResult = True
		except Exception as impErr:
			print(str(type(impErr)))
			print(str(impErr))
			theResult = False
		assert theResult


	def test_actual_depends(self):
		"""Test case importing depends."""
		theResult = False
		try:
			import sys
			import os
			import argparse
			import subprocess
			import time
			import re
			import hashlib
			import hmac
			theResult = True
		except Exception as impErr:
			print(str(type(impErr)))
			print(str(impErr))
			theResult = False
		assert theResult


	def test_before_case_saltify(self):
		"""Test before test-case saltify."""
		theResult = False
		try:
			from piaplib import keyring as keyring
			from keyring import saltify as saltify
			theResult = True
		except Exception as err:
			print(u'')
			print(str(type(err)))
			print(str(err))
			print(str((err.args)))
			print(u'')
			err = None
			del err
			theResult = False
		assert theResult


	def test_case_saltify(self):
		"""Test case for saltify."""
		theResult = False
		try:
			from piaplib import keyring as keyring
			from keyring import saltify as saltify
			saltify._test_keyring_salt_test_salt()
			theResult = True
		except Exception as err:
			print(u'')
			print(str(type(err)))
			print(str(err))
			print(str((err.args)))
			print(u'')
			err = None
			del err
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
				print(u'')
				print(str(type(err)))
				print(str(err))
				print(str((err.args)))
				print(u'')
				err = None
				del err
				theResult = False
		except Exception as othererr:
			print(u'')
			print(str(type(othererr)))
			print(str(othererr))
			print(str((othererr.args)))
			print(u'')
			othererr = None
			del othererr
			theResult = False
		assert theResult


#	def test_z_remote_command(self):
#		"""Test case for backend library."""
#		theResult = False
#		try:
#			import subprocess
#			theOutputtext = subprocess.check_output(["which", "check_nrpe"])
#			if (str("/check_nrpe") in str(theOutputtext)):
#				theResult = True
#		except Exception:
#			theResult = False
#			try:
#				theOutputtext = subprocess.check_output(["which", "ssh"])
#				if (str("/ssh") in str(theOutputtext)):
#					theResult = True
#			except Exception:
#				theResult = False
#		assert theResult

if __name__ == '__main__':
	unittest.main()
