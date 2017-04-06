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
			if sys.__name__ is None:
				theResult = False
			import os
			if os.__name__ is None:
				theResult = False
			import argparse
			if argparse.__name__ is None:
				theResult = False
			import subprocess
			if subprocess.__name__ is None:
				theResult = False
			import time
			if time.__name__ is None:
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
		except Exception as impErr:
			print(u'')
			print(str(type(impErr)))
			print(str(impErr))
			print(str((impErr.args)))
			print(u'')
			theResult = False
		assert theResult

	def test_before_case_saltify(self):
		"""Test before test-case saltify."""
		theResult = True
		try:
			from piaplib import keyring as keyring
			if keyring.__name__ is None:
				theResult = False
			from keyring import saltify as saltify
			if saltify.__name__ is None:
				theResult = False
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
		theResult = True
		try:
			from piaplib import keyring as keyring
			if keyring.__name__ is None:
				raise ImportError("Failed to import keyring")
			from keyring import saltify as saltify
			if saltify.__name__ is None:
				raise ImportError("Failed to import saltify")
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

	def test_case_utils_literal_str(self):
		"""Test case for saltify."""
		theResult = True
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			theResult = utils.test_literal_str()
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


if __name__ == '__main__':
	unittest.main()
