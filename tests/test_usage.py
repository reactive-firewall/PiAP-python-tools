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

	def test_b_python_command(self):
		"""Test case for backend library."""
		theResult = False
		try:
			import subprocess
			theOutputtext = subprocess.check_output(["which", "python3"])
			if (str("/python3") in str(theOutputtext)):
				theResult = True
		except Exception:
			theResult = False
			try:
				theOutputtext = subprocess.check_output(["which", "python"])
				if (str("/python") in str(theOutputtext)):
					theResult = True
			except Exception:
				theResult = False
		assert theResult

	def test_c_python_command_pocket(self):
		"""Test case for piaplib.pocket help."""
		theResult = False
		try:
			import subprocess
			thepython = subprocess.check_output(["which", "python3"])
			if (str("/python3") in str(thepython)):
				thepython = "python3"
			else:
				thepython = "python"
			if (thepython is not None):
				try:
					theOutputtext = subprocess.check_output([
						str(thepython),
						str("-m"),
						str("piaplib.pocket"),
						str("--help")
					], stderr=subprocess.STDOUT)
					if (str("usage:") in str(theOutputtext)):
						theResult = True
					else:
						theResult = False
						print(str(""))
						print(str("python cmd is {}").format(str(thepython)))
						print(str(""))
						print(str("actual output was..."))
						print(str(""))
						print(str("{}").format(str(theOutputtext)))
						print(str(""))
				except Exception as othererr:
					print(str(""))
					print(str(type(othererr)))
					print(str(othererr))
					print(str((othererr.args)))
					print(str(""))
					othererr = None
					del othererr
					theResult = False
		except Exception as err:
			print(str(""))
			print(str(type(err)))
			print(str(err))
			print(str((err.args)))
			print(str(""))
			othererr = None
			del othererr
			theResult = False
		assert theResult

	def test_d_python_command_check_users(self):
		"""Test case for piaplib.pocket.lint check users."""
		theResult = False
		try:
			import subprocess
			thepython = subprocess.check_output(["which", "python3"])
			if (str("/python3") in str(thepython)):
				thepython = "python3"
			else:
				thepython = "python"
			if (thepython is not None):
				try:
					theOutputtext = subprocess.check_output([
						str(thepython),
						str("-m"),
						str("piaplib.pocket"),
						str("lint"),
						str("check"),
						str("users"),
						str("--all")
					], stderr=subprocess.STDOUT)
					if (str("root console ") in str(theOutputtext)):
						theResult = True
					else:
						theResult = False
						print(str(""))
						print(str("python cmd is {}").format(str(thepython)))
						print(str(""))
						print(str("actual output was..."))
						print(str(""))
						print(str("{}").format(str(theOutputtext)))
						print(str(""))
				except Exception as othererr:
					print(str(""))
					print(str(type(othererr)))
					print(str(othererr))
					print(str((othererr.args)))
					print(str(""))
					othererr = None
					del othererr
					theResult = False
		except Exception as err:
			print(str(""))
			print(str(type(err)))
			print(str(err))
			print(str((err.args)))
			print(str(""))
			othererr = None
			del othererr
			theResult = False
		assert theResult

	def test_d_python_command_check_iface(self):
		"""Test case for piaplib.pocket.lint check iface."""
		theResult = False
		try:
			import subprocess
			thepython = subprocess.check_output(["which", "python3"])
			if (str("/python3") in str(thepython)):
				thepython = "python3"
			else:
				thepython = "python"
			if (thepython is not None):
				try:
					theOutputtext = subprocess.check_output([
						str(thepython),
						str("-m"),
						str("piaplib.pocket"),
						str("lint"),
						str("check"),
						str("iface"),
						str("--all")
					], stderr=subprocess.STDOUT)
					if (str("eth0") in str(theOutputtext)):
						theResult = True
					else:
						theResult = False
						print(str(""))
						print(str("python cmd is {}").format(str(thepython)))
						print(str(""))
						print(str("actual output was..."))
						print(str(""))
						print(str("{}").format(str(theOutputtext)))
						print(str(""))
				except Exception as othererr:
					print(str(""))
					print(str(type(othererr)))
					print(str(othererr))
					print(str((othererr.args)))
					print(str(""))
					othererr = None
					del othererr
					theResult = False
		except Exception as err:
			print(str(""))
			print(str(type(err)))
			print(str(err))
			print(str((err.args)))
			print(str(""))
			othererr = None
			del othererr
			theResult = False
		assert theResult


if __name__ == '__main__':
	unittest.main()
