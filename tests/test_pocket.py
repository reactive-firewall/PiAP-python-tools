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
import subprocess


def getPythonCommand():
	"""function for backend python command"""
	thepython = "exit 1 ; #"
	try:
		import sys
		if sys.__name__ is None:
			raise ImportError("Failed to import system. WTF?!!")
		thepython = checkPythonCommand(["which", "coverage"])
		if (str("/coverage") in str(thepython)) and (sys.version_info >= (3, 3)):
			thepython = str("coverage run -p")
		else:
			thepython = checkPythonCommand(["which", "python3"])
			if (str("/python3") not in str(thepython)) or (sys.version_info <= (3, 2)):
				thepython = "python3"
	except Exception:
		thepython = "exit 1 ; #"
		try:
			thepython = checkPythonCommand(["which", "python"])
			if (str("/python") in str(thepython)):
				thepython = "python"
		except Exception:
			thepython = "exit 1 ; #"
	return str(thepython)


def checkPythonCommand(args=[None], stderr=None):
	"""function for backend subprocess check_output command"""
	theOutput = None
	try:
		if args is None or args is [None]:
			theOutput = subprocess.check_output(["exit 1 ; #"])
		else:
			if str("coverage ") in args[0]:
				args[0] = str("coverage")
				args.insert(1, "run")
				args.insert(2, "-p")
				args.insert(2, "--source=piaplib,piaplib/lint,piaplib/keyring,piaplib/pku,piaplib/book")
			theOutput = subprocess.check_output(args, stderr=stderr)
	except Exception:
		theOutput = None
	return theOutput


def checkPythonFuzzing(args=[None], stderr=None):
	"""function for backend subprocess check_output command"""
	theOutput = None
	try:
		if args is None or args is [None]:
			theOutput = subprocess.check_output(["exit 1 ; #"])
		else:
			if str("coverage ") in args[0]:
				args[0] = str("coverage")
				args.insert(1, "run")
				args.insert(2, "--source=piaplib,piaplib/lint,piaplib/keyring,piaplib/pku,piaplib/book")
				args.insert(2, "-p")
			theOutput = subprocess.check_output(args, stderr=stderr)
	except Exception as err:
		theOutput = None
		raise RuntimeError(err)
	return theOutput


class PocketUsageTestSuite(unittest.TestCase):
	"""Basic functional test cases."""

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

	def test_b_python_command(self):
		"""Test case for backend library."""
		theResult = False
		try:
			import sys
			if sys.__name__ is None:
				raise ImportError("Failed to import system. WTF?!!")
			thepython = getPythonCommand()
			if (str("/python3") in str(thepython)) or (sys.version_info <= (3, 2)):
				theResult = True
			elif (str("coverage") in str(thepython)) or (sys.version_info <= (3, 2)):
				theResult = True
		except Exception:
			theResult = False
			try:
				theOutputtext = checkPythonCommand(["which", "python"])
				if (str("/python") in str(theOutputtext)):
					theResult = True
			except Exception:
				theResult = False
		assert theResult

	def test_c_python_command_pocket(self):
		"""Test case for piaplib.pocket help."""
		theResult = False
		try:
			import sys
			if sys.__name__ is None:
				raise ImportError("Failed to import system. WTF?!!")
			thepython = getPythonCommand()
			if (thepython is not None):
				try:
					theOutputtext = checkPythonCommand([
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

	def test_c_python_command_pocket_units(self):
		"""Test case for piaplib.* --help."""
		theResult = False
		try:
			import sys
			if sys.__name__ is None:
				raise ImportError("Failed to import system. WTF?!!")
			thepython = getPythonCommand()
			if (thepython is not None):
				try:
					for unit in ["lint", "pku", "book", "keyring"]:
						theOutputtext = checkPythonCommand([
							str(thepython),
							str("-m"),
							str("piaplib.pocket"),
							str("{}").format(str(unit))
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

	def test_d_python_command_bad_saltify(self):
		"""Test case for piaplib.pocket.lint check users."""
		theResult = True
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			import sys
			if sys.__name__ is None:
				raise ImportError("Failed to import system. WTF?!!")
			thepython = getPythonCommand()
			if (thepython is not None):
				theOutputtext = None
				with self.assertRaises(Exception):
					theOutputtext = checkPythonFuzzing([
						str(thepython),
						str("-m"),
						str("piaplib.pocket"),
						str("keyring"),
						str("saltify"),
						str("""--salt={}""").format(str("testSalt"))
					], stderr=subprocess.STDOUT)
				self.assertIsNone(theOutputtext)
				with self.assertRaises(Exception):
					theOutputtext = checkPythonFuzzing([
						str(thepython),
						str("-m"),
						str("piaplib.pocket"),
						str("keyring"),
						str("saltify"),
						str("""--msg={}""").format(str("Test Message"))
					], stderr=subprocess.STDOUT)
				self.assertIsNone(theOutputtext)
				with self.assertRaises(Exception):
					theOutputtext = checkPythonFuzzing([
						str(thepython),
						str("-m"),
						str("piaplib.pocket"),
						str("keyring"),
						str("saltify")
					], stderr=subprocess.STDOUT)
				self.assertIsNone(theOutputtext)
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

	def test_d_python_command_bad_interface(self):
		"""Test case for piaplib.pocket.lint check users."""
		theResult = True
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			import sys
			if sys.__name__ is None:
				raise ImportError("Failed to import system. WTF?!!")
			thepython = getPythonCommand()
			if (thepython is not None):
				theOutputtext = None
				with self.assertRaises(Exception):
					theOutputtext = checkPythonFuzzing([
						str(thepython),
						str("-m"),
						str("piaplib.pocket"),
						str("pku"),
						str("interfaces"),
						str("""-i {}""").format(str("eth0"))
					], stderr=subprocess.STDOUT)
				self.assertIsNone(theOutputtext)
				with self.assertRaises(Exception):
					theOutputtext = checkPythonFuzzing([
						str(thepython),
						str("-m"),
						str("piaplib.pocket"),
						str("pku"),
						str("interfaces"),
						str("""-i {} -r""").format(str("eth0"))
					], stderr=subprocess.STDOUT)
				self.assertIsNone(theOutputtext)
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

	def test_o_exec_command_run(self):
		"""Test case for piaplib.pocket.lint do_execve calls."""
		theResult = False
		try:
			import sys
			if sys.__name__ is None:
				raise ImportError("Failed to import system. WTF?!!")
			thepython = getPythonCommand()
			if (thepython is not None):
				try:
					self.assertIsNotNone(checkPythonCommand([
						str(thepython),
						str("-m"),
						str("piaplib.pocket"),
						str("lint"),
						str("execve"),
						str("""--cmd={}""").format(str(thepython)),
						str("""--args={}""").format(str("piaplib.pocket"))
					], stderr=subprocess.STDOUT))
					theResult = True
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

