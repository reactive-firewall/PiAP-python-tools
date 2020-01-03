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

import unittest
import subprocess
import sys


def getPythonCommand():
	"""function for backend python command"""
	thepython = "exit 1 ; #"
	try:
		thepython = checkPythonCommand(["which", "coverage"])
		if (str("/coverage") in str(thepython)) and (sys.version_info >= (3, 3)):
			thepython = str("coverage run -p")
		elif (str("/coverage") in str(thepython)) and (sys.version_info <= (3, 2)):
			try:
				import coverage
				if coverage.__name__ is not None:
					thepython = str("{} -m coverage run -p").format(str(sys.executable))
				else:
					thepython = str(sys.executable)
			except Exception:
				thepython = str(sys.executable)
		else:
			thepython = str(sys.executable)
	except Exception:
		thepython = "exit 1 ; #"
		try:
			thepython = str(sys.executable)
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
				if sys.__name__ is None:
					raise ImportError("Failed to import system. WTF?!!")
				if str("{} -m coverage ").format(str(sys.executable)) in str(args[0]):
					args[0] = str(sys.executable)
					args.insert(1, str("-m"))
					args.insert(2, str("coverage"))
					args.insert(3, str("run"))
					args.insert(4, str("-p"))
					args.insert(4, str("--source=piaplib,piaplib/lint,piaplib/keyring,piaplib/pku,piaplib/book"))
				else:
					args[0] = str("coverage")
					args.insert(1, str("run"))
					args.insert(2, str("-p"))
					args.insert(2, str("--source=piaplib,piaplib/lint,piaplib/keyring,piaplib/pku,piaplib/book"))
			theOutput = subprocess.check_output(args, stderr=stderr)
	except Exception:
		theOutput = None
	try:
		if isinstance(theOutput, bytes):
			theOutput = theOutput.decode('utf8')
	except UnicodeDecodeError:
		theOutput = bytes(theOutput)
	return theOutput


def checkPythonFuzzing(args=[None], stderr=None):
	"""function for backend subprocess check_output command"""
	theOutput = None
	try:
		if args is None or args is [None]:
			theOutput = subprocess.check_output(["exit 1 ; #"])
		else:
			if str("coverage ") in args[0]:
				import sys
				if sys.__name__ is None:
					raise ImportError("Failed to import system. WTF?!!")
				if str("{} -m coverage ").format(str(sys.executable)) in str(args[0]):
					args[0] = str(sys.executable)
					args.insert(1, str("-m"))
					args.insert(2, str("coverage"))
					args.insert(3, str("run"))
					args.insert(4, str("-p"))
					args.insert(4, str("--source=piaplib,piaplib/lint,piaplib/keyring,piaplib/pku,piaplib/book"))
				else:
					args[0] = str("coverage")
					args.insert(1, str("run"))
					args.insert(2, str("-p"))
					args.insert(2, str("--source=piaplib,piaplib/lint,piaplib/keyring,piaplib/pku,piaplib/book"))
			theOutput = subprocess.check_output(args, stderr=stderr)
		if isinstance(theOutput, bytes):
			theOutput = theOutput.decode('utf8')
	except Exception as err:
		theOutput = None
		raise RuntimeError(err)
	return theOutput


def check_exec_command_has_output(test_case, someArgs):
	"""Test case for command output != None.
		returns True if has output and False otherwise."""
	theResult = False
	try:
		import sys
		if sys.__name__ is None:
			raise ImportError("Failed to import system. WTF?!!")
		import piaplib.pku.utils as utils
		if utils.__name__ is None:
			raise ImportError("Failed to import system. WTF?!!")
		thepython = getPythonCommand()
		if (thepython is not None):
			try:
				theArgs = [thepython] + someArgs
				test_case.assertIsNotNone(checkPythonCommand(theArgs, stderr=subprocess.STDOUT))
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
	return theResult


class PocketUsageTestSuite(unittest.TestCase):
	"""Basic functional test cases."""

	def setup(self):
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

	def test_absolute_truth_and_meaning(self):
		"""Insanitty Test."""
		assert True

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
			elif (str("python") in str(thepython)) or (sys.version_info >= (3, 2)):
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

	def test_case_pocket_insane_none(self):
		"""Tests the imposible state for pocket given bad tools"""
		theResult = True
		try:
			from .context import piaplib
			if piaplib.__name__ is None:
				theResult = False
			from piaplib import pocket
			if pocket.__name__ is None:
				theResult = False
			from piaplib import pocket as pocket
			if pocket.__name__ is None:
				raise ImportError("Failed to import pocket")
			self.assertIsNone(pocket.useTool("NoSuchTool"))
			self.assertIsNone(pocket.useTool(None))
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

	def test_c_python_command_pocket(self):
		"""Test case for piaplib.pocket --help."""
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

	def test_h_python_command_pocket_version(self):
		"""Test case for piaplib.pocket --version."""
		theResult = False
		try:
			import sys
			if sys.__name__ is None:
				raise ImportError("Failed to import system. WTF?!!")
			from .context import piaplib as piaplib
			if piaplib.__version__ is not None:
				theResult = False
			thepython = getPythonCommand()
			if (thepython is not None):
				try:
					theOutputtext = checkPythonCommand([
						str(thepython),
						str("-m"),
						str("piaplib.pocket"),
						str("--version")
					], stderr=subprocess.STDOUT)
					if (str(piaplib.__version__) in str(theOutputtext)):
						theResult = True
					else:
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
		"""Test case for piaplib.pocket *"""
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
						elif (theOutputtext is None) or (str(theOutputtext) in str("")):
							theResult = True
						else:
							theResult = False
							print(str(""))
							print(str("python cmd is {}").format(str(thepython)))
							print(str(""))
							print(str("actual output was..."))
							print(str(""))
							print(str("{}").format(repr(theOutputtext)))
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

	def test_d_python_command_bad_pocket(self):
		"""Test case for piaplib.pocket check null."""
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
						str("piaplib.pocket")
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
			from pku import interfaces as interfaces
			if interfaces.__name__ is None:
				raise ImportError("Failed to import interfaces")
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
					theOutputtext = checkPythonCommand([
						str(thepython),
						str("-m"),
						str("piaplib.pocket"),
						str("pku"),
						str("interfaces"),
						str("""-i {} -r""").format(interfaces.INTERFACE_CHOICES[1])
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
						str("""--cmd={}""").format(str(sys.executable)),
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

	def test_o_exec_command_io(self):
		"""Test case for piaplib.pocket.lint do_execve calls."""
		theResult = False
		try:
			theResult = check_exec_command_has_output(self, [
				str("-m"),
				str("piaplib.pocket"),
				str("lint"),
				str("execve"),
				str("""--out""").format(str(sys.executable)),
				str("""--cmd={}""").format(str(sys.executable)),
				str("""--args={}""").format(str("piaplib.pocket")),
				str("""--args={}""").format(str("--help"))
			])
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

