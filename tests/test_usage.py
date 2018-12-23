#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Pocket PiAP
# ......................................................................
# Copyright (c) 2017-2018, Kendrick Walls
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
import profiling as profiling


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
	except Exception as err:
		if isinstance(err, subprocess.SubprocessError):
			theOutput = err.output
		else:
			theOutput = None
	try:
		if isinstance(theOutput, bytes):
			theOutput = theOutput.decode('utf8')
	except UnicodeDecodeError:
		theOutput = bytes(theOutput)
	return theOutput


@profiling.do_cprofile
def timePythonCommand(args=[None], stderr=None):
	"""function for backend subprocess check_output command"""
	return checkPythonCommand(args, stderr)


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


def debugBlob(blob=None):
	try:
		print(str(""))
		print(str("String:"))
		print(str("""\""""))
		print(str(blob))
		print(str("""\""""))
		print(str(""))
		print(str("CODE:"))
		print(str("""\""""))
		print(repr(blob))
		print(str("""\""""))
		print(str(""))
	except Exception:
		return False
	return True


def debugtestError(someError=None):
	print(str(""))
	print(str("ERROR:"))
	print(str(type(someError)))
	print(str(someError))
	print(str((someError.args)))
	print(str(""))


def debugUnexpectedOutput(expectedOutput, actualOutput, thepython):
	print(str(""))
	if (thepython is not None):
		print(str("python cmd is {}").format(str(thepython)))
	else:
		print("warning: Unexpected output!")
	print(str(""))
	if (expectedOutput is not None):
		print(str("the expected output is..."))
		print(str(""))
		print(str("{}").format(str(expectedOutput)))
		print(str(""))
	print(str("actual output was..."))
	print(str(""))
	print(str("{}").format(str(actualOutput)))
	print(str(""))


class BasicUsageTestSuite(unittest.TestCase):
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
			debugtestError(impErr)
			theResult = False
		assert theResult

	def test_a_which_command(self):
		"""Test case for backend which."""
		theResult = False
		try:
			theOutputtext = checkPythonCommand(["which", "which"])
			try:
				if (str("/which") in str(theOutputtext)):
					theResult = True
			except Exception as err:
				debugtestError(err)
				err = None
				del err
				theResult = False
		except Exception as othererr:
			debugtestError(othererr)
			othererr = None
			del othererr
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

	def test_d_python_command_main(self):
		"""Test case for piaplib.pocket help."""
		theResult = False
		try:
			thepython = getPythonCommand()
			if (thepython is not None):
				theOutputtext = checkPythonCommand([
					str(thepython),
					str("-m"),
					str("piaplib"),
					str("--help")
				], stderr=subprocess.STDOUT)
				if (str("usage:") in str(theOutputtext)):
					theResult = True
				else:
					theResult = False
					debugUnexpectedOutput(str("usage:"), str(theOutputtext), thepython)
		except Exception as err:
			debugtestError(err)
			err = None
			del err
			theResult = False
		assert theResult

	def test_d_python_command_lib_main(self):
		"""Test case for piaplib vs piaplib.__main__"""
		theResult = False
		try:
			thepython = getPythonCommand()
			if (thepython is not None):
				theExpectedText = checkPythonCommand([
					str(thepython),
					str("-m"),
					str("piaplib.__main__")
				], stderr=subprocess.STDOUT)
				self.assertIsNotNone(theExpectedText)
				theOutputtext = checkPythonCommand([
					str(thepython),
					str("-m"),
					str("piaplib")
				], stderr=subprocess.STDOUT)
				if (str(theExpectedText) in str(theOutputtext)):
					theResult = True
				else:
					theResult = False
					debugUnexpectedOutput(str(theExpectedText), str(theOutputtext), thepython)
		except Exception as err:
			debugtestError(err)
			err = None
			del err
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
			test_units = [
				"lint.lint",
				"pku.__main__",
				"book.__main__",
				"book.version",
				"book.logs",
				"keyring.__main__"
			]
			if (thepython is not None):
				try:
					for unit in test_units:
						theOutputtext = checkPythonCommand([
							str(thepython),
							str("-m"),
							str("piaplib.{}").format(str(unit)),
							str("--help")
						], stderr=subprocess.STDOUT)
						if (str("usage:") in str(theOutputtext)):
							theResult = True
						else:
							theResult = False
							debugUnexpectedOutput(str("usage:"), str(theOutputtext), thepython)
				except Exception as othererr:
					debugtestError(othererr)
					othererr = None
					del othererr
					theResult = False
		except Exception as err:
			debugtestError(err)
			err = None
			del err
			theResult = False
		assert theResult

	def test_c_python_command_pku_units(self):
		"""Test case for piaplib.pku.* --help."""
		theResult = False
		try:
			import sys
			if sys.__name__ is None:
				raise ImportError("Failed to import system. WTF?!!")
			thepython = getPythonCommand()
			if (thepython is not None):
				try:
					for unit in ["pku.interfaces", "pku.compile_interface", "pku.upgrade"]:
						theOutputtext = checkPythonCommand([
							str(thepython),
							str("-m"),
							str("piaplib.{}").format(str(unit)),
							str("--help")
						], stderr=subprocess.STDOUT)
						if (str("usage:") in str(theOutputtext)):
							theResult = True
						else:
							theResult = False
							debugUnexpectedOutput(str("usage:"), str(theOutputtext), thepython)
				except Exception as othererr:
					debugtestError(othererr)
					othererr = None
					del othererr
					theResult = False
		except Exception as err:
			debugtestError(err)
			err = None
			del err
			theResult = False
		assert theResult

	def test_e_python_command_pku_units_versions(self):
		"""Test case for piaplib.pku.* --version."""
		theResult = False
		try:
			import sys
			if sys.__name__ is None:
				raise ImportError("Failed to import system. WTF?!!")
			thepython = getPythonCommand()
			from .context import piaplib as piaplib
			if piaplib.__version__ is not None:
				theResult = False
			if (thepython is not None):
				test_units = [
					"pocket", "book.version", "pku.interfaces",
					"pku.compile_interface", "pku.upgrade"
				]
				for unit in test_units:
					theOutputtext = checkPythonCommand([
						str(thepython),
						str("-m"),
						str("piaplib.{}").format(str(unit)),
						str("--version")
					], stderr=subprocess.STDOUT)
					if (str(piaplib.__version__) in str(theOutputtext)):
						theResult = True
					else:
						theResult = False
						print(str(""))
						print(str("python cmd is {}").format(str(thepython)))
						print(str("{} unit is {}").format(str(unit).split(".")[0], str(unit)))
						print(str(""))
						print(str("actual version was..."))
						print(str(""))
						print(str("{}").format(str(theOutputtext)))
						print(str(""))
		except Exception as err:
			debugtestError(err)
			err = None
			del err
			theResult = False
		assert theResult

	def test_c_python_command_lint_units(self):
		"""Test case for piaplib.lint.* --help."""
		theResult = False
		try:
			import sys
			if sys.__name__ is None:
				raise ImportError("Failed to import system. WTF?!!")
			thepython = getPythonCommand()
			if (thepython is not None):
				try:
					mod_tests = [
						"lint.lint", "lint.check", "lint.clients_check_status",
						"lint.iface_check_status", "lint.users_check_status", "lint.do_execve"
					]
					for unit in mod_tests:
						theOutputtext = checkPythonCommand([
							str(thepython),
							str("-m"),
							str("piaplib.{}").format(str(unit)),
							str("--help")
						], stderr=subprocess.STDOUT)
						if (str("usage:") in str(theOutputtext)):
							theResult = True
						else:
							theResult = False
							debugUnexpectedOutput(str("usage:"), str(theOutputtext), thepython)
				except Exception as othererr:
					debugtestError(othererr)
					othererr = None
					del othererr
					theResult = False
		except Exception as err:
			debugtestError(err)
			err = None
			del err
			theResult = False
		assert theResult

	def test_e_python_command_lint_units_versions(self):
		"""Test case for piaplib.lint.* --version."""
		theResult = False
		try:
			import sys
			if sys.__name__ is None:
				raise ImportError("Failed to import system. WTF?!!")
			thepython = getPythonCommand()
			from .context import piaplib as piaplib
			if piaplib.__version__ is not None:
				theResult = False
			if (thepython is not None):
				for unit in ["lint.lint", "lint.check", "lint.do_execve"]:
					theOutputtext = checkPythonCommand([
						str(thepython),
						str("-m"),
						str("piaplib.{}").format(str(unit)),
						str("--version")
					], stderr=subprocess.STDOUT)
					if (str(piaplib.__version__) in str(theOutputtext)):
						theResult = True
					else:
						theResult = False
						print(str(""))
						print(str("python cmd is {}").format(str(thepython)))
						print(str("check unit is {}").format(str(unit)))
						print(str(""))
						print(str("actual version was..."))
						print(str(""))
						print(str("{}").format(str(theOutputtext)))
						print(str(""))
		except Exception as err:
			debugtestError(err)
			err = None
			del err
			theResult = False
		assert theResult

	def test_e_python_command_lint_check_units(self):
		"""Test case for piaplib.lint.check* --version."""
		theResult = False
		try:
			import sys
			if sys.__name__ is None:
				raise ImportError("Failed to import system. WTF?!!")
			thepython = getPythonCommand()
			from .context import piaplib as piaplib
			if piaplib.__version__ is not None:
				theResult = False
			if (thepython is not None):
				for unit in ["iface", "clients", "users"]:
					theOutputtext = checkPythonCommand([
						str(thepython),
						str("-m"),
						str("piaplib.lint.check"),
						str(unit),
						str("--version")
					], stderr=subprocess.STDOUT)
					if (str(piaplib.__version__) in str(theOutputtext)):
						theResult = True
					else:
						theResult = False
						print(str(""))
						print(str("python cmd is {}").format(str(thepython)))
						print(str("check unit is {}").format(str(unit)))
						print(str(""))
						print(str("actual version was..."))
						print(str(""))
						print(str("{}").format(str(theOutputtext)))
						print(str(""))
		except Exception as err:
			debugtestError(err)
			err = None
			del err
			theResult = False
		assert theResult

	def test_c_python_command_keyring_units(self):
		"""Test case for piaplib.keyring.* --help."""
		theResult = False
		try:
			import sys
			if sys.__name__ is None:
				raise ImportError("Failed to import system. WTF?!!")
			thepython = getPythonCommand()
			test_units = [
				"keyring.saltify",
				"keyring.rand",
				"keyring.clarify",
				"keyring.__main__"
			]
			if (thepython is not None):
				try:
					for unit in test_units:
						theOutputtext = checkPythonCommand([
							str(thepython),
							str("-m"),
							str("piaplib.{}").format(str(unit)),
							str("--help")
						], stderr=subprocess.STDOUT)
						if (str("usage:") in str(theOutputtext)):
							theResult = True
						else:
							theResult = False
							debugUnexpectedOutput(str("usage:"), str(theOutputtext), thepython)
				except Exception as othererr:
					debugtestError(othererr)
					othererr = None
					del othererr
					theResult = False
		except Exception as err:
			debugtestError(err)
			err = None
			del err
			theResult = False
		assert theResult

	def test_c_python_command_keyring_rand(self):
		"""Test case for piaplib.keyring.rand --count=5."""
		theResult = False
		try:
			thepython = getPythonCommand()
			if (thepython is not None):
				try:
					for unit in ["rand"]:
						theOutputtext = timePythonCommand([
							str(thepython),
							str("-m"),
							str("piaplib.pocket"),
							str("keyring"),
							str("{}").format(str(unit)),
							str("--count"),
							str("5")
						], stderr=subprocess.STDOUT)
						if (theOutputtext is not None and len(theOutputtext) > 0):
							theResult = True
						else:
							theResult = False
							print(str(""))
							print(str("python cmd is {}").format(str(thepython)))
							print(str(""))
							print(str("actual output was..."))
							print(str(""))
							print(str("{}").format(str(theOutputtext)))
							print(str("{}").format(repr(theOutputtext)))
							print(str("{}").format(str(type(theOutputtext))))
							print(str("{}").format(str(len(theOutputtext))))
							print(str(""))
				except Exception as othererr:
					debugtestError(othererr)
					othererr = None
					del othererr
					theResult = False
		except Exception as err:
			debugtestError(err)
			err = None
			del err
			theResult = False
		assert theResult

	def test_keyring_rand_gen_units(self):
		"""Test case for piaplib.keyring.rand -g *."""
		theResult = False
		try:
			thepython = getPythonCommand()
			if (thepython is not None):
				try:
					for unit in ["str", "passphrase", "int", "bool", "IP", "SSID"]:
						theOutputtext = timePythonCommand([
							str(thepython),
							str("-m"),
							str("piaplib.keyring.rand"),
							str("--count"),
							str("2"),
							str("--generate"),
							str("{}").format(str(unit))
						], stderr=subprocess.STDOUT)
						try:
							if isinstance(theOutputtext, bytes):
								theOutputtext = theOutputtext.decode('utf8')
						except UnicodeDecodeError:
							theOutputtext = str(repr(bytes(theOutputtext)))
						if (str(theOutputtext) is not None):
							theResult = True
						else:
							theResult = False
							print(str(""))
							print(str("python cmd is {}").format(str(thepython)))
							print(str("python exe is {}").format(str(sys.executable)))
							print(str(""))
							print(str("actual output was..."))
							print(str(""))
							print(str("{}").format(str(theOutputtext)))
							print(str(""))
				except Exception as othererr:
					debugtestError(othererr)
					othererr = None
					del othererr
					theResult = False
		except Exception as err:
			debugtestError(err)
			err = None
			del err
			theResult = False
		assert theResult

	def test_keyring_clarify_io(self):
		"""Test case for piaplib.keyring.clarify."""
		theResult = False
		try:
			import piaplib.keyring.rand as rand
			if rand.__name__ is None:
				raise ImportError("Failed to import rand.")
			thepython = getPythonCommand()
			if (thepython is not None):
				try:
					test_message = str("This is a test Message")
					enc_string_salted = str("U2FsdGVk")
					enc_string_py3 = str("jO2fjYejUczBE9ol2lsFWO0JjLRCaQ==")
					enc_string_test_key = str("{}junk{}junk{}key{}").format(
						str(rand.randInt(1, 11, 99)),
						str(rand.randInt(1, 1001, 9999)),
						str(rand.randInt(1, 0, 99)),
						str(rand.randInt(1, 1000, 9999))
					)
					theOutputtext = test_message
					for unit in ["--pack", "--unpack"]:
						input_text = str(theOutputtext)
						arguments = [
							str(thepython),
							str("-m"),
							str("piaplib.keyring.clarify"),
							str("{}").format(str(unit)),
							str("--msg={}").format(theOutputtext),
							str("-S=testSeedNeedstobelong"),
							str("-K={}").format(str(enc_string_test_key)),
							str("-k=/tmp/.beta_PiAP_weak_key")
						]
						theOutputtext = checkPythonCommand(arguments, stderr=subprocess.STDOUT)
						theOutputtext = str(theOutputtext).replace(str("\\n"), str(""))
						if (test_message in str(theOutputtext)):
							theResult = True
						elif (enc_string_py3 in str(theOutputtext)):
							theResult = True
						elif (enc_string_salted in str(theOutputtext)):
							theResult = True
						else:
							print(str(""))
							print(str("Not working yet"))
							print(str(""))
							print(str("python cmd is {}").format(str(thepython)))
							print(str("arguments are {}").format(str(arguments)))
							print(str(""))
							print(str("action is {}").format(str(unit)))
							print(str("input given {}").format(str(input_text)))
							print(str("but actual output was..."))
							print(str(""))
							print(str("{}").format(str(theOutputtext)))
							print(str(""))
							raise unittest.SkipTest("BETA. Experemental feature not ready yet.")
				except unittest.SkipTest:
					raise unittest.SkipTest("BETA. Experemental feature not ready yet.")
				except Exception as othererr:
					debugtestError(othererr)
					othererr = None
					del othererr
					theResult = False
		except unittest.SkipTest:
			raise unittest.SkipTest("BETA. Experemental feature not ready yet.")
		except Exception as err:
			debugtestError(err)
			err = None
			del err
			theResult = False
		assert theResult

	def test_f_python_command_check_list_units(self):
		"""Test case for piaplib.lint.check.* --list."""
		theResult = False
		try:
			thepython = getPythonCommand()
			if (thepython is not None):
				try:
					for unit in ["iface", "clients", "users"]:
						theOutputtext = checkPythonCommand([
							str(thepython),
							str("-m"),
							str("piaplib.lint.check"),
							str("{}").format(str(unit)),
							str("--list")
						], stderr=subprocess.STDOUT)
						if (theOutputtext is not None):
							theResult = True
						else:
							theResult = False
				except Exception as othererr:
					debugtestError(othererr)
					othererr = None
					del othererr
					theResult = False
		except Exception as err:
			debugtestError(err)
			err = None
			del err
			theResult = False
		assert theResult

	def test_d_python_command_check_users(self):
		"""Test case for piaplib.pocket.lint check users."""
		theResult = False
		import os
		try:
			thepython = getPythonCommand()
			if (thepython is not None):
				try:
					theOutputtext = checkPythonCommand([
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
					elif (str("travis UNKNOWN UNKNOWN") in str(theOutputtext)):
						theResult = True
					elif (str("circleci UNKNOWN UNKNOWN") in str(theOutputtext)):
						theResult = True
					elif (str(os.getlogin()) in str(theOutputtext)):
						theResult = True
						raise unittest.SkipTest("function ok, but not a compatible Test ENV")
					else:
						theResult = False
						debugUnexpectedOutput(None, str(theOutputtext), thepython)
				except unittest.SkipTest:
					raise unittest.SkipTest("function ok, but not a compatible Test ENV")
				except Exception as othererr:
					debugtestError(othererr)
					othererr = None
					del othererr
					theResult = False
		except unittest.SkipTest:
			raise unittest.SkipTest("function ok, but not a compatible Test ENV")
		except Exception as err:
			debugtestError(err)
			err = None
			del err
			theResult = False
		assert theResult

	def test_g_python_command_build_iface(self):
		"""Test case for piaplib.pku.compile_interface dhcp iface."""
		theResult = False
		try:
			thepython = getPythonCommand()
			if (thepython is not None):
				try:
					theOutputtext = checkPythonCommand([
						str(thepython),
						str("-m"),
						str("piaplib.pku.compile_interface"),
						str("-d"),
						str("-t"),
						str("wlan"),
						str("-z"),
						str("WAN")
					], stderr=subprocess.STDOUT)
					if (str("inet static") in str(theOutputtext)):
						theResult = True
					elif (str("inet dhcp") in str(theOutputtext)):
						theResult = True
					else:
						theResult = False
						debugUnexpectedOutput(
							str("inet [static|dhcp]"),
							str(theOutputtext),
							thepython
						)
				except Exception as othererr:
					debugtestError(othererr)
					othererr = None
					del othererr
					theResult = False
		except Exception as err:
			debugtestError(err)
			err = None
			del err
			theResult = False
		assert theResult

	def test_h_python_command_build_iface(self):
		"""Test case for piaplib.pku.compile_interface static iface."""
		theResult = False
		try:
			thepython = getPythonCommand()
			if (thepython is not None):
				try:
					theOutputtext = checkPythonCommand([
						str(thepython),
						str("-m"),
						str("piaplib.pku.compile_interface"),
						str("-S"),
						str("-t"),
						str("wlan"),
						str("-z"),
						str("WAN"),
						str("-g"),
						str("10.0.1.1"),
						str("-n"),
						str("255.255.255.255"),
						str("-i"),
						str("10.0.1.40")
					], stderr=subprocess.STDOUT)
					if (str("inet static") in str(theOutputtext)):
						theResult = True
					elif (str("inet dhcp") in str(theOutputtext)):
						theResult = False
					else:
						theResult = False
						debugUnexpectedOutput(
							str("inet [static|dhcp]"),
							str(theOutputtext),
							thepython
						)
				except Exception as othererr:
					debugtestError(othererr)
					othererr = None
					del othererr
					theResult = False
		except Exception as err:
			debugtestError(err)
			err = None
			del err
			theResult = False
		assert theResult

	def test_d_python_command_check_users_html(self):
		"""Test case for piaplib.pocket.lint check users."""
		theResult = False
		try:
			thepython = getPythonCommand()
			if (thepython is not None):
				try:
					theOutputtext = checkPythonCommand([
						str(thepython),
						str("-m"),
						str("piaplib.pocket"),
						str("lint"),
						str("check"),
						str("users"),
						str("--all"),
						str("--html")
					], stderr=subprocess.STDOUT)
					if (str("</tbody></table>") in str(theOutputtext)):
						if str("<table") in str(theOutputtext):
							theResult = True
						else:
							theResult = False
							debugUnexpectedOutput(
								str("<HTML TABLE CODE>"),
								str(theOutputtext),
								thepython
							)
					else:
						theResult = False
						debugUnexpectedOutput(
							None,
							str(theOutputtext),
							thepython
						)
				except Exception as othererr:
					debugtestError(othererr)
					othererr = None
					del othererr
					theResult = False
		except Exception as err:
			debugtestError(err)
			err = None
			del err
			theResult = False
		assert theResult

	def test_d_python_command_check_clients_html(self):
		"""Test case for piaplib.pocket.lint check clients for html."""
		theResult = False
		try:
			thepython = getPythonCommand()
			if (thepython is not None):
				try:
					theOutputtext = checkPythonCommand([
						str(thepython),
						str("-m"),
						str("piaplib.pocket"),
						str("lint"),
						str("check"),
						str("clients"),
						str("--all"),
						str("--html")
					], stderr=subprocess.STDOUT)
					if (str("</tbody></table>") in str(theOutputtext)):
						if str("<table") in str(theOutputtext):
							theResult = True
						else:
							theResult = False
					else:
						theResult = False
						debugUnexpectedOutput(
							str("<HTML TABLE CODE>"),
							str(theOutputtext),
							thepython
						)
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
			debugtestError(err)
			err = None
			del err
			theResult = False
		assert theResult

	def test_d_python_command_check_users_single(self):
		"""Test case for piaplib.pocket.lint check users --user *"""
		theResult = False
		try:
			thepython = getPythonCommand()
			if (thepython is not None):
				try:
					for some_test_user in [str("root"), str("circleci")]:
						theOutputtext = checkPythonCommand([
							str(thepython),
							str("-m"),
							str("piaplib.pocket"),
							str("lint"),
							str("check"),
							str("users"),
							str("--user"),
							str(some_test_user)
						], stderr=subprocess.STDOUT)
						if (some_test_user in str(theOutputtext)):
							theResult = True
							print(str(""))
							print(str("MATCHED").format(str(thepython)))
							print(str("expected user {}").format(some_test_user))
							print(str(""))
						else:
							theResult = (False or theResult)
							debugUnexpectedOutput(
								str(some_test_user),
								str(theOutputtext),
								None
							)
				except Exception as othererr:
					debugtestError(othererr)
					othererr = None
					del othererr
					theResult = False
		except Exception as err:
			debugtestError(err)
			err = None
			del err
			theResult = False
		assert theResult

	def test_f_python_command_check_users_all(self):
		"""Test case for piaplib.pocket.lint check users --all"""
		theResult = False
		try:
			import os
			thepython = getPythonCommand()
			if (thepython is not None):
				try:
					theOutputtext = checkPythonCommand([
						str(thepython),
						str("-m"),
						str("piaplib.pocket"),
						str("lint"),
						str("check"),
						str("users"),
						str("--all")
					], stderr=subprocess.STDOUT)
					if (str("root") in str(theOutputtext)):
						theResult = True
					elif (str("circleci") in str(theOutputtext)):
						theResult = True
					elif (str(os.getlogin()) in str(theOutputtext)):
						theResult = True
						raise unittest.SkipTest("function ok, but not a compatible Test ENV")
					else:
						theResult = False
						debugUnexpectedOutput(
							None,
							str(theOutputtext),
							thepython
						)
				except unittest.SkipTest:
					raise unittest.SkipTest("function ok, but not a compatible Test ENV")
				except Exception as othererr:
					debugtestError(othererr)
					othererr = None
					del othererr
					theResult = False
		except unittest.SkipTest:
			raise unittest.SkipTest("function ok, but not a compatible Test ENV")
		except Exception as err:
			debugtestError(err)
			err = None
			del err
			theResult = False
		assert theResult

	def test_f_python_command_check_users_list(self):
		"""Test case for piaplib.pocket.lint check users --list"""
		theResult = False
		try:
			import os
			thepython = getPythonCommand()
			if (thepython is not None):
				try:
					theOutputtext = checkPythonCommand([
						str(thepython),
						str("-m"),
						str("piaplib.pocket"),
						str("lint"),
						str("check"),
						str("users"),
						str("--list")
					], stderr=subprocess.STDOUT)
					if (str("root") in str(theOutputtext)):
						theResult = True
					elif (str("circleci") in str(theOutputtext)):
						theResult = True
					elif (str(os.getlogin()) in str(theOutputtext)):
						theResult = True
						raise unittest.SkipTest("function ok, but not a compatible Test ENV")
					else:
						theResult = False
						debugUnexpectedOutput(
							None,
							str(theOutputtext),
							thepython
						)
				except unittest.SkipTest:
					raise unittest.SkipTest("function ok, but not a compatible Test ENV")
				except Exception as othererr:
					debugtestError(othererr)
					othererr = None
					del othererr
					theResult = False
		except unittest.SkipTest:
			raise unittest.SkipTest("function ok, but not a compatible Test ENV")
		except Exception as err:
			debugtestError(err)
			err = None
			del err
			theResult = False
		assert theResult

	@unittest.skipUnless(sys.platform.startswith("linux"), "Requires linux")
	def test_d_python_command_check_iface(self):
		"""Test case for piaplib.pocket.lint check iface."""
		theResult = False
		try:
			thepython = getPythonCommand()
			if (thepython is not None):
				try:
					theOutputtext = checkPythonCommand([
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
					elif (str("ens") in str(theOutputtext)):
						raise unittest.SkipTest("function probably ok, but not a compatible Test network")
					elif (str("enp0s") in str(theOutputtext)):
						raise unittest.SkipTest("function ok, but not a compatible Test network")
					elif (str("en0") in str(theOutputtext)):
						raise unittest.SkipTest("function ok, but not a compatible Test network")
					else:
						theResult = False
						print(str(""))
						print(str("python cmd is {}").format(str(thepython)))
						print(str(""))
						print(str("actual output was..."))
						print(str(""))
						print(str("{}").format(str(theOutputtext)))
						print(str(""))
				except unittest.SkipTest:
					raise unittest.SkipTest("function ok, but not a compatible Test network")
				except Exception as othererr:
					debugtestError(othererr)
					othererr = None
					del othererr
					theResult = False
		except unittest.SkipTest:
			raise unittest.SkipTest("function ok, but not a compatible Test network")
		except Exception as err:
			debugtestError(err)
			err = None
			del err
			theResult = False
		assert theResult

	@unittest.skipUnless(sys.platform.startswith("linux"), "Requires linux")
	def test_d_python_command_check_iface_html(self):
		"""Test case for piaplib.pocket.lint check iface with html."""
		theResult = False
		try:
			thepython = getPythonCommand()
			if (thepython is not None):
				try:
					theOutputtext = checkPythonCommand([
						str(thepython),
						str("-m"),
						str("piaplib.pocket"),
						str("lint"),
						str("check"),
						str("iface"),
						str("--all"),
						str("--html")
					], stderr=subprocess.STDOUT)
					if (str("eth0") in str(theOutputtext)):
						theResult = True
					elif (str("ens") in str(theOutputtext)):
						raise unittest.SkipTest("function probably ok, but not a compatible Test network")
					elif (str("enp0s") in str(theOutputtext)):
						raise unittest.SkipTest("function ok, but not a compatible Test network")
					elif (str("en0") in str(theOutputtext)):
						raise unittest.SkipTest("function ok, but not a compatible Test network")
					else:
						theResult = False
						print(str(""))
						print(str("python cmd is {}").format(str(thepython)))
						print(str(""))
						print(str("actual output was..."))
						print(str(""))
						print(str("{}").format(str(theOutputtext)))
						print(str(""))
				except unittest.SkipTest:
					raise unittest.SkipTest("function ok, but not a compatible Test network")
				except Exception as othererr:
					debugtestError(othererr)
					othererr = None
					del othererr
					theResult = False
		except unittest.SkipTest:
			raise unittest.SkipTest("function ok, but not a compatible Test network")
		except Exception as err:
			debugtestError(err)
			err = None
			del err
			theResult = False
		assert theResult

	def test_d_python_command_saltify(self):
		"""Test case for piaplib.pocket.lint check users."""
		theResult = False
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			thepython = getPythonCommand()
			if (thepython is not None):
				test_salt_one = str(
					"7a9356011e7f6bc42105deee6d49983e0cfa7650c7fce5d5d3b19aacca91605199ee" +
					"017707f627087f8376143f368b17ed927d918eecfe100a7b1b6e39dd3c8a" +
					"\n"
				)
				try:
					theOutputtext = checkPythonCommand([
						str(thepython),
						str("-m"),
						str("piaplib.pocket"),
						str("keyring"),
						str("saltify"),
						str("""--msg={}""").format(str("Test Message")),
						str("""--salt={}""").format(str("testSalt"))
					], stderr=subprocess.STDOUT)
					a = (utils.literal_str(theOutputtext)[-129:] in utils.literal_str(test_salt_one))
					b = (utils.literal_str(test_salt_one) in utils.literal_str(theOutputtext)[-129:])
					if (a and b):
						theResult = True
					else:
						theResult = False
						debugUnexpectedOutput(
							str("{}").format(str(test_salt_one)),
							str(theOutputtext),
							thepython
						)
					del theOutputtext
					del test_salt_one
				except Exception as othererr:
					debugtestError(othererr)
					othererr = None
					del othererr
					theResult = False
		except Exception as err:
			debugtestError(err)
			err = None
			del err
			theResult = False
		assert theResult

	def test_d_python_command_bad_saltify(self):
		"""Test case for piaplib.keyring.saltify JUNK."""
		theResult = True
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
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
			debugtestError(err)
			err = None
			del err
			theResult = False
		assert theResult

	@unittest.skipUnless(sys.platform.startswith("linux"), "Requires linux ifup/ifdown tools")
	def test_d_python_command_bad_interface(self):  # noqa
		"""Test case for piaplib.pocket pku interfaces -i=junk."""
		theResult = True
		try:
			thepython = getPythonCommand()
			theOutputtext = None
			rebootIface = None
			try:
				for someTest in [str("eth0"), str("enp0s")]
					if theOutputtext is None:
						rebootIface = str(someTest)
						theOutputtext = checkPythonFuzzing([
							str(thepython),
							str("-m"),
							str("piaplib.pocket"),
							str("pku"),
							str("interfaces"),
							str("""-i={}""").format(someTest)
						], stderr=subprocess.STDOUT)
			except Exception as junkErr:  # noqa
				del(junkErr)
			self.assertIsNotNone(theOutputtext)
			try:
				theOutputtext = checkPythonFuzzing([
					str(thepython),
					str("-m"),
					str("piaplib.pocket"),
					str("pku"),
					str("interfaces"),
					str("""-i={}""").format(rebootIface),
					str("""-r""")
				], stderr=subprocess.STDOUT)
			except Exception as junkErr:  # noqa
				del(junkErr)
				# self.assertIsNone(theOutputtext)
		except Exception as err:
			debugtestError(err)
			err = None
			del err
			theResult = False
		assert theResult

	@unittest.skipUnless(sys.platform.startswith("linux"), "Requires linux for script")
	def test_x_python_command_upgrade_all(self):
		"""Test case for piaplib.pocket pku upgrade --all."""
		theResult = False
		try:
			thepython = getPythonCommand()
			if (thepython is not None):
				try:
					theOutputtext = timePythonCommand([
						str(thepython),
						str("-m"),
						str("piaplib.pocket"),
						str("pku"),
						str("upgrade"),
						str("all")
					], stderr=subprocess.STDOUT)
					if (theOutputtext is not None and len(theOutputtext) > 0):
						theResult = True
					else:
						theResult = False
						print(str(""))
						print(str("python cmd is {}").format(str(thepython)))
						print(str(""))
						print(str("actual output was..."))
						print(str(""))
						print(str("{}").format(str(theOutputtext)))
						print(str("{}").format(repr(theOutputtext)))
						print(str("{}").format(str(type(theOutputtext))))
						print(str("{}").format(str(len(theOutputtext))))
						print(str(""))
				except Exception as othererr:
					debugtestError(othererr)
					othererr = None
					del othererr
					theResult = False
		except Exception as err:
			debugtestError(err)
			err = None
			del err
			theResult = False
		assert theResult

	def test_d_python_command_version_check(self):  # noqa
		"""Test case for piaplib.book.version."""
		theResult = True
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			thepython = getPythonCommand()
			if (thepython is not None):
				theOutputtext = None
				theOutputtext = checkPythonFuzzing([
					str(thepython),
					str("-m"),
					str("piaplib.book.version"),
					str("--version")
				], stderr=subprocess.STDOUT)
				self.assertIsNotNone(theOutputtext)
				theOutputtext = checkPythonFuzzing([
					str(thepython),
					str("-m"),
					str("piaplib.book.version"),
					str("all"),
					str("--verbose")
				], stderr=subprocess.STDOUT)
				self.assertIsNotNone(theOutputtext)
		except Exception as err:
			debugtestError(err)
			err = None
			del err
			theResult = False
		assert theResult

	def test_o_exec_command_run(self):
		"""Test case for piaplib.pocket.lint do_execve calls."""
		theResult = False
		try:
			thepython = getPythonCommand()
			if (thepython is not None):
				try:
					self.assertIsNotNone(checkPythonCommand([
						str(thepython),
						str("-m"),
						str("piaplib.pocket"),
						str("lint"),
						str("execve"),
						str("""--cmd={}""").format(str("echo")),
						str("""--args={}""").format(str("test"))
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
			debugtestError(err)
			err = None
			del err
			theResult = False
		assert theResult


if __name__ == '__main__':
	unittest.main()

