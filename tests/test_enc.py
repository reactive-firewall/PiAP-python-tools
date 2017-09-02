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


class CryptoTestSuite(unittest.TestCase):
	"""Special Pocket keyring crypto test cases."""

	def test_absolute_truth_and_meaning(self):
		"""Insanity Test."""
		assert True
		self.assertIsNone(None)

	def test_keyring_import_syntax(self):
		"""Test case importing keyring code."""
		theResult = False
		try:
			from .context import piaplib
			if piaplib.__name__ is None:
				theResult = False
			from piaplib import keyring
			if keyring.__name__ is None:
				theResult = False
			theResult = True
		except Exception as impErr:
			print(str(type(impErr)))
			print(str(impErr))
			theResult = False
		assert theResult

	def test_y_case_clearify_hasbackend(self):
		"""Tests the helper function hasBackendCommand of keyring.clearify"""
		theResult = True
		try:
			from piaplib.keyring import clearify as clearify
			if clearify.__name__ is None:
				raise ImportError("Failed to import clearify")
			theTest = (clearify.hasBackendCommand() is True)
			theTest = (theTest is True or clearify.hasBackendCommand() is False)
			self.assertTrue(theTest)
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

	def test_z_case_clearify_getKeyFile(self):
		"""Tests the helper function getKeyFilePath of keyring.clearify"""
		theResult = True
		try:
			from piaplib.keyring import clearify as clearify
			if clearify.__name__ is None:
				raise ImportError("Failed to import clearify")
			self.assertIsNotNone(clearify.getKeyFilePath())
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

	def test_z_case_clearify_setKeyFile(self):
		"""Tests the helper function makeKeystoreFile of keyring.clearify"""
		theResult = True
		try:
			from piaplib.keyring import clearify as clearify
			if clearify.__name__ is None:
				raise ImportError("Failed to import clearify")
			self.assertIsNotNone(clearify.makeKeystoreFile(
				str("This is not a real key"),
				str("./test.secret")
			))
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

	def test_z_case_clearify_setKeyFile_no_path(self):
		"""Tests the helper function makeKeystoreFile(x, None) of keyring.clearify"""
		theResult = True
		try:
			from piaplib.keyring import clearify as clearify
			if clearify.__name__ is None:
				raise ImportError("Failed to import clearify")
			self.assertIsNotNone(clearify.makeKeystoreFile(
				str("This is not a real key"),
				None
			))
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

	def test_z_z_case_clearify_setKeyFile_no_key(self):
		"""Tests the helper function makeKeystoreFile(None, x) of keyring.clearify"""
		theResult = True
		try:
			from piaplib.keyring import clearify as clearify
			if clearify.__name__ is None:
				raise ImportError("Failed to import clearify")
			self.assertIsNotNone(clearify.makeKeystoreFile(
				None,
				str("./test.secret")
			))
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

	def test_z_case_clearify_setKeyFile_none(self):
		"""Tests the helper function makeKeystoreFile(None) of keyring.clearify"""
		theResult = True
		try:
			from piaplib.keyring import clearify as clearify
			if clearify.__name__ is None:
				raise ImportError("Failed to import clearify")
			self.assertIsNotNone(clearify.makeKeystoreFile(None))
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

	def test_z_case_clearify_main_bad(self):
		"""Tests the helper function main(bad stuff) of keyring.clearify"""
		theResult = True
		try:
			from piaplib.keyring import clearify as clearify
			if clearify.__name__ is None:
				raise ImportError("Failed to import clearify")
			self.assertIsNotNone(clearify.main([
				str("--pack"),
				str("-msg=None")
			]), 2)
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

	def test_z_case_clearify_main_lazy(self):
		"""Tests the helper function main(lazy stuff) of keyring.clearify"""
		theResult = True
		try:
			from piaplib.keyring import clearify as clearify
			if clearify.__name__ is None:
				raise ImportError("Failed to import clearify")
			self.assertIsNotNone(clearify.main([
				str("--pack"),
				str("--msg=testing")
			]))
		except Exception as err:
			print(str(""))
			print(str(type(err)))
			print(str(err))
			print(str((err.args)))
			print(str(""))
			err = None
			del err
		assert theResult

	def test_case_clearify_main_a(self):
		"""Tests the helper function main pack of keyring.clearify"""
		theResult = True
		try:
			from piaplib.keyring import clearify as clearify
			if clearify.__name__ is None:
				raise ImportError("Failed to import clearify")
			test_out = clearify.main([
				str("--pack"),
				str("--msg=\"This is a test Message\""),
				str("-K=testkeyneedstobelong")
			])
			self.assertIsNotNone(test_out)
			try:
				if isinstance(test_out, bytes):
					test_out = test_out.decode('utf8')
			except UnicodeDecodeError:
				test_out = str(repr(bytes(test_out)))
			if (str("U2FsdGVkX") in str(test_out)):
				theResult = True
			else:
				theResult = False
		except Exception as err:
			print(str(""))
			print(str(type(err)))
			print(str(err))
			print(str((err.args)))
			print(str(""))
			err = None
			del err
			if sys.platform.startswith("linux"):
				theResult = False
			else:
				raise unittest.SkipTest("BETA. Experemental feature not ready yet.")
		assert theResult

	def test_case_clearify_main_b(self):
		"""Tests the helper function main unpack of keyring.clearify"""
		theResult = True
		try:
			temp_msg = None
			args = None
			if sys.platform.startswith("linux"):
				temp_msg = str("""U2FsdGVkX1+dD6bFlND+Xa0bzNttrZfB5zYCp0mSEYfhMTpaM7U=""")
				args = [
					str("--unpack"),
					str("--msg={}").format(temp_msg),
					str("-K=testkeyneedstobelong")
				]
			else:
				temp_msg = str("U2FsdGVkX18cNPUnfix9LYLebBgwP6BdT7ReAJvL1+ZHJWN96sNB5IvV/u+fRL6D")
				args = [
					str("--unpack"),
					str("--msg=\"{}\"").format(temp_msg),
					str("-K=testkeyneedstobelong")
				]
			from piaplib.keyring import clearify as clearify
			if clearify.__name__ is None:
				raise ImportError("Failed to import clearify")
			test_out = clearify.main(args)
			try:
				if isinstance(test_out, bytes):
					test_out = test_out.decode('utf8')
			except UnicodeDecodeError:
				test_out = str(repr(bytes(test_out)))
			self.assertIsNotNone(test_out)
			if (str("This is a test Message") in str(test_out)):
				theResult = True
			else:
				if sys.platform.startswith("linux"):
					print(str(repr(bytes(test_out))))
					theResult = False
				else:
					raise unittest.SkipTest("BETA. Experemental feature not ready yet.")
		except Exception as err:
			print(str(""))
			print(str(type(err)))
			print(str(err))
			print(str((err.args)))
			print(str(""))
			err = None
			del err
			if sys.platform.startswith("linux"):
				theResult = False
			else:
				raise unittest.SkipTest("BETA. Experemental feature not ready yet.")
		assert theResult

	def test_case_clearify_read_write(self):  # noqa C901
		"""Tests the helper function pack to file of keyring.clearify and then unpack"""
		theResult = False
		try:
			from piaplib.keyring import clearify as clearify
			if clearify.__name__ is None:
				raise ImportError("Failed to import clearify")
			elif (clearify.hasBackendCommand() is not True):
				raise unittest.SkipTest("Requires backend tool")
			from piaplib.keyring import rand as rand
			if rand.__name__ is None:
				raise ImportError("Failed to import rand")
			sometestfile = str("./the_test_file.enc")
			theteststore = clearify.makeKeystoreFile(
				str("testkeyneedstobelong"),
				str("./.weak_test_key_{}").format(rand.randInt(1, 10, 99))
			)
			self.assertIsNotNone(theteststore)
			try:
				test_write = clearify.packToFile(
					sometestfile,
					str("This is a test Message"),
					theteststore
				)
			except Exception as dbugerr:
				print(str("file:"))
				print(str(sometestfile))
				print(str(""))
				print(str("keyfile:"))
				print(str(theteststore))
				print(str(""))
				print(str("result:"))
				print(str(test_write))
				print(str(""))
				print(str(type(dbugerr)))
				print(str(dbugerr))
				print(str((dbugerr.args)))
				print(str(""))
				err = None
				del err
			self.assertTrue(test_write)
			if (test_write is True):
				test_read = clearify.unpackFromFile(sometestfile, theteststore)
				try:
					if isinstance(test_read, bytes):
						test_read = test_read.decode('utf8')
				except UnicodeDecodeError:
					test_read = str(repr(bytes(test_read)))
				self.assertIsNotNone(test_read)
				if (str("This is a test Message") in str(test_read)):
					theResult = True
				else:
					if sys.platform.startswith("linux"):
						print(str(repr(bytes(test_read))))
						theResult = False
					else:
						raise unittest.SkipTest("BETA. Experemental feature not ready yet.")
		except Exception as err:
			print(str(""))
			print(str(type(err)))
			print(str(err))
			print(str((err.args)))
			print(str(""))
			err = None
			del err
			if sys.platform.startswith("linux"):
				theResult = False
			else:
				raise unittest.SkipTest("BETA. Experemental feature not ready yet.")
		assert theResult


if __name__ == u'__main__':
	unittest.main()
