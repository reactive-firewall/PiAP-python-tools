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


try:
	from hypothesis import given
	from hypothesis import note
	from hypothesis import assume
	from hypothesis.strategies import text
except Exception as ImportErr:
	def given(*given_arguments, **given_kwargs):
		"""Helpful if you don't have a hypothisis!"""
		return unittest.skip(str("Missing a hypothisis"))

	def text(*args, **kwargs):
		"""Helpful if you don't have a hypothisis!"""
		return str("""This is a test Message.""")

	def note(*args, **kwargs):
		"""Helpful if you don't have a hypothisis!"""
		print(str(*args, **kwargs))

	def assume(condition):
		"""Helpful if you don't have a hypothisis!"""
		if not condition:
			raise unittest.SkipTest(str("Failed test assumption: {}").format(repr(condition)))
		return True


import unittest


sub_proc_bug_message = str(
	"hypothisis ignores bug https://bugs.python.org/issue2320 which has no fix before python 3.2"
)


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

	def test_a_case_clarify_hasbackend(self):
		"""Tests the helper function hasBackendCommand of keyring.clarify"""
		theResult = True
		try:
			from piaplib.keyring import clarify as clarify
			if clarify.__name__ is None:
				raise ImportError("Failed to import clarify")
			theTest = (clarify.hasBackendCommand() is True)
			self.assertIsNotNone(clarify.hasBackendCommand())
			theTest = (theTest is True or clarify.hasBackendCommand() is False)
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

	def test_b_case_clarify_getKeyFile(self):
		"""Tests the helper function getKeyFilePath of keyring.clarify"""
		theResult = True
		try:
			from piaplib.keyring import clarify as clarify
			if clarify.__name__ is None:
				raise ImportError("Failed to import clarify")
			self.assertIsNotNone(clarify.getKeyFilePath())
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

	def test_b_case_clarify_setKeyFile(self):
		"""Tests the helper function makeKeystoreFile of keyring.clarify"""
		theResult = True
		try:
			from piaplib.keyring import clarify as clarify
			if clarify.__name__ is None:
				raise ImportError("Failed to import clarify")
			self.assertIsNotNone(clarify.makeKeystoreFile(
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

	def test_z_case_clarify_setKeyFile_no_path(self):
		"""Tests the helper function makeKeystoreFile(x, None) of keyring.clarify"""
		theResult = True
		try:
			from piaplib.keyring import clarify as clarify
			if clarify.__name__ is None:
				raise ImportError("Failed to import clarify")
			self.assertIsNotNone(clarify.makeKeystoreFile(
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

	def test_z_z_case_clarify_setKeyFile_no_key(self):
		"""Tests the helper function makeKeystoreFile(None, x) of keyring.clarify"""
		theResult = True
		try:
			from piaplib.keyring import clarify as clarify
			if clarify.__name__ is None:
				raise ImportError("Failed to import clarify")
			self.assertIsNotNone(clarify.makeKeystoreFile(
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

	def test_z_case_clarify_setKeyFile_none(self):
		"""Tests the helper function makeKeystoreFile(None) of keyring.clarify"""
		theResult = True
		try:
			from piaplib.keyring import clarify as clarify
			if clarify.__name__ is None:
				raise ImportError("Failed to import clarify")
			self.assertIsNotNone(clarify.makeKeystoreFile(None))
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

	def test_z_case_clarify_main_bad(self):
		"""Tests the helper function main(bad stuff) of keyring.clarify"""
		theResult = True
		try:
			from piaplib.keyring import clarify as clarify
			if clarify.__name__ is None:
				raise ImportError("Failed to import clarify")
			self.assertIsNotNone(clarify.main([
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

	def test_d_case_clarify_main_lazy(self):
		"""Tests the helper function main(lazy stuff) of keyring.clarify"""
		theResult = True
		try:
			from piaplib.keyring import clarify as clarify
			if clarify.__name__ is None:
				raise ImportError("Failed to import clarify")
			self.assertIsNotNone(clarify.main([
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

	def test_case_clarify_main_a(self):
		"""Tests the helper function main pack of keyring.clarify"""
		theResult = True
		try:
			from piaplib.keyring import clarify as clarify
			if clarify.__name__ is None:
				raise ImportError("Failed to import clarify")
			test_out = clarify.main([
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

	def test_case_clarify_main_b(self):
		"""Tests the helper function main unpack of keyring.clarify"""
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
				temp_msg = str(
					"""U2FsdGVkX1/beHoH2ziXWcMFpb3fzzPxQqdeU1tO5UVoBUEnow8T9g=="""
				)
				args = [
					str("--unpack"),
					str("--msg={}").format(temp_msg),
					str("-K=testkeyneedstobelong")
				]
			from piaplib.keyring import clarify as clarify
			if clarify.__name__ is None:
				raise ImportError("Failed to import clarify")
			test_out = clarify.main(args)
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

	def test_case_clarify_write_inverts_read_example(self):
		"""Tests the write then read workflow of keyring.clarify."""
		theResult = False
		someMessageText = str("This is a test Message")
		try:
			from piaplib.keyring import clarify as clarify
			if clarify.__name__ is None:
				raise ImportError("Failed to import clarify")
			elif (clarify.hasBackendCommand() is not True):
				raise unittest.SkipTest("Requires backend tool")
			from piaplib.keyring import rand as rand
			if rand.__name__ is None:
				raise ImportError("Failed to import rand")
			sometestfile = str("./the_test_file.enc")
			theteststore = clarify.makeKeystoreFile(
				str("testkeyneedstobelong"),
				str("./.weak_test_key_{}").format(rand.randInt(1, 10, 99))
			)
			assume((theteststore is not None))
			self.assertIsNotNone(theteststore)
			test_write = clarify.packToFile(
				sometestfile,
				str(someMessageText),
				theteststore
			)
			self.assertTrue(test_write)
			if (test_write is True):
				test_read = clarify.unpackFromFile(sometestfile, theteststore)
				try:
					if isinstance(test_read, bytes):
						test_read = test_read.decode('utf8')
				except UnicodeDecodeError:
					test_read = str(repr(bytes(test_read)))
				self.assertIsNotNone(test_read)
				if (str(someMessageText) in str(test_read)):
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

	@unittest.skipUnless((sys.version_info > (3, 2)), sub_proc_bug_message)
	@given(text())
	def test_case_clarify_write_inverts_read(self, someInput):  # noqa C901
		"""Tests the write then read workflow of keyring.clarify with fuzzing."""
		theResult = False
		assume(isinstance(someInput, str))
		assume(len(str(someInput)) > 3)
		assume(repr(str(someInput)) not in repr(str(repr(someInput))))
		assume(str(someInput) in someInput)
		assume(someInput in str(someInput))
		someMessageText = str(repr(someInput))
		try:
			from piaplib.keyring import clarify as clarify
			if clarify.__name__ is None:
				raise ImportError("Failed to import clarify")
			elif (clarify.hasBackendCommand() is not True):
				raise unittest.SkipTest("Requires backend tool")
			from piaplib.keyring import rand as rand
			if rand.__name__ is None:
				raise ImportError("Failed to import rand")
			sometestfile = str("./the_test_file.enc")
			theteststore = clarify.makeKeystoreFile(
				str("testkeyneedstobelong"),
				str("./.weak_test_key_{}").format(rand.randInt(1, 10, 99))
			)
			assume((theteststore is not None))
			self.assertIsNotNone(theteststore)
			test_write = clarify.packToFile(
				sometestfile,
				str(someMessageText),
				theteststore
			)
			self.assertTrue(test_write)
			note(str("encoded: \"{}\"").format(repr(someMessageText)))
			if (test_write is True):
				test_read = clarify.unpackFromFile(sometestfile, theteststore)
				try:
					if isinstance(test_read, bytes):
						test_read = test_read.decode('utf8')
				except UnicodeDecodeError:
					test_read = str(repr(bytes(test_read)))
				self.assertIsNotNone(test_read)
				if (str(someMessageText) in str(test_read)):
					theResult = True
				else:
					note(str("decoded: \"{}\"").format(repr(test_read)))
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


if __name__ == u'__main__':
	unittest.main()
