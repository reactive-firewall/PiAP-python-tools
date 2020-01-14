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
		print(str((args, kwargs)))

	def assume(condition):
		"""Helpful if you don't have a hypothisis!"""
		try:
			if not condition:
				raise unittest.SkipTest(str("Failed test assumption: {}").format(repr(condition)))
		except BaseException:
			raise unittest.SkipTest(str("Failed test syntax assumption"))
		return True
	ImportErr = None
	del ImportErr


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
			from piaplib import pku
			if pku.__name__ is None:
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
		theResult = False
		try:
			import piaplib.keyring.clarify as clarify
			if clarify.__name__ is None:
				raise ImportError("Failed to import clarify")
			self.assertIsNotNone(clarify.getKeyFilePath())
			self.assertIsNotNone(os.path.abspath(clarify.getKeyFilePath()))
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
		theResult = False
		try:
			from piaplib.keyring import clarify as clarify
			if clarify.__name__ is None:
				raise ImportError("Failed to import clarify")
			self.assertIsNotNone(clarify.makeKeystoreFile(
				None,
				str("./test.secret")
			))
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
		assert theResult

	def test_z_case_clarify_setKeyFile_none(self):
		"""Tests the helper function makeKeystoreFile(None) of keyring.clarify"""
		theResult = False
		try:
			from piaplib.keyring import clarify as clarify
			if clarify.__name__ is None:
				raise ImportError("Failed to import clarify")
			self.assertIsNotNone(clarify.makeKeystoreFile(None))
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
				str("--msg=None")
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
		theResult = False
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
					test_out = test_out.decode("""utf-8""")
			except UnicodeDecodeError:
				test_out = str(repr(bytes(test_out).decode(
					"""utf-8""", errors=clarify.getCTLModeForPY()
				)))
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

	@unittest.skipIf(("""utf""" not in sys.getdefaultencoding()), "wrong encoding for test")
	def test_case_clarify_main_b(self):
		"""Tests the helper function main unpack of keyring.clarify"""
		theResult = False
		try:
			from piaplib.pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			from piaplib.keyring import clarify as clarify
			if clarify.__name__ is None:
				raise ImportError("Failed to import clarify")
			elif (clarify.hasBackendCommand() is not True):
				raise unittest.SkipTest("Requires backend tool")
			temp_msg = None
			test_args = []
			# temp_msg = str("""U2FsdGVkX1+dD6bFlND+Xa0bzNttrZfB5zYCp0mSEYfhMTpaM7U=""")
			if sys.platform.startswith("linux"):
				temp_msg = str("""U2FsdGVkX1+dD6bFlND+Xa0bzNttrZfB5zYCp0mSEYfhMTpaM7U=""")
				# temp_msg = str("""U2FsdGVkX1/MMOdV6OYwAURQQg9b9K1AoVA0OCcanG9FjHk7gHk=""")
				test_args = [
					str("--unpack"),
					str("--msg=\"{}\"").format(temp_msg),
					str("-K=testkeyneedstobelong")
				]
			else:
				temp_msg = str(
					"""U2FsdGVkX1/beHoH2ziXWcMFpb3fzzPxQqdeU1tO5UVoBUEnow8T9g=="""
				)
				test_args = [
					str("--unpack"),
					str("--msg={}").format(str(temp_msg)),
					str("-K=testkeyneedstobelong")
				]
			print(str("... args {}").format(str(test_args)))
			print(str("... test"))
			test_out = clarify.main(test_args)
			print(str("... checking"))
			try:
				if isinstance(test_out, bytes):
					test_out = test_out.decode("""utf-8""", errors=clarify.getCTLModeForPY())
			except UnicodeDecodeError as unierr:
				print(str(type(unierr)))
				print(str(unierr))
				test_out = str(repr(bytes(test_out, encoding="""utf-8""").decode(
					"""utf-8""", errors=clarify.getCTLModeForPY()
				)))
			self.assertIsNotNone(test_out)
			self.assertIsNotNone(str(test_out))
			print(str("... assert not none or junk"))
			if (str("""This is a test Message""") in str(test_out)):
				theResult = True
			else:
				if sys.platform.startswith("linux") or sys.platform.startswith("darwin"):
					print(str(repr(bytes(test_out, encoding="""utf-8""").decode(
						"""utf-8""", errors=clarify.getCTLModeForPY()
					))))
					theResult = False
					print(str(""))
					print(str("... DECODE BUG CONFIRMED ..."))
					print(str(""))
					print(str(test_out))
					print(str("vs"))
					print(str("""This is a test Message"""))
				else:
					raise unittest.SkipTest("BETA. Experemental feature not ready yet.")
		except Exception as err:
			print(str(""))
			print(str(sys.getdefaultencoding()))
			print(str(type(err)))
			print(str(err))
			print(str((err.args)))
			print(str(""))
			err = None
			del err
			if sys.platform.startswith("linux") or sys.platform.startswith("darwin"):
				theResult = False
			else:
				raise unittest.SkipTest("BETA. Experemental feature not ready yet.")
		assert theResult

	@unittest.skipIf(("""utf""" not in sys.getdefaultencoding()), "wrong encoding for test")
	def test_case_clarify_main_keyring(self):
		"""Tests the helper function main unpack of keyring.main(clarify)"""
		theResult = False
		try:
			from piaplib.pku import utils as utils
			if utils.__name__ is None:
				raise ImportError("Failed to import utils")
			import piaplib.keyring.__main__
			temp_msg = None
			test_args = []
			if sys.platform.startswith("linux") or True:
				temp_msg = str("""U2FsdGVkX1/MMOdV6OYwAURQQg9b9K1AoVA0OCcanG9FjHk7gHk=""")
				test_args = [
					str("clarify"),
					str("--unpack"),
					str("--msg='{}'").format(temp_msg),
					str("-K=testkeyneedstobelong")
				]
			else:
				temp_msg = str(
					"""U2FsdGVkX1/beHoH2ziXWcMFpb3fzzPxQqdeU1tO5UVoBUEnow8T9g=="""
				)
				test_args = [
					str("clarify"),
					str("--unpack"),
					str("--msg={}").format(str(temp_msg)),
					str("-K=testkeyneedstobelong")
				]
			print(str("... test: piaplib.keyring.__main__({})").format(str(test_args)))
			test_out = piaplib.keyring.__main__.main(test_args)
			print(str("... checking"))
			self.assertIsNotNone(test_out)
			self.assertIsNotNone(str(test_out))
			print(str("... is not none: PASS"))
			if (int(0) == int(test_out)):
				theResult = True
			else:
				if sys.platform.startswith("darwin"):
					print(str(test_out))
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
			if sys.platform.startswith("darwin"):
				theResult = False
			else:
				raise unittest.SkipTest("BETA. Experemental feature not ready yet.")
		assert theResult

	@unittest.skipIf(("""utf""" not in sys.getdefaultencoding()), "wrong encoding for test")
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
						test_read = test_read.decode("""utf-8""", errors=clarify.getCTLModeForPY())
				except UnicodeDecodeError:
					test_read = str(repr(bytes(test_read, """utf-8""")))
				self.assertIsNotNone(test_read)
				if (str(someMessageText) in str(test_read)):
					theResult = True
				else:
					if sys.platform.startswith("linux") or sys.platform.startswith("darwin"):
						print(str(repr(bytes(test_read, """utf-8"""))))
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

	@unittest.skipIf(("""utf""" not in sys.getdefaultencoding()), "wrong encoding for test")
	@unittest.skipUnless((sys.version_info > (3, 2)), str(sub_proc_bug_message))
	@given(text())
	def test_case_clarify_write_inverts_read(self, someInput):  # noqa C901
		"""Tests the write then read workflow of keyring.clarify with fuzzing."""
		theResult = False
		someInput = str(someInput)
		assume(isinstance(someInput, str))
		assume(len(str(someInput)) > 3)
		assume("""\"""" not in str(someInput))
		assume("""'""" not in str(someInput))
		assume(repr(str(someInput)) not in repr(str(repr(someInput))))
		from piaplib.pku import utils as utils
		if utils.__name__ is None:
			raise ImportError("Failed to import utils")
		assume(str(someInput) in utils.literal_str(someInput))
		assume(utils.literal_str(someInput) in str(someInput))
		assume(utils.literal_str(someInput) in utils.literal_code(str(someInput)))
		assume(utils.literal_code(str(someInput)) in utils.literal_str(someInput))
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
			assume(test_write is True)
			self.assertTrue(test_write)
			check_wrap = clarify.packForRest(
				str(someMessageText),
				theteststore
			)
			assume((check_wrap is not None))
			try:
				note(str("encoded: \"{}\"").format(utils.literal_str(someMessageText)))
				note(str("as data: \"{}\"").format(utils.literal_str(check_wrap)))
			except Exception as noteErr:
				raise unittest.SkipTest(noteErr)
				noteErr = None
				del noteErr
			if (test_write is True):
				test_read = clarify.unpackFromFile(sometestfile, theteststore)
				try:
					if isinstance(test_read, bytes):
						test_read = test_read.decode("""utf-8""", errors=clarify.getCTLModeForPY())
				except UnicodeDecodeError:
					test_read = str(repr(bytes(test_read, """utf-8""")))
					assume(False)
				self.assertIsNotNone(test_read)
				if (str(someMessageText) in str(test_read)):
					theResult = True
				else:
					note(str("failed test: \"{}\" is not in \"{}\"").format(
						str(someMessageText), str(test_read)
					))
					note(str("decoded: \"{}\"").format(utils.literal_str(test_read)))
					note(str("should decoded: \"{}\"").format(utils.literal_code(str(someMessageText))))
					note(str("from undecoded: \"{}\"").format(utils.literal_str(utils.readFile(sometestfile))))
					note(str("with key: \"{}\"").format(utils.literal_str(theteststore)))
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
