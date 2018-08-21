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


def dict_compare(d1, d2):
	d1_keys = set(d1.keys())
	d2_keys = set(d2.keys())
	intersect_keys = d1_keys.intersection(d2_keys)
	same = set(o for o in intersect_keys if d1[o] == d2[o])
	return (len(same) is len(d1) and len(d1) is len(d2))


def debugtestError(someError=None):
	print(str(""))
	print(str("ERROR:"))
	print(str(type(someError)))
	print(str(someError))
	print(str((someError.args)))
	print(str(""))


def random_file_path():
	from .context import piaplib as piaplib
	if piaplib.__name__ is None:
		raise ImportError("Failed to import piaplib")
	from piaplib import keyring as keyring
	if keyring.__name__ is None:
		raise ImportError("Failed to import keyring")
	from piaplib.keyring import rand as rand
	rOut = str("""config_{someInt}_temp_file.tmp""").format(someInt=rand.randInt())
	return rOut


def clean_temp_file(someFile):
	from .context import piaplib as piaplib
	if piaplib.__name__ is None:
		raise ImportError("Failed to import piaplib")
	from piaplib import pku as pku
	if pku.__name__ is None:
		raise ImportError("Failed to import pku")
	from piaplib.pku import utils as utils
	return utils.cleanFileResource(someFile)


class ConfigTestSuite(unittest.TestCase):
	"""Basic piaplib.pku.config (configuration) test cases."""

	def setUp(self):
		"""sets up the configuration tests."""
		from .context import piaplib as piaplib
		if piaplib.__name__ is None:
			raise ImportError("Failed to import pku")
		from piaplib import pocket as pocket
		if pocket.__name__ is None:
			raise ImportError("Failed to import utils")
		from piaplib import pku as pku
		if pku.__name__ is None:
			raise ImportError("Failed to import pku")
		from piaplib.pku import config as config
		if config.__name__ is None:
			raise ImportError("Failed to import config")
		assert config.isLoaded()

	def test_absolute_truth_and_meaning(self):
		"""Test case: Insanity Test (True is True)."""
		assert True

	def test_dict_compare(self):
		"""Meta dict-Test; Tests the utility function for comparing python dict type values."""
		test_control = dict({"test": "this", "for": "match"})
		test_control_b = dict({"test": "this", "for": "match"})
		test_match = dict(test_control)
		test_diff = dict({"test": "this", "for": "bad match"})
		self.assertTrue(dict_compare(test_control, test_control_b))
		self.assertDictEqual(test_control, test_control_b)
		self.assertTrue(dict_compare(test_control, test_match))
		self.assertTrue(dict_compare(test_match, test_control_b))
		self.assertTrue(dict_compare(test_match, test_control))
		self.assertFalse(dict_compare(test_control, test_diff))
		self.assertFalse(dict_compare(test_control_b, test_diff))
		self.assertFalse(dict_compare(test_match, test_diff))

	def test_config_import_syntax(self):
		"""Test case: importing piaplib.pku.config code."""
		theResult = True
		try:
			from .context import piaplib as piaplib
			if piaplib.__name__ is None:
				raise ImportError("Failed to import test context")
			from piaplib import pocket as pocket
			if pocket.__name__ is None:
				raise ImportError("Failed to import pocket piaplib")
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku module")
			from pku import config as config
			if config.__name__ is None:
				raise ImportError("Failed to import config")
		except Exception as impErr:
			debugtestError(impErr)
			theResult = False
		assert theResult

	def test_case_config_supports_json(self):
		"""Tests the config.hasJsonSupport() function"""
		theResult = True
		try:
			from .context import piaplib as piaplib
			if piaplib.__name__ is None:
				raise ImportError("Failed to import pku")
			from piaplib import pocket as pocket
			if pocket.__name__ is None:
				raise ImportError("Failed to import utils")
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import config as config
			if config.__name__ is None:
				raise ImportError("Failed to import config")
			theResult = False
			theResult = (config.hasJsonSupport() is True)
			theResult = (theResult or (config.hasJsonSupport() is False))
		except Exception as err:
			debugtestError(err)
			err = None
			del err
			theResult = False
		assert theResult

	def test_z_case_json_attempt_bad_write_file(self):
		"""Tests the JSON write functions with no data. Should return False."""
		theResult = False
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import config as config
			if config.__name__ is None:
				raise ImportError("Failed to import config")
			somefile = str("the_test_file.json")
			if (config.writeJsonFile(somefile, None) is False):
				theResult = True
			else:
				theResult = False
		except Exception as err:
			debugtestError(err)
			err = None
			del err
			theResult = False
		assert theResult

	def test_case_json_read_write_file(self):
		"""Tests the JSON read and write functions"""
		theResult = False
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import config as config
			if config.__name__ is None:
				raise ImportError("Failed to import config")
			theBlob = dict({
				u'test': {
					u'write_test': u'This will test writes',
					u'read_test': u'and this will test reads.'
				}
			})
			somefile = str("the_test_file.json")
			if (config.writeJsonFile(somefile, theBlob) is True):
				readback = config.readJsonFile(somefile)
				if (readback is None):
					theResult = False
				else:
					a = dict_compare(theBlob[u'test'], readback[u'test'])
					b = dict_compare(readback, theBlob)
					input_data = str(theBlob[u'test'][u'write_test'])
					output_data = str(readback[u'test'][u'write_test'])
					c = (output_data in input_data)
					d = (input_data in output_data)
					theResult = (a and b and c and d)
				if theResult:
					theResult = True
				else:
					theResult = False
				if (theResult is False):
					print(str("wrote"))
					print(str(theBlob))
					print(str(""))
					print(str("read"))
					print(str(readback))
					print(str(""))
			else:
				theResult = False
				print(str("write failed"))
				print(str(theBlob))
				print(str(""))
		except Exception as err:
			debugtestError(err)
			err = None
			del err
			theResult = False
		assert theResult

	def test_case_default_baseconfig(self):
		""" Tests the default base configuration function
			piaplib.pku.baseconfig.getDefaultMainConfigFile() != None
		"""
		theResult = False
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import baseconfig as baseconfig
			if baseconfig.__name__ is None:
				raise ImportError("Failed to import config")
			self.assertIsNotNone(baseconfig.getDefaultMainConfigFile())
			theResult = True
		except Exception as err:
			debugtestError(err)
			err = None
			del err
			theResult = False
		assert theResult

	def test_case_default_config(self):
		""" Tests the default configuration function
			piaplib.pku.config.getDefaultMainConfigFile() != None
		"""
		theResult = False
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import config as config
			if config.__name__ is None:
				raise ImportError("Failed to import config")
			self.assertIsNotNone(config.getDefaultMainConfigFile())
			theResult = True
		except Exception as err:
			debugtestError(err)
			err = None
			del err
			theResult = False
		assert theResult

	def test_case_default_main_config(self):
		""" Tests the default configuration function
			piaplib.pku.config.getMainConfig() != None
		"""
		theResult = False
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import config as config
			if config.__name__ is None:
				raise ImportError("Failed to import config")
			self.assertIsNotNone(config.getMainConfig())
			theResult = True
		except Exception as err:
			debugtestError(err)
			err = None
			del err
			theResult = False
		assert theResult

	def test_a_case_write_default_config(self):
		""" Tests the default configuration file write (save) functions.
			config.writeMainConfigFile(test_path) == config.loadMainConfigFile(test_path)
		"""
		theResult = False
		test_path = str("{}.cnf").format(str(random_file_path()))
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import config as config
			if config.__name__ is None:
				raise ImportError("Failed to import config")
			print(str(""" init """))
			self.assertTrue(
				config.writeMainConfigFile(test_path),
				config.getMainConfig(test_path).as_dict()
			)
			print(str(""" ... wrote """))
			self.assertTrue(config.reloadConfigCache(test_path))
			test_load = config.loadMainConfigFile(test_path)
			self.assertIsNotNone(test_load)
			print(str(""" ... loaded ... """))
			self.maxDiff = None
			mock_value = config.getMainConfig(test_path).as_dict()
			self.assertIsNotNone(mock_value)
			mock_value["""PiAP-piaplib"""]["""loaded"""]
			self.assertDictEqual(
				test_load,
				mock_value
			)
			print(str(""" ... checked ... """))
			theResult = True
		except Exception as err:
			debugtestError(err)
			err = None
			del err
			theResult = False
		clean_temp_file(test_path)
		assert theResult

	def test_case_get_set_config(self):
		""" Tests the get/set configuration functions.
			config.setConfigValue(key, config.getConfigValue(key)) == getConfigValue(key)
		"""
		theResult = False
		test_path = str("{}.cnf").format(str(random_file_path()))
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import config as config
			if config.__name__ is None:
				raise ImportError("Failed to import config")
			self.assertIsNotNone(config.loadMainConfigFile(test_path))
			self.assertIsNotNone(config.isLoaded())
			test_key = str("""PiAP-piaplib.loaded""")
			self.assertEqual(
				config.isLoaded(),
				config.getConfigValue(key=test_key)
			)
			test_key = str("""unitTests.testkey""")
			test_key_value = str("""{}""").format(random_file_path())
			config.setConfigValue(key=test_key, value=test_key_value)
			self.assertTrue(config.isLoaded())
			self.assertEqual(config.getConfigValue(key=test_key), test_key_value)
			theResult = True
		except Exception as err:
			debugtestError(err)
			err = None
			del err
			theResult = False
		clean_temp_file(test_path)
		assert theResult

	def test_case_of_parse_empty_baseconfig(self):
		"""Tests the parse configuration functions given empty values"""
		theResult = False
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import baseconfig as baseconfig
			if baseconfig.__name__ is None:
				raise ImportError("Failed to import baseconfig")
			self.assertIsNotNone(
				baseconfig.parseConfigParser(
					config_data=baseconfig.getDefaultMainConfigFile(),
					theConfig=None,
					overwrite=True
				)
			)
			theResult = True
		except Exception as err:
			debugtestError(err)
			err = None
			del err
			theResult = False
		assert theResult

	def test_case_of_parse_mock_baseconfig(self):
		"""Tests the parse configuration functions given mocked values"""
		theResult = False
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import baseconfig as baseconfig
			if baseconfig.__name__ is None:
				raise ImportError("Failed to import baseconfig")
			from pku.baseconfig import configparser
			if configparser.__name__ is None:
				raise ImportError("Failed to import configparser")
			cfg_mock_data = configparser.ConfigParser()
			cfg_mock_data.add_section('PiAP-logging')
			cfg_mock_data.set('PiAP-logging', 'mode', 'stdout')
			cfg_mock_data.set('PiAP-logging', 'dir', '/var/log')
			cfg_mock_data.set('PiAP-logging', 'keyFile', repr(None))
			cfg_mock_data.set('PiAP-logging', 'encryptlogs', repr(False))
			self.assertIsNotNone(
				baseconfig.parseConfigParser(
					config_data=baseconfig.getDefaultMainConfigFile(),
					theConfig=cfg_mock_data,
					overwrite=True
				)
			)
			theResult = True
		except Exception as err:
			debugtestError(err)
			err = None
			del err
			theResult = False
		assert theResult

	def test_case_of_parse_mock_config(self):
		"""Tests the parse configuration functions given mocked values"""
		theResult = False
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import baseconfig as baseconfig
			if baseconfig.__name__ is None:
				raise ImportError("Failed to import baseconfig")
			from pku.baseconfig import configparser
			if configparser.__name__ is None:
				raise ImportError("Failed to import configparser")
			from pku import config as config
			if config.__name__ is None:
				raise ImportError("Failed to import config")
			cfg_mock_data = configparser.ConfigParser()
			cfg_mock_data.add_section('PiAP-logging')
			cfg_mock_data.set('PiAP-logging', 'mode', 'stdout')
			cfg_mock_data.set('PiAP-logging', 'dir', '/var/log')
			cfg_mock_data.set('PiAP-logging', 'keyFile', repr(None))
			cfg_mock_data.set('PiAP-logging', 'encryptlogs', repr(False))
			self.assertIsNotNone(
				config.parseConfigParser(
					config_data=config.getMainConfig(),
					theConfig=cfg_mock_data,
					overwrite=True
				)
			)
			theResult = True
		except Exception as err:
			debugtestError(err)
			err = None
			del err
			theResult = False
		assert theResult

	def test_case_read_default_baseconfig(self):
		"""Tests the read default configuration functions"""
		theResult = False
		test_path = str("{}.cnf").format(str(random_file_path()))
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import baseconfig as baseconfig
			if baseconfig.__name__ is None:
				raise ImportError("Failed to import baseconfig")
			from pku import config as config
			if config.__name__ is None:
				raise ImportError("Failed to import config")
			self.assertTrue(
				config.writeMainConfigFile(test_path),
				baseconfig.getDefaultMainConfigFile()
			)
			self.assertIsNotNone(baseconfig.loadMainConfigFile(test_path))
			self.assertDictEqual(
				baseconfig.loadMainConfigFile(test_path),
				baseconfig.getDefaultMainConfigFile()
			)
			theResult = True
		except Exception as err:
			debugtestError(err)
			err = None
			del err
			theResult = False
		clean_temp_file(test_path)
		assert theResult

	def test_case_yaml_read_write_file(self):
		"""Tests the YAML read and write functions"""
		theResult = False
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import config as config
			if config.__name__ is None:
				raise ImportError("Failed to import config")
			somefile = str("the_test_file.yml")
			if config.hasYamlSupport() is True:
				theBlob = dict({
					u'test': {
						u'write_test': u'This will test writes',
						u'read_test': u'and this will test reads.'
					}
				})
				if (config.writeYamlFile(somefile, theBlob) is True):
					try:
						readback = config.readYamlFile(somefile)
						a = dict_compare(theBlob[u'test'], readback[u'test'])
						b = dict_compare(readback, theBlob)
						# c = dict_compare(theBlob[u'test'].values(), readback[u'test'].values())
						if a and b:
							theResult = True
						else:
							theResult = False
						if (theResult is False):
							print(str("wrote"))
							print(str(theBlob))
							print(str(""))
							print(str("read"))
							print(str(readback))
							print(str(""))
							print(str("case a"))
							print(str(a))
							print(str(""))
							print(str("case b"))
							print(str(b))
							print(str(""))
					except Exception as err:
						print(str(""))
						print(str("Error in test of yaml write-read"))
						print(str(type(err)))
						print(str(err))
						print(str((err.args)))
						print(str(""))
						print(str("wrote to file"))
						print(str(somefile))
						print(str(""))
						print(str("read"))
						print(str(readback))
						print(str(""))
						print(str(type(readback)))
						err = None
						del err
						theResult = False
				else:
					theResult = False
				if (theResult is False):
					print(str("write failed"))
					print(str(theBlob))
					print(str(type(theBlob)))
					print(str(""))
			else:
				theResult = (not config.writeYamlFile(somefile, None))
				print(str("SKIPPED: no yaml support"))
		except Exception as err:
			debugtestError(err)
			err = None
			del err
			theResult = False
		assert theResult


if __name__ == '__main__':
	unittest.main()
