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


def dict_compare(d1, d2):
	d1_keys = set(d1.keys())
	d2_keys = set(d2.keys())
	intersect_keys = d1_keys.intersection(d2_keys)
	same = set(o for o in intersect_keys if d1[o] == d2[o])
	return (len(same) is len(d1) and len(d1) is len(d2))


class ConfigTestSuite(unittest.TestCase):
	"""Basic config test cases."""

	def test_absolute_truth_and_meaning(self):
		"""Insanitty Test."""
		assert True

	def test_dict_compare(self):
		"""Meta dict-Test."""
		test_control = dict({"test": "this", "for": "match"})
		test_control_b = dict({"test": "this", "for": "match"})
		test_match = dict(test_control)
		test_diff = dict({"test": "this", "for": "bad match"})
		self.assertTrue(dict_compare(test_control, test_control_b))
		self.assertTrue(dict_compare(test_control, test_match))
		self.assertTrue(dict_compare(test_match, test_control_b))
		self.assertTrue(dict_compare(test_match, test_control))
		self.assertFalse(dict_compare(test_control, test_diff))
		self.assertFalse(dict_compare(test_control_b, test_diff))
		self.assertFalse(dict_compare(test_match, test_diff))

	def test_syntax(self):
		"""Test case importing code."""
		theResult = True
		try:
			from .context import piaplib
			if piaplib.__name__ is None:
				theResult = False
			from piaplib import pocket
			if pocket.__name__ is None:
				theResult = False
		except Exception as impErr:
			print(str(type(impErr)))
			print(str(impErr))
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
			print(str(""))
			print(str(type(err)))
			print(str(err))
			print(str((err.args)))
			print(str(""))
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
			print(str(""))
			print(str("Error in test of json write-read"))
			print(str(type(err)))
			print(str(err))
			print(str((err.args)))
			print(str(""))
			err = None
			del err
			theResult = False
		assert theResult

	def test_case_default_config(self):
		"""Tests the default configuration functions"""
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
			print(str(""))
			print(str("Error in test of default config"))
			print(str(type(err)))
			print(str(err))
			print(str((err.args)))
			print(str(""))
			err = None
			del err
			theResult = False
		assert theResult

	def test_case_write_default_config(self):
		"""Tests the write default configuration functions"""
		theResult = False
		try:
			from piaplib import pku as pku
			if pku.__name__ is None:
				raise ImportError("Failed to import pku")
			from pku import config as config
			if config.__name__ is None:
				raise ImportError("Failed to import config")
			test_path = str("/tmp/test_config.cnf")
			self.assertTrue(config.writeMainConfigFile(test_path))
			self.assertIsNotNone(config.loadMainConfigFile(test_path))
			theResult = True
		except Exception as err:
			print(str(""))
			print(str("Error in test of default config"))
			print(str(type(err)))
			print(str(err))
			print(str((err.args)))
			print(str(""))
			err = None
			del err
			theResult = False
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
			if config.hasYamlSupport() is True:
				theBlob = dict({
					u'test': {
						u'write_test': u'This will test writes',
						u'read_test': u'and this will test reads.'
					}
				})
				somefile = str("the_test_file.yml")
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
				theResult = True
				print(str("SKIPPED: no yaml support"))
		except Exception as err:
			print(str(""))
			print(str("Error in test of yaml write-read"))
			print(str(type(err)))
			print(str(err))
			print(str((err.args)))
			print(str(""))
			err = None
			del err
			theResult = False
		assert theResult


if __name__ == '__main__':
	unittest.main()
