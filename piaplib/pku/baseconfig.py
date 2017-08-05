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


try:
	try:
		import configparser as configparser
	except Exception:
		try:
			import ConfigParser as configparser
		except Exception:
			raise ImportError("Error Importing ConfigParser utils for config")
except Exception:
	pass


def getDefaultMainConfigFile():
	try:
		default_config = dict({
			'PiAP-logging': dict({
				'mode': str("stdout"),
				'dir': str("/var/log"),
				'keyfile': repr(None),
				'encryptlogs': repr(False)
			}),
			'PiAP-logging-outputs': dict({
				'splunk': repr(False),
				'syslog': repr(False),
				'file': repr(False),
				'stdout': repr(True)
			})
		})
	except Exception as err:
		print(str(err))
		print(str(type(err)))
		print(str((err.args)))
		default_config = dict({})
	return default_config


def writeDefaultMainConfigFile(confFile=str('/var/opt/PiAP/PiAP.conf')):
	theResult = False
	try:
		if writeMainConfigFile(confFile, getDefaultMainConfigFile()):
			theResult = True
	except Exception as err:
		print(str(err))
		print(str(type(err)))
		print(str((err.args)))
		theResult = False
	return theResult


def mergeDicts(*dict_args):
	"""
	Given any number of dicts, shallow copy and merge into a new dict,
	precedence goes to key value pairs in latter dicts.
	"""
	result = dict({})
	for dictionary in dict_args:
		try:
			result.update(dictionary)
		except Exception:
			continue
	return result


def mergeConfigParser(theConfig=None, config_data=None, overwrite=False):
	"""
	Merges the Configuration Dictionary into a configparser.
	param theConfig - configparser.ConfigParser the ConfigParser.
	param config_data - dict the configuration to merge.
	param overwrite - boolean determining if the dict is record of truth or if theConfig is.
	"""
	try:
		if theConfig is None:
			theConfig = configparser.ConfigParser(allow_no_value=True)
		if config_data is not None:
			for someSection in config_data.keys():
				if not theConfig.has_section(someSection):
					theConfig.add_section(someSection)
				for someOption in config_data[someSection].keys():
					if not theConfig.has_option(someSection, someOption) or (overwrite is True):
						theConfig.set(someSection, someOption, config_data[someSection][someOption])
	except Exception as err:
		print(str(err))
		print(str(type(err)))
		print(str((err.args)))
	return theConfig


def parseConfigParser(config_data=None, theConfig=None, overwrite=True):
	"""
	Merges the Configuration Dictionary into a configparser.
	param config_data - dict the configuration to merge.
	param theConfig - configparser.ConfigParser the ConfigParser.
	param overwrite - boolean determining if the dict is record of truth or if theConfig is.
	"""
	try:
		if config_data is None:
			config_data = dict({})
		if theConfig is not None:
			for someSection in theConfig.sections():
				if str(someSection) not in config_data.keys():
					config_data[someSection] = dict({})
				for someOpt in theConfig.options(someSection):
					if str(someOpt) not in config_data[someSection].keys() or (overwrite is True):
						config_data[someSection][someOpt] = theConfig.get(someSection, someOpt)
	except Exception as err:
		print(str(err))
		print(str(type(err)))
		print(str((err.args)))
	return config_data


def writeMainConfigFile(confFile=str('/var/opt/PiAP/PiAP.conf'), config_data=None):  # noqa C901
	"""Generates the Main Configuration file for PiAPlib"""
	try:
		mainConfig = configparser.ConfigParser(allow_no_value=True)
		default_config = loadMainConfigFile(confFile)
		mainConfig = mergeConfigParser(mainConfig, config_data, True)
		mainConfig = mergeConfigParser(mainConfig, default_config, False)
		try:
			try:
				import six
				if six.PY2:
					import io
					with io.open(file=confFile, mode='w+', buffering=-1, encoding='utf-8') as cfile:
						mainConfig.write(cfile)
				else:
					with open(confFile, 'wb') as cfile:
						mainConfig.write(cfile)
			except Exception:
				import io
				with io.open(file=confFile, mode='w+', buffering=-1, encoding='utf-8') as cfile:
					mainConfig.write(cfile)
		except Exception:
			with open(confFile, 'wb') as cfile:
				mainConfig.write(cfile)
	except Exception as err:
		print(str(err))
		print(str(type(err)))
		print(str((err.args)))
		return False
	return True


def loadMainConfigFile(confFile='/var/opt/PiAP/PiAP.conf'):
	try:
		mainConfig = configparser.ConfigParser(allow_no_value=True)
		result_config = getDefaultMainConfigFile()
		try:
			import six
			if six.PY2:
				import io
				with io.open(file=confFile, mode='r', buffering=-1, encoding='utf-8') as configfile:
					mainConfig.read(configfile)
			else:
				with open(confFile, 'r') as configfile:
					mainConfig.read(configfile)
		except Exception:
			import io
			with io.open(file=confFile, mode='r', buffering=-1, encoding='utf-8') as configfile:
				mainConfig.read(configfile)
		result_config = parseConfigParser(result_config, mainConfig, True)
	except IOError as ioErr:
		ioErr = None
		del(ioErr)
		return getDefaultMainConfigFile()
	except OSError as nonerr:
		nonerr = None
		del(nonerr)
		return getDefaultMainConfigFile()
	except Exception as err:
		print(str(err))
		print(str(type(err)))
		print(str((err.args)))
		return getDefaultMainConfigFile()
	return result_config


if __name__ in u'__main__':
	raise NotImplementedError("ERROR: Can not run config as main. Yet?")

