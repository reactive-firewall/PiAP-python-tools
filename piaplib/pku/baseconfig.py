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
			}),
			'PiAP-piaplib': dict({
				'loaded': repr(False)
			})
		})
	except Exception as err:
		print(str(err))
		print(str(type(err)))
		print(str((err.args)))
		default_config = dict({})
	return default_config


def isLoaded():
	"""returns False. Overloaded by config class."""
	return getDefaultMainConfigFile()['PiAP-piaplib']['loaded']


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


def parseConfigParser(config_data=dict({}), theConfig=None, overwrite=True):
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
					if (str(someOpt) not in config_data[someSection].keys()) or (overwrite is True):
						config_data[someSection][someOpt] = theConfig.get(someSection, someOpt)
	except Exception as err:
		print(str(err))
		print(str(type(err)))
		print(str((err.args)))
	return config_data


def python2ReadFile(confFile, mainConfig):
	import io
	with io.open(file=confFile, mode='r', buffering=-1, encoding='utf-8') as configfile:
		mainConfig.read(configfile)
	return mainConfig


def loadMainConfigFile(confFile='/opt/PiAP/PiAP.conf'):
	try:
		mainConfig = configparser.ConfigParser(allow_no_value=True)
		result_config = getDefaultMainConfigFile()
		try:
			import six
			if six.PY2:
				mainConfig = python2ReadFile(confFile, mainConfig)
			else:
				with open(confFile, 'r') as configfile:
					mainConfig.read(configfile)
		except Exception:
			mainConfig = python2ReadFile(confFile, mainConfig)
		result_config = parseConfigParser(result_config, mainConfig, True)
	except IOError as ioErr:
		ioErr = None
		del(ioErr)
		result_config = getDefaultMainConfigFile()
	except OSError as nonerr:
		nonerr = None
		del(nonerr)
		result_config = getDefaultMainConfigFile()
	except Exception as err:
		print(str(err))
		print(str(type(err)))
		print(str((err.args)))
		result_config = getDefaultMainConfigFile()
	return result_config


if __name__ in u'__main__':
	raise NotImplementedError("ERROR: Can not run baseconfig as main.")

