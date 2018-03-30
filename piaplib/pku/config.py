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
	import json as json
except Exception:
	try:
		import json
	except Exception:
		raise ImportError("Error Importing json utils for config")


try:
	from . import utils as utils
except Exception:
	try:
		import utils as utils
	except Exception:
		raise ImportError("Error Importing utils for config")


try:
	from . import remediation as remediation
except Exception:
	try:
		import remediation as remediation
	except Exception:
		raise ImportError("Error Importing remediation for config")


try:
	from . import baseconfig as baseconfig
except Exception:
	try:
		import baseconfig as baseconfig
	except Exception:
		raise ImportError("Error Importing baseconfig for config")


_MAIN_CONFIG_DATA = None


def hasJsonSupport():
	support_json = False
	try:
		support_json = (json.__name__ is not None)
	except BaseException:
		support_json = False
	return support_json


@remediation.error_passing
def readJsonFile(somefile):
	"""Reads the raw json file."""
	read_data = None
	try:
		someFilePath = utils.addExtension(somefile, str('json'))
		with utils.open_func(someFilePath, mode=u'r', encoding=u'utf-8') as json_data_file:
			read_data = json.load(fp=json_data_file, encoding=u'utf-8')
	except Exception as jsonerr:
		print("")
		print("Error: Failed to load JSON file.")
		print(str(type(jsonerr)))
		print(str(jsonerr))
		print(str((jsonerr.args)))
		print("")
		read_data = dict({u'Error': u'Failed to load JSON file.'})
	return read_data


@remediation.error_passing
def writeJsonFile(somefile, data):
	"""Writes the raw json file."""
	if data is None:
		return False
	did_write = False
	try:
		someFilePath = utils.addExtension(somefile, str('json'))
		with utils.open_func(someFilePath, mode=u'w+', encoding=u'utf-8') as outfile:
			jsonData = json.dumps(
				obj=dict(data),
				ensure_ascii=True,
				indent=1,
				separators=(',', ': ')
			)
			utils.write_func(outfile, jsonData)
		did_write = True
	except Exception as jsonerr:
		print("")
		print("Error: Failed to write JSON file.")
		print(str(type(jsonerr)))
		print(str(jsonerr))
		print(str((jsonerr.args)))
		print("")
		did_write = False
	return did_write


try:
	try:
		import yaml as yaml
	except Exception:
		try:
			import ruamel.yaml as yaml
		except Exception:
			raise ImportError("Error Importing yaml utils for config")
except Exception:
	pass


def hasYamlSupport():
	support_yaml = False
	try:
		support_yaml = (yaml.__name__ is not None)
	except BaseException:
		support_yaml = False
	return support_yaml


def readYamlFile(somefile):
	"""Reads the raw Yaml file."""
	if hasYamlSupport() is not True:
		return None
	read_data = None
	try:
		someFilePath = utils.addExtension(somefile, str('yml'))
		with utils.open_func(file=someFilePath, mode=u'r', encoding=u'utf-8') as ymalfile:
			try:
				if yaml.version_info < (0, 15):
					read_data = yaml.safe_load(ymalfile)
				else:
					yml = yaml.YAML(typ='safe', pure=True)  # 'safe' load and dump
					read_data = yml.load(ymalfile)
			except AttributeError as libyamlerr:
				libyamlerr = None
				del(libyamlerr)
				read_data = yaml.safe_load(ymalfile)
	except Exception as yamlerr:
		print("")
		print("Error: Failed to load YAML file.")
		print(str(type(yamlerr)))
		print(str(yamlerr))
		print(str((yamlerr.args)))
		print("")
		read_data = None
	return read_data


def writeYamlFile(somefile, data):
	"""Writes the Yaml file."""
	if hasYamlSupport() is not True:
		return False
	did_write = False
	try:
		someFilePath = utils.addExtension(somefile, str('yml'))
		did_write = utils.writeFile(someFilePath, yaml.dump(data))
	except Exception as yamlerr:
		print("")
		print("Error: Failed to save YAML file.")
		print(str(type(yamlerr)))
		print(str(yamlerr))
		print(str((yamlerr.args)))
		print(str(somefile))
		print("")
		did_write = None
	return did_write


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


class dictParser(configparser.ConfigParser):
	"""adds as_dict() to ConfigParser"""
	@remediation.error_handling
	def as_dict(self):
		"""returns the config as a nested dict"""
		theResult = dict(self._sections)
		for somekey in theResult:
			theResult[somekey] = dict(self._defaults, **theResult[somekey])
			theResult[somekey].pop('__name__', None)
		return theResult


@remediation.error_handling
def getDefaultMainConfigFile():
	import os
	# logging['timefmt'] = str("""%a %b %d %H:%M:%S %Z %Y""")
	default_config = dict({
		'PiAP-rand': dict({
			'keyfile': repr(None),
			'entropy_function': repr(os.urandom),
			'char_upper': repr(99),
			'char_lower': repr(1),
			'char_range': repr(tuple(('${PiAP-rand:char_lower}', '${PiAP-rand:char_upper}'))),
			'passphrase_length': repr(16),
			'passphrase_encoding': str('utf-8'),
			'ssid_length': repr(20)
		}),
		'PiAP-network-lan': dict({
			'keyfile': repr(None),
			'network_ipv4_on': repr(True),
			'network_ipv4': repr(tuple(('10.0.40', 0))),
			'ipv4_dhcp_reserved': repr({}),
			'network_ipv6_on': repr(False),
			'network_ipv6': repr(None),
			'ipv6_dhcp_reserved': repr(None)
		})
	})
	return baseconfig.mergeDicts(baseconfig.getDefaultMainConfigFile(), default_config)


def _raw_getMainConfig():
	"""returns raw global _MAIN_CONFIG_DATA"""
	global _MAIN_CONFIG_DATA
	if _MAIN_CONFIG_DATA is not None:
		return _MAIN_CONFIG_DATA
	else:
		return None


def _raw_setMainConfig(newValue):
	"""sets raw global _MAIN_CONFIG_DATA"""
	global _MAIN_CONFIG_DATA
	if newValue is None:
		newValue = _raw_getMainConfig()
	_MAIN_CONFIG_DATA = newValue


@remediation.error_handling
def getMainConfig():
	if _raw_getMainConfig() is None:
		tempValue = loadMainConfigFile()
		tempValue['PiAP-piaplib']['loaded'] = True
		_raw_setMainConfig(newValue=tempValue)
	return _raw_getMainConfig()


@remediation.error_handling
def isLoaded():
	"""True if config is loaded."""
	return getMainConfig() is not None and getMainConfig()['PiAP-piaplib']['loaded']


@remediation.error_handling
def hasMainConfigOptionsFor(somekey=None):
	"""Returns True if the main configurtion has the given key, otherwise False."""
	hasValue = False
	if somekey is not None and isLoaded() and (getMainConfig().has_section(somekey)):
		hasValue = True
	return hasValue


@remediation.error_handling
def hasMainConfigOptionFor(mainSectionKey=None):
	"""True if config key maps to value."""
	hasValue = False
	if mainSectionKey is None or not isLoaded():
		hasValue = False
	if str(""".""") not in str(mainSectionKey):
		hasValue = hasMainConfigOptionsFor(mainSectionKey)
	else:
		kp = str(mainSectionKey).split(""".""")
		main_config = getMainConfig()
		if (main_config.has_section(kp[0]) and (main_config[kp[0]].has_option[kp[1]])):
			hasValue = True
	return hasValue


@remediation.error_handling
def writeDefaultMainConfigFile(confFile=str('/var/opt/PiAP/PiAP.conf')):
	theResult = False
	if writeMainConfigFile(confFile, getDefaultMainConfigFile()):
		theResult = True
	return theResult


@remediation.error_passing
def mergeConfigParser(theConfig=None, config_data=dict({}), overwrite=False):
	"""
	Merges the Configuration Dictionary into a configparser.
	param theConfig - configparser.ConfigParser the ConfigParser.
	param config_data - dict the configuration to merge.
	param overwrite - boolean determining if the dict is record of truth or if theConfig is.
	"""
	if theConfig is None:
		theConfig = dictParser(allow_no_value=True)
	if config_data is not None:
		for someSection in config_data.keys():
			if not theConfig.has_section(someSection):
				theConfig.add_section(someSection)
			for someOption in config_data[someSection].keys():
				if not theConfig.has_option(someSection, someOption) or (overwrite is True):
					theConfig.set(someSection, someOption, config_data[someSection][someOption])
	return theConfig


@remediation.error_handling
def parseConfigParser(config_data=dict({}), theConfig=None, overwrite=True):
	"""
	Merges the Configuration Dictionary into a configparser.
	param config_data - dict the configuration to merge.
	param theConfig - configparser.ConfigParser the ConfigParser.
	param overwrite - boolean determining if the dict is record of truth or if theConfig is.
	"""
	if config_data is None:
		config_data = dict({})
	if theConfig is not None:
		for someSection in theConfig.sections():
			if str(someSection) not in config_data.keys():
				config_data[someSection] = dict({})
			for someOption in theConfig.options(someSection):
				if str(someOption) not in config_data[someSection].keys() or (overwrite is True):
					config_data[someSection][someOption] = theConfig.get(someSection, someOption)
	return config_data


@remediation.error_handling
def writeMainConfigFile(confFile=str('/var/opt/PiAP/PiAP.conf'), config_data=None):
	"""Generates the Main Configuration file for PiAPlib"""
	try:
		mainConfig = dictParser(allow_no_value=True)
		default_config = loadMainConfigFile(confFile)
		mainConfig = mergeConfigParser(mainConfig, config_data, True)
		mainConfig = mergeConfigParser(mainConfig, default_config, False)
		try:
			with utils.open_func(file=confFile, mode='w+') as configfile:
				mainConfig.write(configfile)
		except Exception:
			with open(confFile, 'wb') as configfile:
				mainConfig.write(configfile)
	except Exception as err:
		print(str(err))
		print(str(type(err)))
		print(str((err.args)))
		return False
	return True


@remediation.error_handling
def readIniFile(filename, theparser=None):
	""" cross-python load function """
	with utils.open_func(file=filename, mode=u'r', encoding=u'utf-8') as configfile:
		try:
			import six
			if six.PY2:
				theparser.readfp(configfile, str(filename))
			else:
				theparser.read_file(configfile, str(filename))
		except Exception:
			import warnings
			with warnings.catch_warnings():
				warnings.filterwarnings("ignore", category=DeprecationWarning)
				theparser.readfp(configfile, str(filename))
	return theparser


@remediation.error_handling
def loadMainConfigFile(confFile='/var/opt/PiAP/PiAP.conf'):
	try:
		emptyConfig = dictParser(allow_no_value=True)
		result_config = getDefaultMainConfigFile()
		mainConfig = readIniFile(str(confFile), emptyConfig)
		result_config = parseConfigParser(result_config, mainConfig, True)
	except Exception as err:
		print(str(err))
		print(str(type(err)))
		print(str((err.args)))
		return getDefaultMainConfigFile()
	return result_config


if __name__ in u'__main__':
	raise NotImplementedError("ERROR: Can not run config as main. Yet?")

