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
	import os
	import os.path
	import sys
	import argparse
	import ast
	import functools
	for someModule in [os, os.path, sys, argparse, ast, functools]:
		if someModule.__name__ is None:
			raise ImportError(str("OMG! we could not import {}. ABORT. ABORT.").format(someModule))
except Exception as err:
	raise ImportError(err)
	exit(3)


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
	from piaplib.book.logs import ANSIColors as ANSIColors
except Exception:
	try:
		from book.logs import ANSIColors as ANSIColors
	except Exception as err:
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		print("")
		raise ImportError("Error Importing ANSIColors")


try:
	from . import baseconfig as baseconfig
except Exception:
	try:
		import baseconfig as baseconfig
	except Exception:
		raise ImportError("Error Importing baseconfig for config")


__prog__ = """piaplib.pku.config"""
"""The name of this PiAPLib tool is Pocket Knife Configuration Unit"""


__description__ = """Runs piaplib configuration functions."""
"""The description of this PiAPLib tool is 'Runs piaplib configuration functions.'"""


__epilog__ = """basically a python wrapper for configuration I/O."""
"""...basically a python wrapper for configuration I/O."""


_PIAP_KVP_GLOBAL_KEY = str("""PiAP-piaplib""")
"""Cannonical key for PiAP-piaplib section"""


_PIAP_KVP_CONF_KEY = str("""{}.{}""").format(_PIAP_KVP_GLOBAL_KEY, """config""")
"""Cannonical key for PiAP-piaplib.config"""


_PIAP_KVP_LOAD_SUBKEY = str("""loaded""")
"""Sub key for PiAP-piaplib.loaded"""


_PIAP_KVP_LOAD_KEY = str("""{}.{}""").format(_PIAP_KVP_GLOBAL_KEY, _PIAP_KVP_LOAD_SUBKEY)
"""Cannonical key for PiAP-piaplib.loaded"""


_PIAP_KVP_GET_LOAD = str("""piaplib.pku.config.__builtin_isLoaded""")


_PIAP_KVP_GET_KEY = str("""{}.{}""").format(_PIAP_KVP_GLOBAL_KEY, """config_accessors""")
"""Cannonical key for PiAP-piaplib.config_accessors"""


_PIAP_KVP_GET_DEFAULT = str("""config.defaultGetter""")


_PIAP_KVP_SET_KEY = str("""{}.{}""").format(_PIAP_KVP_GLOBAL_KEY, """config_modifiers""")
"""Cannonical key for PiAP-piaplib.config_modifiers"""


_PIAP_KVP_SET_DEFAULT = str("""config.defaultSetter""")


_MAIN_CONFIG_DATA = None


__ALL_KEYS_SETTING__ = str("""all""")


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
		remediation.error_breakpoint(error=jsonerr, context=readJsonFile)
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
		remediation.error_breakpoint(error=jsonerr, context=writeJsonFile)
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
except ImportError:
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
		remediation.error_breakpoint(error=yamlerr, context=readYamlFile)
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
		remediation.error_breakpoint(error=yamlerr, context=writeYamlFile)
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
	try:
		if sys.version_info <= (3, 3):
			class SaneConfigParser(configparser.SafeConfigParser):
				pass
		else:
			class SaneConfigParser(configparser.ConfigParser):
				pass
	except Exception:
		raise ImportError("Error Importing SaneConfigParser for config")
except ImportError:
	pass


@remediation.error_passing
def prepforStore(rawValue):
	"""pack value for storage"""
	taint_value = str(rawValue)
	taint_value_0 = taint_value[0]
	if str('"') not in taint_value_0 and str("""'""") not in taint_value_0:
		taint_value_6 = taint_value[:6]
		taint_value_7 = taint_value[:6]
		taint_value_9 = taint_value[0:9]
		if str("""(""") in taint_value_0 or str("""[""") in taint_value_0:
			taint_value = repr(rawValue)
		elif str("""{""") in taint_value_0:
			taint_value = repr(rawValue)
		elif str(True) in taint_value_6:
			taint_value = repr(True)
		elif str(False) in taint_value_7:
			taint_value = repr(False)
		elif str("""<function""") in taint_value_9:
			taint_value = utils.getHandle(str(rawValue))
	else:
		try:
			taint_value = utils.literal_str(rawValue)
		except BaseException:
			taint_value = None
	return taint_value


class dictParser(SaneConfigParser):
	"""adds as_dict() to ConfigParser"""
	@remediation.error_handling
	def as_dict(self):
		"""returns the config as a nested dict"""
		theResult = dict(self._sections)
		for somekey in theResult:
			theResult[somekey] = dict(self._defaults, **theResult[somekey])
			theResult[somekey].pop('__name__', None)
		return theResult

	@remediation.error_passing
	def keys(self):
		"""see dict.keys()"""
		return self.as_dict().keys()

	@remediation.error_passing
	def allkeys(self):
		"""see dict.keys()"""
		theResult = []
		for section in self.sections():
			theResult.append(str(section))
			for option in self.options(section):
				theResult.append(str("""{sec}.{opt}""").format(sec=section, opt=option))
		return theResult

	def copy(self):
		"""see obj.copy()"""
		theCopy = dictParser()
		for copysection in self.sections():
			if (str(copysection).upper() != str("DEFAULT")):
				theCopy.add_section(copysection)
			for copyoption in self.options(copysection):
				theCopy.set(copysection, copyoption, self.get(copysection, copyoption))
		return theCopy

	def __py2getitem__(self, key):
		try:
			if key == 'sections':
				return self.sections
			elif str(key).upper() != str("DEFAULT"):
				return self.as_dict()[key]
			else:
				return super(dictParser, self).__getitem__(self, key)
		except Exception:
			raise AttributeError(str("<Class dictParser> has no attribute {}").format(str(key)))

	def __getitem__(self, key):
		try:
			import six
			if six.PY2:
				return self.__py2getitem__(key)
			else:
				return super(dictParser, self)._getitem__(self, key)
		except Exception:
			return self.__py2getitem__(key)
		raise AttributeError(str("<Class dictParser> has no attribute {}").format(str(key)))

	def __py2read_dict__(self, dictionary):
		if (dictionary is not None) and (dictionary.keys() is not None):
			for someSection in dictionary.keys():
				isValidSection = (not self.has_section(someSection))
				if (isValidSection is True) and (str(someSection) not in str("DEFAULT")):
					self.add_section(someSection)
				if (dictionary[someSection] is None):
					continue
				elif isinstance(dictionary[someSection], dict):
					for someOption in dictionary[someSection].keys():
						try:
							self.set(
								someSection, someOption,
								dictionary[someSection][someOption]
							)
						except Exception:
							self.set(
								someSection, someOption,
								repr(dictionary[someSection][someOption])
							)
		return self

	def read_dict(self, dictionary, source='<dict>'):
		try:
			import six
			if six.PY2:
				return self.__py2read_dict__(dictionary)
			else:
				return super(dictParser, self).read_dict(self, dictionary, source)
		except Exception:
			return self.__py2read_dict__(dictionary)
		return self


@remediation.error_handling
def getDefaultMainConfigFile():
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
	if globals().get("""_MAIN_CONFIG_DATA""") is None:
		_MAIN_CONFIG_DATA = None
	return _MAIN_CONFIG_DATA


def _raw_setMainConfig(newValue):
	"""sets raw global _MAIN_CONFIG_DATA"""
	global _MAIN_CONFIG_DATA
	if newValue is None:
		newValue = _raw_getMainConfig()
	if isinstance(newValue, dict):
		_MAIN_CONFIG_DATA = dictParser(allow_no_value=True)
		_MAIN_CONFIG_DATA.read_dict(dictionary=newValue)
	elif isinstance(newValue, dictParser):
		_MAIN_CONFIG_DATA = newValue
	elif issubclass(newValue, configparser.RawConfigParser):
		_MAIN_CONFIG_DATA = dictParser(allow_no_value=True)
		for copysect in newValue.sections():
			if str(copysect).upper() != str("DEFAULT"):
				_MAIN_CONFIG_DATA.add_section(copysect)
				for copyoption in newValue.options(copysect):
					_MAIN_CONFIG_DATA.set(copysect, copyoption, newValue.get(copysect, copyoption))
	else:
		_MAIN_CONFIG_DATA = None


def _raw_getConfigPath():
	"""gets raw global _MAIN_CONFIG_DATA source path"""
	confFile = str("""/opt/PiAP/PiAP.conf""")
	if _raw_getMainConfig() is not None:
		if _raw_getMainConfig().has_section(_PIAP_KVP_GLOBAL_KEY) is not True:
			tempValue = _raw_getMainConfig()
			tempValue.add_section(_PIAP_KVP_GLOBAL_KEY)
			_raw_setMainConfig(tempValue)
		if _raw_getMainConfig().has_option(_PIAP_KVP_GLOBAL_KEY, """config"""):
			confFile = _raw_getMainConfig().get(_PIAP_KVP_GLOBAL_KEY, """config""")
		else:
			tempValue = _raw_getMainConfig()
			tempValue.set(_PIAP_KVP_GLOBAL_KEY, """config""", confFile)
			_raw_setMainConfig(tempValue)
	return confFile


@remediation.error_handling
def getMainConfig(confFile=None):
	if confFile is None:
		confFile = _raw_getConfigPath()
	__cacheIsAMiss = True
	if _raw_getMainConfig() is not None:
		if _raw_getMainConfig().has_section(_PIAP_KVP_GLOBAL_KEY) is not True:
			tempValue = _raw_getMainConfig()
			tempValue.add_section(_PIAP_KVP_GLOBAL_KEY)
			_raw_setMainConfig(tempValue)
		if _raw_getMainConfig().has_option(_PIAP_KVP_GLOBAL_KEY, _PIAP_KVP_LOAD_SUBKEY) is True:
			safeVar = _raw_getMainConfig()
			__xLoaded_ = False
			try:
				__xLoaded_ = safeVar.getboolean(_PIAP_KVP_GLOBAL_KEY, _PIAP_KVP_LOAD_SUBKEY)
			except Exception as err:
				remediation.error_breakpoint(error=err, context=_raw_getMainConfig)
			if __xLoaded_ is True:
				__cacheIsAMiss = False
			else:
				__cacheIsAMiss = True
	if __cacheIsAMiss is True:
		tempValue = loadMainConfigFile(confFile)
		if tempValue is not None:
			try:
				_raw_setMainConfig(tempValue)
				tempValue = _raw_getMainConfig()
				tempValue.set(_PIAP_KVP_GLOBAL_KEY, _PIAP_KVP_LOAD_SUBKEY, repr(False))
			except Exception as badErr:
				remediation.error_breakpoint(error=badErr, context=_raw_setMainConfig)
		_raw_setMainConfig(tempValue)
	return _raw_getMainConfig()


@remediation.error_handling
def reloadConfigCache(confFile=None):
	try:
		tempload = loadMainConfigFile(confFile)
		if tempload is not None:
			tempload[_PIAP_KVP_GLOBAL_KEY][_PIAP_KVP_LOAD_SUBKEY] = True
		_raw_setMainConfig(tempload)
	except Exception as err:
		remediation.error_breakpoint(error=err, context=reloadConfigCache)
		return False
	return True


def isLoaded():
	"""True if config is loaded."""
	isLoadable = False
	isCached = False
	if getMainConfig() is not None:
		isLoadable = True
		if getMainConfig()[_PIAP_KVP_GLOBAL_KEY][_PIAP_KVP_LOAD_SUBKEY] is True:
			isCached = True
		elif getMainConfig()[_PIAP_KVP_GLOBAL_KEY][_PIAP_KVP_LOAD_SUBKEY] is repr(True):
			isCached = True
	return isLoadable and isCached


def __builtin_isLoaded(*args, **kwargs):
	"""wrapper function for isLoaded()"""
	return isLoaded() is True


@remediation.error_passing
def invalidateConfigCache():
	"""if config is loaded marks as not loaded."""
	if getMainConfig() is not None:
		tempValue = getMainConfig().copy()
		tempValue.set(_PIAP_KVP_GLOBAL_KEY, _PIAP_KVP_LOAD_SUBKEY, repr(False))
		_raw_setMainConfig(tempValue)


@remediation.error_handling
def hasMainConfigOptionsFor(somekey=None):
	"""Returns True if the main configurtion has the given key, otherwise False."""
	hasValue = False
	if (somekey is not None) and (isLoaded() is True) and (getMainConfig().has_section(somekey)):
		hasValue = True
	return hasValue


@remediation.error_handling
def hasMainConfigOptionFor(mainSectionKey=None):
	"""True if config key maps to value."""
	hasValue = False
	if (mainSectionKey is None) or (not isLoaded()):
		hasValue = False
	else:
		if str(""".""") not in str(mainSectionKey):
			hasValue = hasMainConfigOptionsFor(mainSectionKey)
		else:
			kp = str(mainSectionKey).split(""".""")
			main_config = getMainConfig()
			if (main_config.has_section(kp[0]) and (main_config.has_option(kp[0], kp[1]))):
				hasValue = True
	return hasValue


@remediation.error_handling
def writeDefaultMainConfigFile(confFile=None):
	if confFile is None:
		confFile = _raw_getConfigPath()
	theResult = False
	if writeMainConfigFile(confFile, getDefaultMainConfigFile()):
		theResult = True
	return theResult


@remediation.error_passing
def mergeConfigParser(theConfig=None, config_data=None, overwrite=False):
	"""
	Merges the Configuration Dictionary into a configparser.
	param theConfig - configparser.ConfigParser the ConfigParser.
	param config_data - dict the configuration to merge.
	param overwrite - boolean determining if the dict is record of truth or if theConfig is.
	returns dictParser
	"""

	def helper_func(parser, section, option, value):
		try:
			parser.set(section, option, value)
		except Exception:
			parser.set(section, option, repr(value))

	if theConfig is None:
		theConfig = dictParser(allow_no_value=True)
	if config_data is None:
		config_data = dict({})
	for someSection in config_data.keys():
		if theConfig.has_section(someSection) is not True:
			if str(someSection).upper() not in str("DEFAULT"):
				theConfig.add_section(someSection)
		if config_data[someSection] is None:
			raise AssertionError("Logic bomb detected (0=1)")
		for someOption in config_data[someSection].keys():
			if theConfig.has_option(someSection, someOption) is not True or (overwrite is True):
				helper_func(
					theConfig, someSection, someOption,
					config_data[someSection][someOption]
				)
	return theConfig


@remediation.error_handling
def parseConfigParser(config_data=None, theConfig=None, overwrite=True):
	return baseconfig.parseConfigParser(config_data, theConfig, overwrite)


@remediation.error_handling
def writeMainConfigFile(confFile=None, config_data=None):
	"""Generates the Main Configuration file for PiAPlib"""
	try:
		mainConfig = dictParser(allow_no_value=True)
		if confFile is None:
			confFile = _raw_getConfigPath()
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
	if filename is None:
		filename = _raw_getConfigPath()
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
def loadMainConfigFile(confFile=None):
	"""loads the given config file into the main config cache for global use."""
	if confFile is None:
		confFile = _raw_getConfigPath()
	result_config = None
	try:
		emptyConfig = dictParser(allow_no_value=True)
		default_config = getDefaultMainConfigFile()
		if utils.xisfile(str(confFile)):
			mainConfig = readIniFile(str(confFile), emptyConfig)
			result_config = parseConfigParser(default_config, mainConfig, overwrite=True)
		else:
			result_config = getDefaultMainConfigFile()
		reflect_config_data = baseconfig.__config_data_from_kvp(_PIAP_KVP_CONF_KEY, confFile)
		result_config = baseconfig.mergeDicts(result_config, reflect_config_data)
	except Exception as err:
		print(str(err))
		print(str(type(err)))
		print(str((err.args)))
		result_config = getDefaultMainConfigFile()
	return result_config


def _empty_kvp_getters():
	"""returns an empty get-set kvp encoded dict for get (THIS DOC COULD BE IMPROVED)"""
	return dict({
		_PIAP_KVP_GET_KEY: _PIAP_KVP_GET_DEFAULT,
		_PIAP_KVP_SET_KEY: _PIAP_KVP_GET_DEFAULT,
		_PIAP_KVP_LOAD_KEY: _PIAP_KVP_GET_LOAD
	})


def _empty_kvp_setters():
	"""returns an empty get-set kvp encoded dict for get (THIS DOC COULD BE IMPROVED)"""
	return dict({
		_PIAP_KVP_GET_KEY: _PIAP_KVP_SET_DEFAULT,
		_PIAP_KVP_SET_KEY: _PIAP_KVP_SET_DEFAULT,
		_PIAP_KVP_LOAD_KEY: _PIAP_KVP_SET_DEFAULT
	})


def _util_is_not_tuple_or_list(someVar):
	"""utility function to simplify defaultGetter a little"""
	checkRes = False
	if isinstance(someVar, tuple) is not True:
		if isinstance(someVar, list) is not True:
			checkRes = True
	return checkRes


@remediation.error_handling
def defaultGetter(key, defaultValue=None, initIfEmpty=False):
	"""the default configuration getter for most keys."""
	theValue = defaultValue
	if key is None:
		return theValue
	if (getMainConfig() is not None) and hasMainConfigOptionFor(key):
		main_config = getMainConfig()
		if str(""".""") not in str(key):
			theValue = main_config.as_dict()[key]
		else:
			kp = str(key).split(""".""")
			theValue = main_config.get(kp[0], kp[1])
	try:
		if repr(True) in str(theValue)[:6]:
			theValue = True
		elif repr(False) in str(theValue)[:7]:
			theValue = False
		elif (str("[") in str(theValue)[0]) or (str("(") in str(theValue)[0]):
			if (str("[]") in str(theValue)) and (str(theValue) in str("[]")):
				theValue = []
			elif (str("()") in str(theValue)) and (str(theValue) in str("()")):
				theValue = tuple(())
			else:
				theValue = ast.literal_eval(repr('"' * 3)[1:4] + str(theValue) + repr('"' * 3)[1:4])
				if _util_is_not_tuple_or_list(theValue):
						theValue = ast.literal_eval(theValue)
		elif str("{") in str(theValue)[0]:
			if str("{}") in str(theValue) and str(theValue) in str("{}"):
				theValue = dict({})
			else:
				theValue = ast.literal_eval(repr(theValue))
				if isinstance(theValue, dict) is not True:
					theValue = ast.literal_eval(theValue)
	except Exception as err:
		remediation.error_breakpoint(err, context=defaultGetter)
		# print(str(type(theValue)))
		# print(repr(theValue))
	return theValue


def defaultSetter(key, value=None):
	"""the default configuration setter for most keys."""
	if value is None:
		theValue = repr(None)
	else:
		theValue = prepforStore(value)
	if isLoaded() is not True:
		reloadConfigCache(_raw_getConfigPath())
	if getMainConfig() is not None:
		main_config = getMainConfig().as_dict()
	else:
		main_config = getDefaultMainConfigFile()
	new_config_data = baseconfig.__config_data_from_kvp(key, theValue)
	full_config_data = baseconfig.mergeDicts(main_config, new_config_data)
	writeMainConfigFile(config_data=full_config_data)
	invalidateConfigCache()


def getConfigValue(*args, **kwargs):
	"""API accessor function for configs"""
	config_getters = defaultGetter(key=_PIAP_KVP_GET_KEY, defaultValue=_empty_kvp_getters())
	try:
		if (str(kwargs["""key"""]) in config_getters.keys()):
			return utils.getHandler(config_getters[str(kwargs["""key"""])])(*args, **kwargs)
		else:
			return defaultGetter(*args, **kwargs)
	except Exception as err:
		remediation.error_breakpoint(err, context=getConfigValue)
		# print(repr(args))
		# print(repr(kwargs))
		# print(repr(config_getters))
		# print(str(type(config_getters)))
		err = None
		del err
		return None


def checkKeyWordArgsHasKey(*args, **kwargs):
	theResult = None
	if kwargs is not None:
		if kwargs.keys() is not None and (len(kwargs.keys()) > 0):
			if str("""key""") in kwargs.keys():
				theResult = True
	return theResult


def setConfigValue(*args, **kwargs):
	"""API Modifier function for configs"""
	try:
		config_setters = defaultGetter(key=_PIAP_KVP_SET_KEY, defaultValue=_empty_kvp_setters())
		theSetFunc = defaultSetter
		if checkKeyWordArgsHasKey(kwargs) and str(kwargs["""key"""]) in config_setters.keys():
			theSetFunc =utils.getHandler(config_setters[str(kwargs["""key"""])])
		return theSetFunc(*args, **kwargs)
	except Exception as err:
		remediation.error_breakpoint(err, context=setConfigValue)
		print(repr(config_setters))
		print(str(config_setters))
		print(str(type(config_setters)))
		print(repr(kwargs))
		print(str(kwargs))
		print(str(type(kwargs)))
		print(repr(args))
		print(str(args))
		print(str(type(args)))
		raise NotImplementedError(
			str(
				"""[CWE-758] piaplib.pku.config.setConfigValue({}, {}) not implemented."""
			).format(
				str(args), str(kwargs)
			)
		)


def configRegisterKeyValueFactory(*args, **kwargs):
	"""used to register configs"""
	config_getters = defaultGetter(
		key=_PIAP_KVP_GET_KEY,
		defaultValue=_empty_kvp_getters()
	)
	newValue = dict({kwargs['key']: utils.getHandle(kwargs['getter'])})
	new_KeyValueFactory_data = baseconfig.mergeDicts(config_getters, newValue)
	defaultSetter(key=str("""PiAP-piaplib.config_accessors"""), value=new_KeyValueFactory_data)
	if str('setter') in kwargs.keys():
		config_setters = defaultGetter(
			_PIAP_KVP_SET_KEY,
			_empty_kvp_setters()
		)
		newValue = dict({kwargs['key']: utils.getHandle(kwargs['setter'])})
		new_KeyValueFactory_data = baseconfig.mergeDicts(config_setters, newValue)
		defaultSetter(
			key=str("""PiAP-piaplib.config_modifiers"""), value=new_KeyValueFactory_data
		)


def configKeyValueGETFactory(*kvpargs, **kvpkwargs):
	def decorator(fn):
		@functools.wraps(fn)
		def decorated(*args, **kwargs):
			if kvpkwargs['getter'] is None:
				kvpkwargs['getter'] = fn
			configRegisterKeyValueFactory(*kvpargs, **kvpkwargs)
			return fn(*args, **kwargs)
		return decorated
	return decorator


def configKeyValueSETFactory(*kvpargs, **kvpkwargs):
	def decorator(fn):
		@functools.wraps(fn)
		def decorated(*args, **kwargs):
			if kvpkwargs['setter'] is None:
				kvpkwargs['setter'] = fn
			configRegisterKeyValueFactory(*kvpargs, **kvpkwargs)
			return fn(*args, **kwargs)
		return decorated
	return decorator


@remediation.error_passing
def getMainConfigWithArgs(*args, **kwargs):
	if (kwargs is not None) and (len(kwargs.keys()) > 0):
		if (str("""file""") in kwargs.keys()):
			config_path = kwargs[str("""file""")]
		else:
			config_path = _raw_getConfigPath()
		cache_config = getMainConfig(confFile=config_path)
	else:
		cache_config = getMainConfig()
	return cache_config


@remediation.error_passing
def bootstrapconfig(*args, **kwargs):
	"""loads the config"""
	temp_config = getMainConfigWithArgs(*args, **kwargs)
	if temp_config is not None:
		for section in temp_config.sections():
			for thekey in temp_config.options(section):
				if getConfigValue(key=str("{}.{}").format(str(section), str(thekey))) is None:
					configRegisterKeyValueFactory(
						key=str("{}.{}").format(str(section), str(thekey)), getter=defaultGetter
					)
	return


def colorsFromArgs(*args, **kwargs):
	"""retrurns the collection of colors for syntax highlighting"""
	section_color = str("")
	end_color = str("")
	label_color = str("")
	value_color = str("")
	if kwargs is not None and (str("""color""") in kwargs.keys()):
		if kwargs[str("""color""")]:
			section_color = ANSIColors.BLUE
			end_color = ANSIColors.ENDC
			label_color = ANSIColors.WHITE
			value_color = ANSIColors.AMBER
	return (section_color, end_color, label_color, value_color)


def printMainConfig(*args, **kwargs):
	try:
		bootstrapconfig(*args, **kwargs)
	except Exception as err:
		remediation.error_breakpoint(err, context=printMainConfig)
		print(repr(kwargs))
		print(repr(args))
	temp_config = getMainConfigWithArgs(*args, **kwargs)
	temp = temp_config.as_dict()
	(section_color, end_color, label_color, value_color) = colorsFromArgs(*args, **kwargs)
	for section in temp.keys():
		print(str("[{}{}{}]").format(section_color, str(section), end_color))
		for thekey in temp[section].keys():
			print(
				str("\t{}{}{}: {}{}{}").format(
					label_color,
					thekey,
					end_color,
					value_color,
					getConfigValue(key=str("{}.{}").format(str(section), str(thekey))),
					end_color
				)
			)


def printMainConfigJSON(*args, **kwargs):
	"""dump as json data"""
	temp_config = getMainConfigWithArgs(*args, **kwargs)
	temp = temp_config.as_dict()
	json.dumps(temp, sort_keys=True, indent=4)


@remediation.error_handling
def readMainConfig(*args, **kwargs):
	"""reads a given setting from the configuration"""
	temp_config = getMainConfigWithArgs(*args, **kwargs)
	temp = temp_config.as_dict()
	__sKey = str("""setting""")
	__aKey = str(__ALL_KEYS_SETTING__)
	pre_reqs = False
	if kwargs is not None:
		if kwargs.keys() is not None and __sKey in kwargs.keys():
			if isinstance(kwargs.get(__sKey), type(None)) is False:
				if __aKey not in kwargs.get(__sKey):
					pre_reqs = True
	if pre_reqs:
		config_setting = kwargs[__sKey]
		if getConfigValue(key=config_setting) is None:
			configRegisterKeyValueFactory(key=config_setting, getter=defaultGetter)
		cache_setting = getConfigValue(key=config_setting)
		(section_color, end_color, label_color, value_color) = colorsFromArgs(*args, **kwargs)
		if str(""".""") not in str(config_setting):
			temp_config = getMainConfigWithArgs(*args, **kwargs)
			temp = temp_config.as_dict()
			section = str(config_setting)
			print(str("[{}{}{}]").format(section_color, str(section), end_color))
			for thekey in temp[section].keys():
				print(
					str("\t{}{}{}: {}{}{}").format(
						label_color,
						thekey,
						end_color,
						value_color,
						getConfigValue(key=str("{}.{}").format(str(section), str(thekey))),
						end_color
					)
				)
		else:
			print(
				str("{}{}{}: {}{}{}").format(
					label_color,
					str(config_setting),
					end_color,
					value_color,
					cache_setting,
					end_color
				)
			)
	elif isinstance(kwargs.get(__sKey), type(None)) is False and __aKey in kwargs[__sKey]:
		return printMainConfig(*args, **kwargs)
	else:
		raise remediation.PiAPError("Unsure what setting you are trying to access!")


@remediation.error_passing
def parseargs(arguments=None):
	"""Parse the arguments"""
	parser = argparse.ArgumentParser(prog=__prog__, description=__description__, epilog=__epilog__)
	the_action = parser.add_mutually_exclusive_group()
	the_action.add_argument(
		'-r', '--read', dest='config_action', default='dump', action='store_const',
		const='read', help='Read the Configuration. This is the default.'
	)
	the_action.add_argument(
		'-w', '--write', dest='config_action', action='store_const',
		const='write', help='Modify the Configuration.'
	)
	the_action.add_argument(
		'-T', '--test', dest='config_action', action='store_const',
		const='test', help='Load and test the configuration.'
	)
	parser.add_argument(
		'-f', '--file', dest='config_path', default=str('/opt/PiAP/PiAP.conf'),
		help='Path to PiAPLib configuration file. EXPERIMENTAL.'
	)
	the_setting = parser.add_mutually_exclusive_group()
	the_setting.add_argument(
		'-s', '--setting', nargs=1, dest='config_key', default=str(__ALL_KEYS_SETTING__),
		help=str(
			'the setting key value (i.e. lable). or {} for ALL settings. EXPERIMENTAL.'
		).format(__ALL_KEYS_SETTING__)
	)
	the_setting.add_argument(
		'--all', dest='config_key', action='store_const', const=str(__ALL_KEYS_SETTING__),
		help=str(
			'ALL settings. EXPERIMENTAL.'
		).format(__ALL_KEYS_SETTING__)
	)
	parser.add_argument(
		'-x', '--value', nargs=1, dest='config_value', default=None,
		help='The value to modify (see -w). EXPERIMENTAL.'
	)
	parser.add_argument(
		'--no-color', dest='use_syntax_color', action='store_false', default=True,
		help='Disables syntax color in output. Usuful for piping output.'
	)
	parser = utils._handleVersionArgs(parser)
	theResult = parser.parse_known_args(arguments)
	return theResult


def noOp(*args, **kwargs):
	"""Does nothing. PLACEHOLDER."""
	raise NotImplementedError("CRITICAL - PKU Configuration main() not implemented. yet?")


_CONFIG_CLI_ACTIONS = dict({
	'dump': printMainConfig,
	'read': readMainConfig,
	'write': noOp,
	'test': noOp,
	'reload': reloadConfigCache
})
"""Posible upgrade actions."""


@remediation.bug_handling
def main(argv=None):
	"""The Main Event."""
	(args, extras) = parseargs(argv)
	theResult = 1
	config_path = os.path.abspath(_raw_getConfigPath())
	if args.config_path is not None:
		config_path = os.path.abspath(str(args.config_path))
	config_key = None
	config_value = None
	if args.config_key is not None and str(__ALL_KEYS_SETTING__) not in str(args.config_key):
		config_key = args.config_key[0]
	else:
		config_key = args.config_key
	if args.config_value is not None:
		config_value = args.config_value
	if args.use_syntax_color is not None:
		use_syntax_color = args.use_syntax_color
	if args.config_action is not None:
		kwargs = dict({
			'file': config_path, 'color': use_syntax_color,
			'setting': config_key, 'value': config_value
		})
		_CONFIG_CLI_ACTIONS[args.config_action](*extras, **kwargs)
		theResult = 0
	return theResult


@remediation.bug_handling
def __not_main(*args, **kwargs):
	"""Not The Main Event."""
	if isLoaded() is False:
		reloadConfigCache(_raw_getConfigPath())


if __name__ in u'__main__':
	if (sys.argv is not None and (sys.argv is not []) and (len(sys.argv) > 1)):
		exit(main(sys.argv[1:]))
	else:
		exit(main([]))
else:
	__not_main()
