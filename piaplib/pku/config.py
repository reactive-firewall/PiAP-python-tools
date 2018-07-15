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


__prog__ = """piaplib.pku.upgrade"""
"""The name of this PiAPLib tool is Pocket Knife Configuration Unit"""


__description__ = """Runs piaplib configuration functions."""
"""The description of this PiAPLib tool is 'Runs piaplib configuration functions.'"""


__epilog__ = """basically a python wrapper for configuration I/O."""
"""...basically a python wrapper for pip install --upgrade."""


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

	def __getitem__(self, key):
		try:
			import six
			if six.PY2:
				if key == 'sections':
					return self.sections
				elif not (str(key).upper() == str("DEFAULT")):
					return self.as_dict()[key]
				else:
					return super(dictParser, self)._getitem__(self, key)
			else:
				return super(dictParser, self)._getitem__(self, key)
		except Exception:
			if key == 'sections':
				return self.sections
			elif not (str(key).upper() == str("DEFAULT")):
				return self.as_dict()[key]
			else:
				return super(dictParser, self)._getitem__(self, key)

	def read_dict(self, dictionary, source='<dict>'):
		try:
			import six
			if six.PY2:
				for someSection in dictionary.keys():
					if not self.has_section(someSection) and str(someSection) not in str("DEFAULT"):
						self.add_section(someSection)
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
			else:
				return super(dictParser, self).read_dict(self, dictionary)
		except Exception:
			for someSection in dictionary.keys():
				if not self.has_section(someSection) and str(someSection) not in str("DEFAULT"):
					self.add_section(someSection)
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
	if isinstance(newValue, dict):
		_MAIN_CONFIG_DATA = dictParser(allow_no_value=True)
		_MAIN_CONFIG_DATA.read_dict(newValue)
	elif isinstance(newValue, dictParser):
		_MAIN_CONFIG_DATA = newValue
	else:
		_MAIN_CONFIG_DATA = None


@remediation.error_handling
def getMainConfig(confFile=None):
	if confFile is None:
		confFile = str('/opt/PiAP/PiAP.conf')
	if _raw_getMainConfig() is None:
		tempValue = loadMainConfigFile(confFile)
		tempValue['PiAP-piaplib']['loaded'] = True
		_raw_setMainConfig(newValue=tempValue)
	return _raw_getMainConfig()


@remediation.error_passing
def reloadConfigCache(confFile=None):
	tempValue = loadMainConfigFile(confFile)
	tempValue['PiAP-piaplib']['loaded'] = True
	_raw_setMainConfig(newValue=tempValue)
	return


@remediation.error_passing
def isLoaded():
	"""True if config is loaded."""
	if (getMainConfig() is not None):
		isLoadable = True
	if (getMainConfig()['PiAP-piaplib']['loaded'] is not False):
		isCached = True
	return ((isLoadable and isCached) is True)


@remediation.error_passing
def invalidateConfigCache():
	"""if config is loaded marks as not loaded."""
	tempValue = getMainConfig().deep_copy()
	tempValue['PiAP-piaplib']['loaded'] = False
	_raw_setMainConfig(newValue=tempValue)


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
		if (main_config.has_section(kp[0]) and (main_config.has_option(kp[0], kp[1]))):
			hasValue = True
	return hasValue


@remediation.error_handling
def writeDefaultMainConfigFile(confFile=None):
	if confFile is None:
		confFile = str('/opt/PiAP/PiAP.conf')
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
		if not theConfig.has_section(someSection) and str(someSection) not in str("DEFAULT"):
			theConfig.add_section(someSection)
		if config_data[someSection] is None:
			raise AssertionError("Logic bomb detected (0=1)")
		for someOption in config_data[someSection].keys():
			if not theConfig.has_option(someSection, someOption) or (overwrite is True):
				helper_func(
					theConfig, someSection, someOption,
					config_data[someSection][someOption]
				)
	return theConfig


@remediation.error_handling
def parseConfigParser(config_data=None, theConfig=None, overwrite=True):
	"""
	Merges the configparser into the Configuration Dictionary.
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
def writeMainConfigFile(confFile=None, config_data=None):
	"""Generates the Main Configuration file for PiAPlib"""
	try:
		mainConfig = dictParser(allow_no_value=True)
		if confFile is None:
			confFile = str('/opt/PiAP/PiAP.conf')
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
def loadMainConfigFile(confFile=None):
	if confFile is None:
		confFile = str('/opt/PiAP/PiAP.conf')
	try:
		emptyConfig = dictParser(allow_no_value=True)
		result_config = getDefaultMainConfigFile()
		if utils.xisfile(str(confFile)):
			mainConfig = readIniFile(str(confFile), emptyConfig)
			result_config = parseConfigParser(result_config, mainConfig, True)
	except Exception as err:
		print(str(err))
		print(str(type(err)))
		print(str((err.args)))
		return getDefaultMainConfigFile()
	return result_config


def getHandle(handler):
	for someFunc in locals().copy().keys():
		if handler == locals()[someFunc]:
			handle = someFunc
	for theFunc in globals().copy().keys():
		if handler == globals()[theFunc]:
			handle = theFunc
	return handle


def getHandler(handle):
	possibles = globals().copy()
	# possibles.update(globals()['__builtins__'].__dict__)
	possibles.update(locals())
	handler = possibles.get(handle)
	if handler is None:
		raise NotImplementedError(str("Function {} not implemented").format(str(handle)))
	return handler


def prepforStore(rawValue):
	"""pack value for storage"""
	taint_value = str(rawValue)
	if str('"') in taint_value[0] or str("""'""") in taint_value[0]:
		taint_value = repr(taint_value)
	elif str("""(""") in taint_value[0] or str("""[""") in taint_value[0]:
		taint_value = repr(rawValue)
	elif str("""{""") in taint_value[0]:
		taint_value = repr(rawValue)
	elif str("""<function""") in taint_value[0:9]:
		taint_value = getHandle(str(rawValue))
	return taint_value


_PIAP_KVP_GET_KEY = str("""PiAP-piaplib.config_accessors""")


_PIAP_KVP_GET_DEFAULT = str("""defaultGetter""")


_PIAP_KVP_SET_KEY = str("""PiAP-piaplib.config_modifiers""")


_PIAP_KVP_SET_DEFAULT = str("""defaultSetter""")


def _empty_kvp_getters():
	"""returns an empty get-set kvp encoded dict for get (THIS DOC COULD BE IMPROVED)"""
	return dict({
		_PIAP_KVP_GET_KEY: _PIAP_KVP_GET_DEFAULT,
		_PIAP_KVP_SET_KEY: _PIAP_KVP_GET_DEFAULT
	})


def _empty_kvp_setters():
	"""returns an empty get-set kvp encoded dict for get (THIS DOC COULD BE IMPROVED)"""
	return dict({
		_PIAP_KVP_GET_KEY: _PIAP_KVP_SET_DEFAULT,
		_PIAP_KVP_SET_KEY: _PIAP_KVP_SET_DEFAULT
	})


@remediation.error_passing
def defaultGetter(key, defaultValue=None, initIfEmpty=False):
	"""the default configuration getter for most keys."""
	theValue = defaultValue
	if hasMainConfigOptionFor(key):
		main_config = getMainConfig().as_dict()
		default_config_data = baseconfig.__config_data_from_kvp(key, defaultValue)
		if initIfEmpty is True:
			full_config_data = baseconfig.mergeDicts(main_config, default_config_data)
		else:
			full_config_data = baseconfig.mergeDicts(default_config_data, main_config)
		if str(""".""") not in str(key):
			theValue = full_config_data[key]
		else:
			kp = str(key).split(""".""")
			theValue = full_config_data[kp[0]][kp[1]]
	try:
		if str("[") in str(theValue)[0] or str("(") in str(theValue)[0]:
			theValue = ast.literal_eval(repr('"' * 3)[1:4] + repr(theValue) + repr('"' * 3)[1:4])
		elif str("{") in str(theValue)[0]:
			if str("{}") in str(theValue) and str(theValue) in str("{}"):
				theValue = dict({})
			else:
				theValue = ast.literal_eval(repr(theValue))
				if not isinstance(theValue, dict):
					theValue = ast.literal_eval(theValue)
	except Exception as err:
		remediation.error_breakpoint(err, context=dict)
	return theValue


def defaultSetter(key, newValue=None):
	"""the default configuration setter for most keys."""
	if newValue is None:
		theValue = repr(None)
	else:
		theValue = newValue
	if not isLoaded():
		reloadConfigCache()
	main_config = getMainConfig().as_dict()
	new_config_data = baseconfig.__config_data_from_kvp(key, repr(theValue))
	full_config_data = baseconfig.mergeDicts(main_config, new_config_data)
	writeMainConfigFile(config_data=full_config_data)
	invalidateConfigCache()


def getConfigValue(*args, **kwargs):
	"""API accessor function for configs"""
	config_getters = defaultGetter(key=_PIAP_KVP_GET_KEY, defaultValue=_empty_kvp_getters())
	try:
		if (str(kwargs['key']) in config_getters.keys()):
			return getHandler(config_getters[str(kwargs['key'])])(*args, **kwargs)
		else:
			return defaultGetter(*args, **kwargs)
	except Exception as err:
		remediation.error_breakpoint(err, context=getConfigValue)
		# print(repr(args))
		# print(repr(kwargs))
		print(repr(config_getters))
		print(str(type(config_getters)))
		return None


def setConfigValue(*args, **kwargs):
	"""API Modifier function for configs"""
	config_setters = defaultGetter(key=_PIAP_KVP_SET_KEY, defaultValue=_empty_kvp_setters())
	try:
		if (str(kwargs['key']) in config_setters.keys()):
			return getHandler(config_setters[str(kwargs['key'])])(*args, **kwargs)
		else:
			return defaultSetter(*args, **kwargs)
	except Exception as err:
		remediation.error_breakpoint(err, getConfigValue)
		print(repr(config_setters))
		print(str(config_setters))
		print(str(type(config_setters)))
		return None


def configRegisterKeyValueFactory(*args, **kwargs):
	"""used to register configs"""
	config_getters = defaultGetter(
		key=_PIAP_KVP_GET_KEY,
		defaultValue=_empty_kvp_getters()
	)
	newValue = dict({kwargs['key']: getHandle(kwargs['getter'])})
	new_KeyValueFactory_data = baseconfig.mergeDicts(config_getters, newValue)
	defaultSetter(key=str("""PiAP-piaplib.config_accessors"""), newValue=new_KeyValueFactory_data)
	if str('setter') in kwargs.keys():
		config_setters = defaultGetter(
			_PIAP_KVP_SET_KEY,
			_empty_kvp_setters()
		)
		newValue = dict({kwargs['key']: getHandle(kwargs['setter'])})
		new_KeyValueFactory_data = baseconfig.mergeDicts(config_setters, newValue)
		defaultSetter(
			key=str("""PiAP-piaplib.config_modifiers"""), newValue=new_KeyValueFactory_data
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


@configKeyValueGETFactory(key="PiAP-piaplib.loaded")
def __builtin_isLoaded(*args, **kwargs):
	return isLoaded()


def getMainConfigWithArgs(*args, **kwargs):
	if kwargs is not None and (str("""file""") in kwargs.keys()):
		config_path = kwargs[str("""file""")]
		cache_config = getMainConfig(confFile=config_path)
	else:
		cache_config = getMainConfig()
	return cache_config


def printMainConfig(*args, **kwargs):
	temp_config = getMainConfigWithArgs(*args, **kwargs)
	temp = temp_config.as_dict()
	for section in temp.keys():
		for thekey in temp[section].keys():
			if getConfigValue(key=str("{}.{}").format(str(section), str(thekey))) is None:
				configRegisterKeyValueFactory(
					key=str("{}.{}").format(str(section), str(thekey)), getter=defaultGetter
				)
	temp_config = getMainConfigWithArgs(*args, **kwargs)
	temp = temp_config.as_dict()
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


def readMainConfig(*args, **kwargs):
	"""reads a given setting from the configuration"""
	temp_config = getMainConfigWithArgs(*args, **kwargs)
	temp = temp_config.as_dict()
	__sKey = str("""setting""")
	__aKey = str(__ALL_KEYS_SETTING__)
	if kwargs is not None and (__sKey in kwargs.keys()) and __aKey not in kwargs[__sKey]:
		config_setting = kwargs[__sKey]
		if getConfigValue(key=config_setting) is None:
			configRegisterKeyValueFactory(key=config_setting, getter=defaultGetter)
		cache_setting = getConfigValue(key=config_setting)
		temp_config = getMainConfigWithArgs(*args, **kwargs)
		temp = temp_config.as_dict()
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
		if str(""".""") not in str(config_setting):
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
		'-x', '--value', dest='config_value', default=None,
		help='The value to modify (see -w). EXPERIMENTAL.'
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
	"""The Main Event. Upgrade Time."""
	(args, extras) = parseargs(argv)
	theResult = 1
	config_path = os.path.abspath(str('/opt/PiAP/PiAP.conf'))
	if args.config_path is not None:
		config_path = os.path.abspath(str(args.config_path))
	config_key = None
	if args.config_key is not None and str(__ALL_KEYS_SETTING__) not in str(args.config_key):
		config_key = args.config_key[0]
	if args.config_action is not None:
		kwargs = dict({'file': config_path, 'color': True, 'setting': config_key})
		_CONFIG_CLI_ACTIONS[args.config_action](**kwargs)
		theResult = 0
	return theResult


if __name__ in u'__main__':
	try:
		if (sys.argv is not None and (sys.argv is not []) and (len(sys.argv) > 1)):
			exit(main(sys.argv[1:]))
		else:
			exit(main([]))
	except Exception:
		raise ImportError("Error running main")
	exit(3)
else:
	if isLoaded() is False:
		reloadConfigCache()
