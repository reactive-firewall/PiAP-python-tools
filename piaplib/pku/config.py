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
		raise ImportError("Error Importing config")


try:
	from . import remediation as remediation
except Exception:
	try:
		import remediation as remediation
	except Exception:
		raise ImportError("Error Importing remediation")


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
		someFilePath = utils.addExtension(somefile, str('yaml'))
		with utils.open_func(file=someFilePath, mode=u'r', encoding=u'utf-8') as ymalfile:
			if yaml.version_info < (0, 15):
				read_data = yaml.safe_load(ymalfile)
			else:
				yml = yaml.YAML(typ='safe', pure=True)  # 'safe' load and dump
				read_data = yml.load(ymalfile)
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
		someFilePath = utils.addExtension(somefile, str('yaml'))
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


if __name__ in u'__main__':
	raise NotImplementedError("ERROR: Can not run config as main. Yet?")

