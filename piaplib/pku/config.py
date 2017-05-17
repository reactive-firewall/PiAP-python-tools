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


def addExtension(somefile, extension):
	"""Ensures the given extension is used."""
	if (somefile is None):
		return None
	if (extension is None):
		return somefile
	if (len(str(somefile)) > len(extension)):
		offset = (-1 * len(extension))
		if (extension in str(somefile)[offset:-1]) and (str(".") in str(somefile)):
			return somefile
		else:
			return str("{}.{}").format(somefile, extension)
	else:
		return str("{}.{}").format(somefile, extension)


def readJsonFile(somefile):
	"""Reads the raw json file."""
	read_data = None
	try:
		with utils.open_func(somefile, 'r', encoding='utf-8') as json_data_file:
			read_data = json.load(fp=json_data_file, ensure_ascii=True)
	except Exception as jsonerr:
		print("")
		print("Error: Failed to load JSON file.")
		print(str(type(jsonerr)))
		print(str(jsonerr))
		print(str((jsonerr.args)))
		print("")
		read_data = None
	return read_data


def writeJsonFile(data, somefile):
	"""Reads the raw json file."""
	did_write = False
	try:
		someFilePath = addExtension(somefile, str('json'))
		with utils.open_func(someFilePath, 'w', encoding='utf-8') as outfile:
			json.dump(data, fp=outfile, indent=1, separators=(',', ': '))
			did_write = True
	except Exception as jsonerr:
		print("")
		print("Error: Failed to load JSON file.")
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

	def readYamlFile(somefile):
		"""Reads the raw Yaml file."""
		read_data = None
		try:
			with utils.open_func(somefile, 'r', encoding='utf-8') as ymalfile:
				read_data = yaml.load(ymalfile)
		except Exception as yamlerr:
			print("")
			print("Error: Failed to load YAML file.")
			print(str(type(yamlerr)))
			print(str(yamlerr))
			print(str((yamlerr.args)))
			print("")
			read_data = None
		return read_data

	def writeYamlFile(data, somefile):
		"""Writes the Yaml file."""
		did_write = False
		try:
			someFilePath = addExtension(somefile, str('yaml'))
			did_write = utils.writeFile(someFilePath, yaml.dump(data))
		except Exception as yamlerr:
			print("")
			print("Error: Failed to load YAML file.")
			print(str(type(yamlerr)))
			print(str(yamlerr))
			print(str((yamlerr.args)))
			print("")
			did_write = None
		return did_write

except Exception:
	pass


def hasJsonSupport():
	support_json = False
	try:
		support_json = (json.__name__ is not None)
	except:
		support_json = False
	return support_json


def hasYamlSupport():
	support_yaml = False
	try:
		support_yaml = (yaml.__name__ is not None)
	except:
		support_yaml = False
	return support_yaml


if __name__ in u'__main__':
	raise NotImplementedError("ERROR: Can not run config as main. Yet?")

