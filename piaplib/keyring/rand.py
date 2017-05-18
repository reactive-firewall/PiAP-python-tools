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
	import argparse
	import os
	if os.__name__ is None:
		raise ImportError("Failed to import rand.")
except Exception:
	raise ImportError("Failed to import rand.")
	exit(255)


def parseArgs(arguments=None):
	theArgs = None
	try:
		parser = argparse.ArgumentParser(description='random string wrapper')
		parser.add_argument(
			'-c',
			'--count',
			dest='count',
			default=int(512),
			type=int,
			help='count.'
		)
		theArgs = parser.parse_args(arguments)
	except Exception as err:
		print(str(u'FAILED DURRING RAND. ABORT.'))
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		err = None
		del err
		theArgs = None
	return theArgs


def rand(count=None):
	"""wrapper for os.urandom()"""
	if count is None or count < 0:
		x_count = 512
	else:
		x_count = count
	try:
		return os.urandom(x_count)
	except Exception as err:
		print(str(u'FAILED DURRING RAND. ABORT.'))
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		err = None
		del err
		os.abort(3)


def randStr(count=None):
	"""wrapper for str(os.urandom())"""
	if count is None or count < 0:
		x_count = 512
	else:
		x_count = count
	try:
		return str(rand(x_count))
	except Exception as err:
		print(str(u'FAILED DURRING RAND. ABORT.'))
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		err = None
		del err
		os.abort(3)


def randInt(count=None, min=0, max=512):
	"""wrapper for int(os.urandom())"""
	if count is None or count < 0:
		x_count = 32
	else:
		x_count = count
	try:
		return (int(rand(x_count)) + min) % max
	except Exception as err:
		print(str(u'FAILED DURRING RAND. ABORT.'))
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		err = None
		del err
		os.abort(3)


def randBool(count=None):
	"""wrapper for str(os.urandom())"""
	if count is None or count < 0:
		x_count = 1
	else:
		x_count = (count % 2)
	try:
		return (bool(randInt(x_count)) is True)
	except Exception as err:
		print(str(u'FAILED DURRING RAND. ABORT.'))
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		err = None
		del err
		os.abort(3)


def randChar(count=None):
	"""wrapper for str(os.urandom())"""
	import os
	if count is None or count < 0:
		x_count = 1
	else:
		x_count = count
	try:
		theRandomResult = str("")
		for char_x in range(x_count):
			char_rand_seed = rand(1)
			while str(char_rand_seed).isalnum() is False:
				char_rand_seed = rand(1)
			theRandomResult = str("{}{}").format(theRandomResult, str(char_rand_seed))
		return theRandomResult
	except Exception as err:
		print(str(u'FAILED DURRING RAND. ABORT.'))
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		err = None
		del err
		os.abort(3)


def main(argv=None):
	args = parseArgs(argv)
	if args.count is None:
		exit(2)
	else:
		print(str(rand(args.count)))


if __name__ in u'__main__':
	try:
		import sys
		main(sys.argv[1:])
	except Exception as err:
		print(str(u'MAIN FAILED DURRING RAND. ABORT.'))
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		del err
		exit(255)
	finally:
		exit(0)

