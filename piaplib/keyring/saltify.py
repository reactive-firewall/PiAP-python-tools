#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Pocket PiAP
# ......................................................................
# Copyright (c) 2017, Kendrick Walls
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
	import functools
	import argparse
	import hashlib
	import hmac
	if hmac.__name__ is None:
		raise ImportError("Failed to import saltify.")
except Exception:
	raise ImportError("Failed to import saltify.")
	exit(255)


def parseArgs(arguments=None):
	theArgs = None
	try:
		parser = argparse.ArgumentParser(description='saltify a message')
		parser.add_argument(
			'-m',
			'--msg',
			dest='msg',
			required=True,
			type=str,
			help='The Message. An unsalted message.'
		)
		parser.add_argument(
			'-S',
			'--salt',
			dest='salt',
			required=True,
			type=str,
			help='The Salt. A unique secret.'
		)
		theArgs = parser.parse_args(arguments)
	except Exception as err:
		print(str(u'FAILED DURRING SALTIFY. ABORT.'))
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		err = None
		del err
		theArgs = None
	return theArgs


def memoize(func):
	cache = func.cache = {}

	@functools.wraps(func)
	def memoized_func(*args, **kwargs):
		try:
			key = str(args) + str(kwargs)
			if key not in cache:
				cache[key] = func(*args, **kwargs)
			return cache[key]
		except Exception:
			return func(*args, **kwargs)

	return memoized_func


@memoize
def saltify(raw_msg, raw_salt):
	the_salted_msg = str(hmac.new(
		str(raw_salt).encode("utf8"),
		str(raw_msg).encode("utf8"),
		hashlib.sha512).hexdigest()
	)
	return the_salted_msg


def main(argv=None):
	args = parseArgs(argv)
	print(saltify(str(args.msg), str(args.salt)))
	return 0


if __name__ in u'__main__':
	exitcode = 3
	try:
		import sys
		exitcode = main(sys.argv[1:])
	except Exception as err:
		print(str(u'MAIN FAILED DURRING SALTIFY. ABORT.'))
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		del err
		exitcode = 255
	exit(exitcode)

