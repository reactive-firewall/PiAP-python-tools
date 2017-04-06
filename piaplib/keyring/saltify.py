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
	import hashlib
	import hmac
except Exception:
	raise ImportError()
	exit(255)


def parseArgs(arguments=None):
	theArgs = None
	try:
		parser = argparse.ArgumentParser(description='check for an arp entry')
		parser.add_argument(
			'-m',
			'--msg',
			dest='msg',
			required=True,
			help='The Message. An unsalted message.'
		)
		parser.add_argument(
			'-S',
			'--salt',
			dest='salt',
			required=True,
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


def saltify(raw_msg, raw_salt):
	return str(hmac.new(raw_salt, raw_msg, hashlib.sha512).hexdigest())


def main(argv=None):
	args = parseArgs(argv)
	if args.msg is None or args.salt is None:
		exit(2)
	else:
		print(saltify(str(args.msg), str(args.salt)))


""" Test cases """


def _test_try_or_fail(f):
	""" decorator for try-except wrapping tests """
	def helper():
		theResult = False
		try:
			theResult = f()
		except Exception as failErr:
			failErr = None
			del failErr
			theResult = False
		return theResult
	return helper


@_test_try_or_fail
def _test_keyring_salt_test_salt():
	test_salt_one = str(
		u'7a9356011e7f6bc42105deee6d49983e0cfa7650c7fce5d' +
		u'5d3b19aacca91605199ee017707f627087f8376143f368b17ed927d918eecfe100a7b1b6e39dd3c8a'
	)
	theTest = (str(saltify("Test Message", "testSalt")) is str(test_salt_one))
	del test_salt_one
	if theTest:
		del theTest
		return True
	else:
		del theTest
		return False


if __name__ in u'__main__':
	try:
		import sys
		main(sys.argv)
	except Exception as err:
		print(str(u'MAIN FAILED DURRING SALTIFY. ABORT.'))
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		del err
		exit(255)
	finally:
		exit(0)

