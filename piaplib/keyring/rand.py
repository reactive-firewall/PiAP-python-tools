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
	import sys
	if os.__name__ is None:
		raise ImportError("Failed to import rand.")
	if sys.__name__ is None:
		raise ImportError("Failed to import rand.")
except Exception:
	raise ImportError("Failed to import rand.")
	exit(255)


try:
	from ..pku import remediation as remediation
except Exception:
	try:
		import pku.remediation as remediation
	except Exception:
		raise ImportError("Error Importing remediation")

RAND_CHARS = [
	str("""a"""), str("""b"""), str("""c"""), str("""d"""), str("""e"""), str("""f"""),
	str("""g"""), str("""h"""), str("""i"""), str("""j"""), str("""k"""), str("""l"""),
	str("""m"""), str("""n"""), str("""o"""), str("""p"""), str("""q"""), str("""r"""),
	str("""s"""), str("""t"""), str("""u"""), str("""v"""), str("""w"""), str("""x"""),
	str("""y"""), str("""z"""), str("""1"""), str("""2"""), str("""3"""), str("""4"""),
	str("""5"""), str("""6"""), str("""7"""), str("""8"""), str("""9"""), str("""0"""),
	str("""!"""), str("""@"""), str("""#"""), str("""$"""), str("""%"""), str("""^"""),
	str("""&"""), str("""*"""), str("""("""), str(""")"""), str("""_"""), str("""-"""),
	str("""+"""), str("""="""), str("""<"""), str(""">"""), str(""","""), str("""."""),
	str("""?"""), str("""/"""), str("""'"""), str(""";"""), str("""["""), str("""]"""),
	str("""{"""), str("""}"""), str("""|"""), str("""~"""), str("""\""""), str(""" """)
]
"""Posible Chars for randChar (which is not so random, as it is very qwerty based)"""


__prog__ = """piaplib.keyring.rand"""
"""The name of this PiAPLib tool is rand"""


@remediation.error_handling
def rand(count=None):
	"""wrapper for os.urandom()"""
	if count is None or (isinstance(count, int) is False) or count <= 1:
		x_count = 512
	else:
		x_count = count
	try:
		theEntropy = os.urandom(x_count)
		if isinstance(theEntropy, str):
			theEntropy = bytes(theEntropy)
		return theEntropy
	except Exception as err:
		print(str(u'FAILED DURRING RAND. ABORT.'))
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		err = None
		del err
	raise AssertionError("IMPOSIBLE STATE REACHED IN RAND. ABORT.")


@remediation.error_handling
def randStr(count=None):
	"""wrapper for str(os.urandom())"""
	if count is None or (isinstance(count, int) is False) or count <= 1:
		x_count = randInt(1, 1, 512)
	else:
		x_count = count
	try:
		import string
		return str("").join([string.printable[randInt(1, 1, 99)] for _ in range(x_count)])
	except Exception as err:
		print(str(u'FAILED DURRING RAND-STR. ABORT.'))
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		err = None
		del err
	raise AssertionError("BUG: BAD STATE REACHED IN RAND-STR. ABORT.")


@remediation.error_handling
def randPW(count=None):
	"""wrapper for str(os.urandom())"""
	if count is None or (isinstance(count, int) is False) or count <= 1:
		x_count = randInt(1, 1, 512)
	else:
		x_count = count
	try:
		return str(randStr((x_count + 4))).replace(str("""\\x"""), str(""))[2:-1]
	except Exception as err:
		print(str(u'FAILED DURRING RAND-PW. ABORT.'))
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		err = None
		del err
	raise AssertionError("BUG: BAD STATE REACHED IN RAND-PW. ABORT.")


@remediation.error_handling
def randSSID(count=None):
	"""
	generate random SSID
	WARNING: this is a placeholder.
	count - length to return. Defaults to 20.
	"""
	if count is None or (isinstance(count, int) is False) or count <= 1:
		x_count = 20
	else:
		x_count = int(count)
	try:
		if x_count <= 1:
			return randChar(1)
		else:
			theResult = ""
			for someChar in range(x_count):
				nextChar = randChar(1)
				while not (nextChar.isalpha() or nextChar.isdigit()):
					nextChar = randChar(1)
				theResult = theResult.join(nextChar)
			return theResult
	except Exception as err:
		print(str(u'FAILED DURRING RAND-SSID. ABORT.'))
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		err = None
		del err
	raise AssertionError("IMPOSIBLE STATE REACHED IN RAND-SSID. ABORT.")


@remediation.error_handling
def randIP(count=None, min=0, max=256):
	"""
	mostly for testing, generates random ip
	WARNING: this is not intended for cryptographic randomness, in that case use os.urandom().
	count - int the number of integers to return. Defaults to 1.
	min - int the smallest value of integers to return. Defaults to 0.
	max - int the largest value of integers to return. Defaults to 512.
	"""
	if min is None or (isinstance(min, int) is False) or min <= 0:
		min = 1
	if max is None or (isinstance(max, int) is False) or max <= 0 or max <= min or max >= 256:
		max = 255
	if count is None or (isinstance(count, int) is False) or count <= 1:
		x_count = 1
	else:
		x_count = int(count)
	try:
		if x_count <= 1:
			return str(str("{}.{}.{}.{}").format(
				randInt(1, min, max), randInt(1, min, max),
				randInt(1, min, max), randInt(1, min, max)
			))
		else:
			theResult = []
			for someIP in range(x_count):
				theResult.append(randIP(1, min, max))
			return theResult
	except Exception as err:
		print(str(u'FAILED DURRING RAND-IIP. ABORT.'))
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		err = None
		del err
	raise AssertionError("IMPOSIBLE STATE REACHED IN RAND-IP. ABORT.")


@remediation.error_handling
def fastrandInt(count=None, max=512):
	"""
	Wrapper for random.randint(min, max)
	WARNING: this is not intended for cryptographic randomness, in that case use os.urandom().
	count - int the number of integers to return. Defaults to 1.
	min - fast as 0.
	max - int the largest value of integers to return. Defaults to 512.
	"""
	min = 0
	if max is None or (isinstance(max, int) is False) or max <= 0 or max <= min:
		max = 512
	if count is None or (isinstance(count, int) is False) or count <= 1:
		x_count = 1
	else:
		x_count = int(count)
	try:
		if x_count <= 1:
			try:
				import six
				if six.PY2:
					return int(int(bytearray(os.urandom(16))[8]) % max)
				else:
					return int(os.urandom(max), max)
			except Exception:
				return int(int(bytearray(os.urandom(16))[8]) % max)
		else:
			return [fastrandInt(1, min, max) for someInt in range(x_count)]
	except Exception as err:
		print(str(u'FAILED DURRING RAND-INT. ABORT.'))
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		err = None
		del err
	raise AssertionError("IMPOSIBLE STATE REACHED IN RAND-INT. ABORT.")


@remediation.error_handling
def randInt(count=None, min=0, max=512):
	"""
	Wrapper for random.randint(min, max)
	WARNING: this is not intended for cryptographic randomness, in that case use os.urandom().
	count - int the number of integers to return. Defaults to 1.
	min - int the smallest absolute value of integers to return. Defaults to 0.
	max - int the largest absolute value of integers to return. Defaults to 512.
	"""
	if min is None or (isinstance(min, int) is False) or min <= 0:
		return int(fastrandInt(1, max))
	if max is None or (isinstance(max, int) is False) or max <= 0 or max <= min:
		max = 512
	if count is None or (isinstance(count, int) is False) or count <= 1:
		x_count = 1
	else:
		x_count = int(count)
	try:
		if x_count <= 1:
			entropy_seed = int(fastrandInt(1, max))
			if min <= entropy_seed:
				return entropy_seed
			else:
				return int(min)
		else:
			return [randInt(1, min, max) for someInt in range(x_count)]
	except Exception as err:
		print(str(u'FAILED DURRING RAND-INT. ABORT.'))
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		err = None
		del err
	raise AssertionError("IMPOSIBLE STATE REACHED IN RAND-INT. ABORT.")



@remediation.error_handling
def randBool(count=None):
	"""wrapper for str(os.urandom())"""
	if count is None or (isinstance(count, int) is False) or count <= 1:
		x_count = 1
	else:
		x_count = count
	try:
		if x_count == 1:
			return (bool(((randInt(1, 0, 512) % 2) == 0)) is True)
		else:
			theResult = []
			for someInt in range(x_count):
				theResult.append(randBool(1))
			return theResult
	except Exception as err:
		print(str(u'FAILED DURRING RAND-BOOL. ABORT.'))
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		err = None
		del err
	raise AssertionError("IMPOSIBLE STATE REACHED IN RAND-BOOL. ABORT.")


@remediation.error_handling
def randChar(count=None):
	"""wrapper for str(os.urandom())"""
	if count is None or (isinstance(count, int) is False) or count <= 1:
		x_count = 1
	else:
		x_count = int(count)
	try:
		theRandomResult = str("")
		for char_x in range(x_count):
			char_rand_seed = str(RAND_CHARS[randInt(1, 0, 65)])
			while str(char_rand_seed).isalnum() is False:
				char_rand_seed = str(RAND_CHARS[randInt(1, 0, 65)])
			if (randBool(1)):
				char_rand_seed = str(char_rand_seed).upper()
			theRandomResult = str("{}{}").format(theRandomResult, str(char_rand_seed))
		return theRandomResult
	except Exception as err:
		print(str(u'FAILED DURRING RAND-CHAR. ABORT.'))
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		print(str(RAND_CHARS))
		print(str(len(RAND_CHARS)))
		err = None
		del err
	raise AssertionError("IMPOSIBLE STATE REACHED IN RAND-CHAR. ABORT.")


RANDOM_TASKS = {
	u'raw': rand, u'int': randInt, u'str': randStr, u'bool': randBool,
	u'passphrase': randPW, u'SSID': randSSID, u'IP': randIP}
"""
	The posible random actions.
	raw - same as calling os.urandom(). This is default.
	int - return a random integer.
	str - return a random string.
	bool - return a random boolean.
	passphrase - return a random string to use as a passphrase. For automation; Not secure entry.
	SSID - return a random string to use as a wifi SSID. For automation; Not secure entry.
	IP - return a random IPv4 IP address.
"""


@remediation.error_handling
def parseArgs(arguments=[None]):
	"""Parses the CLI arguments."""
	theArgs = None
	try:
		parser = argparse.ArgumentParser(
			prog=__prog__,
			description='Handles PiAP random utility functions',
			epilog="PiAP Controller for near-cryptographic randomness. Use os.urandom for CPRNG."
		)
		parser.add_argument(
			'-g',
			'--generate',
			dest='random_action',
			choices=RANDOM_TASKS.keys(),
			default='raw',
			type=str,
			required=False,
			help='the random service option.'
		)
		parser.add_argument(
			'-c',
			'--count',
			dest='count',
			default=int(512),
			type=int,
			required=False,
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


@remediation.error_handling
def useRandTool(tool, *args, **kwargs):
	"""Handler for launching pocket-tools."""
	if tool is None:
		return None
	if tool in RANDOM_TASKS.keys():
		return RANDOM_TASKS[tool](*args, **kwargs)
	else:
		raise NotImplementedError("IMPOSIBLE STATE REACHED IN RAND-CHAR. ABORT.")


@remediation.bug_handling
def main(argv=None):
	"""Simple but Random Main event."""
	args = parseArgs(argv)
	if args.random_action is not None:
		if args.count is not None:
			print(useRandTool(args.random_action, args.count))
		else:
			print(useRandTool(args.random_action))
	else:
		return 3
	return 0


if __name__ in u'__main__':
	try:
		import sys
		error_code = main(sys.argv[1:])
		exit(error_code)
	except Exception as err:
		print(str(u'MAIN FAILED DURRING RAND. ABORT.'))
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		del err
		exit(255)
	finally:
		exit(0)

