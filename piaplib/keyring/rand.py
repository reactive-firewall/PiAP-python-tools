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


try:
	from ..pku import utils as utils
except Exception:
	try:
		import pku.utils as utils
	except Exception:
		raise ImportError("Error Importing remediation")


RAND_CHARS = [
	"""a""", """b""", """c""", """d""", """e""", """f""", """g""", """h""",
	"""i""", """j""", """k""", """l""", """m""", """n""", """o""", """p""",
	"""q""", """r""", """s""", """t""", """u""", """v""", """w""", """x""",
	"""y""", """z""", """1""", """2""", """3""", """4""", """5""", """6""",
	"""7""", """8""", """9""", """0""", """!""", """@""", """#""", """$""",
	"""%""", """^""", """&""", """*""", """(""", """)""", """_""", """-""",
	"""+""", """=""", """<""", """>""", """,""", """.""", """?""", """/""",
	"""'""", """;""", """[""", """]""", """{""", """}""", """|""", """~""",
	"""\"""", """ """
]
"""Posible Chars for randChar (which is not so random, as it is very qwerty based)"""


@remediation.error_handling
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


@remediation.error_handling
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
		return None


@remediation.error_handling
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
		return None


@remediation.error_handling
def randInt(count=None, min=0, max=512):
	"""wrapper for int(os.urandom())"""
	if min is None:
		min = 0
	if max is None:
		max = 512
	if count is None or count < 0:
		x_count = 32
	else:
		x_count = count
	try:
		if x_count == 1:
			try:
				import six
				if six.PY2:
					return (int(utils.extractInt(str(os.urandom(20))), 10) + min) % max
				else:
					return (int.from_bytes(os.urandom(1), sys.byteorder) + min) % max
			except Exception:
				return (int(utils.extractInt(str(os.urandom(20))), 10) + min) % max
		else:
			theResult = []
			for someInt in range(x_count):
				theResult.append((randInt(1) + min) % max)
			return theResult
	except Exception as err:
		print(str(u'FAILED DURRING RAND. ABORT.'))
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		err = None
		del err
		return None


@remediation.error_handling
def randBool(count=None):
	"""wrapper for str(os.urandom())"""
	if count is None or count < 0:
		x_count = 1
	else:
		x_count = (count % 2)
	try:
		return (bool(((randInt(x_count) % 2) == 0)) is True)
	except Exception as err:
		print(str(u'FAILED DURRING RAND. ABORT.'))
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		err = None
		del err
		return None


@remediation.error_handling
def randChar(count=None):
	"""wrapper for str(os.urandom())"""
	if count is None or count < 0:
		x_count = 1
	else:
		x_count = int(count)
	try:
		theRandomResult = str("")
		for char_x in range(x_count):
			char_rand_seed = str(RAND_CHARS[randInt(1, 0, len(RAND_CHARS))])
			while str(char_rand_seed).isalnum() is False:
				char_rand_seed = RAND_CHARS[randInt(1, 0, len(RAND_CHARS))]
			theRandomResult = str("{}{}").format(theRandomResult, str(char_rand_seed))
		return theRandomResult
	except Exception as err:
		print(str(u'FAILED DURRING RANDCHAR. ABORT.'))
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		err = None
		del err
	return None


@remediation.bug_handling
def main(argv=None):
	args = parseArgs(argv)
	if args.count is None:
		return 2
	else:
		print(str(rand(args.count)))
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

