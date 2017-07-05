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
	import os
	import sys
	import argparse
	import base64
	sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
except Exception:
	raise NotImplementedError("OMG! We could not import the os. We're like in the matrix!")
	exit(3)


"""
	CAVEAT:
	REMEMBER PYTHON HAS NO SECURE MEMORY.
	If there is a weakness in PiAP data io it is in memory.
	PYTHON STRINGS ARE IMUTABLE, THUS ONCE IN CLEAR, ALWAYS IN CLEAR.
"""


try:
	from . import rand as rand
except Exception:
	import rand as rand

try:
	from ..pku import remediation as remediation
except Exception:
	import pku.remediation as remediation


__prog__ = """piaplib.keyring.clearify"""
"""The name of this PiAPLib tool is clearify"""


KEY_BLOCK_SIZE = len(base64.standard_b64encode(bytes(os.urandom(32))))


@remediation.bug_handling
def packForRest(message=None, key='static key CHANGEME', seed='This is a static IV SEED'):
	import six
	if six.PY2:
		from Crypto.Cipher import AES
		obj = AES.new(
			str(key.join("0123456789abcdef")).encode('utf8')[:16],
			AES.MODE_CBC,
			str(seed.join("0123456789ABCDEFG")).encode('utf8')[:16]
		)
		pad_text = str(bytes(b'\0' * (16 - (len(message) % 16))).decode('utf8'))
		pad_message = str("{}{}").format(message, pad_text).encode('utf8')
		ciphertext = obj.encrypt(pad_message)
		del(obj)
		return str(base64.standard_b64encode(ciphertext).decode('utf8'))
	else:
		from cryptography.fernet import Fernet
		f = Fernet(base64.urlsafe_b64encode(
			bytes(key.join(str("0123456789abcdefg")).encode('utf8'))[:32]
		)[:KEY_BLOCK_SIZE])
		ciphertext = f.encrypt(message.encode('utf8'))
		return str(ciphertext.decode('utf8'))


@remediation.bug_handling
def unpackFormRest(ciphertext=None, key='static key CHANGEME', seed='This is a static IV SEED'):
	import six
	if six.PY2:
		from Crypto.Cipher import AES
		obj = AES.new(
			str(key.join("0123456789abcdef")).encode('utf8')[:16],
			AES.MODE_CBC,
			str(seed.join("0123456789ABCDEFG")).encode('utf8')[:16]
		)
		cleartext = obj.decrypt(base64.standard_b64decode(ciphertext.encode('utf8')))
		for pad_len in range(16, 0, -1):
			pad_text = str(bytes(b'\0' * (16 - pad_len)).decode('utf8'))
			cleartext_unpad = cleartext.decode('utf8').rstrip(pad_text)
			if (len(cleartext_unpad.encode('utf8')) is len(cleartext)):
				continue
			else:
				cleartext = cleartext_unpad.encode('utf8')
		del(obj)
		return cleartext.decode('utf8')
	else:
		from cryptography.fernet import Fernet
		f = Fernet(base64.urlsafe_b64encode(
			bytes(key.join(str("0123456789abcdefg")).encode('utf8'))[:32]
		)[:KEY_BLOCK_SIZE])
		cleartext = f.decrypt(ciphertext.encode('utf8'))
		return str(cleartext.decode('utf8'))

WEAK_ACTIONS = {u'pack': packForRest, u'unpack': unpackFormRest}
""" The Pocket bag Unit actions.
	pack - save/pack/pickle functions.
	unpack - load/unpack/unpickle functions.
	"""


@remediation.error_handling
def parseArgs(arguments=None):
	theArgs = None
	try:
		parser = argparse.ArgumentParser(
			prog=__prog__,
			description='Handles PiAP keyring tools',
			epilog="PiAP Controller for cryptographic tools."
		)
		parser.add_argument(
			'-m',
			'--msg',
			dest='msg',
			required=True,
			type=str,
			help='The Message data. A cleartext or cyphertext message.'
		)
		parser.add_argument(
			'-S',
			'--seed',
			dest='seed',
			required=True,
			type=str,
			help=str('The initialization vector. A unique IV. Like {}').format(str(rand.randPW(16)))
		)
		parser.add_argument(
			'-K',
			'--key',
			dest='key',
			required=True,
			type=str,
			help=str('The cryptographic Key String. A unique secret. Like {}').format(str(rand.randPW(16)))
		)
		thegroup = parser.add_mutually_exclusive_group(required=True)
		for action in WEAK_ACTIONS.keys():
			thegroup.add_argument(
				str("--{}").format(str(action)),
				dest='clear_action',
				const=action,
				action='store_const',
				help='The clearify service option.'
			)
		theArgs = parser.parse_args(arguments)
	except Exception as err:
		print(str(u'FAILED DURRING CLEARIFY. ABORT.'))
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		err = None
		del err
		theArgs = None
	return theArgs


@remediation.bug_handling
def main(argv=None):
	"""The main event"""
	args = parseArgs(argv)
	if args.msg is None or args.seed is None or args.key is None:
		return 2
	else:
		print(str(WEAK_ACTIONS[args.clear_action](str(args.msg), str(args.key), str(args.seed))))
	return 0


if __name__ in u'__main__':
	exitcode = 0
	try:
		import sys
		exitcode = main(sys.argv[1:])
	except Exception as err:
		print(str(u'MAIN FAILED DURRING CLEARIFY. ABORT.'))
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		del err
		exit(255)
	finally:
		exit(exitcode)

