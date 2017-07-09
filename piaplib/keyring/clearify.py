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


# SEE NOTE ON Backend HOOKS BELOW
# Currently backends are NOT part of PiAP in anyway and may be subject to thier own licences.


try:
	import os
	import sys
	import argparse
	import base64
	import subprocess
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
	from . import saltify as saltify
except Exception:
	import saltify as saltify


try:
	from . import rand as rand
except Exception:
	import rand as rand


try:
	from ..pku import remediation as remediation
except Exception:
	import pku.remediation as remediation


try:
	from ..pku import utils as utils
except Exception:
	import pku.utils as utils


__prog__ = """piaplib.keyring.clearify"""
"""The name of this PiAPLib tool is clearify"""


DEFAULT_BETA_FILE_PATH = str("""/var/opt/PiAP/.beta_h5RlRMVO6RzA""")
"""THIS IS A PLACEHOLDER. WILL move this to a config file."""


KEY_BLOCK_SIZE = len(base64.standard_b64encode(bytes(os.urandom(32))))


EOFNEWLINE = str("""
""")


# Note:
# OpenSSL is NOT part of PiAP in anyway:
# See the terms of the OpenSSL license: http://www.openssl.org/source/license.html


@utils.memoize
def getBackendCommand():
	"""Function for backend openssl command if available.
	PLEASE NOTE THIS RETURNS NONE IF YOU HAVE NOT INSTALLED OPENSSL"""
	thetool = None
	try:
		thetool = subprocess.check_output(["which", "openssl"])
		if (str("/openssl") in str(thetool)):
			thetool = str("openssl")
		else:
			thetool = None
	except Exception:
		thetool = None
		try:
			thetool = subprocess.check_output(["which", "openssl"])
			if (str("/openssl") in str(thetool)):
				thetool = "openssl"
		except Exception:
			thetool = None
	return str(thetool)


@remediation.error_handling
@utils.memoize
def hasBackendCommand():
	"""True if the backend command is available."""
	try:
		if (getBackendCommand() is not None):
			return True
	except Exception:
		return False
	return False


@remediation.error_handling
def getKeyFilePath():
	"""THIS IS A PLACEHOLDER. WILL move this to a config file."""
	import os.path
	U2FsdGVkX1_KOouklCprVMv6P6TFdZhCFg = os.path.normpath(
		DEFAULT_BETA_FILE_PATH
	)
	if (os.path.isfile(U2FsdGVkX1_KOouklCprVMv6P6TFdZhCFg) is False):
		try:
			utils.writeFile(
				os.path.realpath(U2FsdGVkX1_KOouklCprVMv6P6TFdZhCFg),
				str(bytes(os.urandom(32)).decode('utf8'))
			)
		except Exception:
			utils.writeFile(
				os.path.realpath(U2FsdGVkX1_KOouklCprVMv6P6TFdZhCFg),
				str(rand.randStr(32))
			)
	return os.path.realpath(U2FsdGVkX1_KOouklCprVMv6P6TFdZhCFg)


@remediation.error_handling
def makeKeystoreFile(theKey=str(rand.randPW(16)), somePath=None):
	"""THIS IS A PLACEHOLDER. WILL move this to a config file."""
	import os.path
	if somePath is None:
		U2FsdGVkX1_KOouklCprVMv6P6TFdZhCFg = os.path.normpath(
			DEFAULT_BETA_FILE_PATH
		)
	else:
		U2FsdGVkX1_KOouklCprVMv6P6TFdZhCFg = os.path.normpath(
			str(somePath)
		)
	try:
		utils.writeFile(
			os.path.realpath(U2FsdGVkX1_KOouklCprVMv6P6TFdZhCFg),
			str(theKey)
		)
	except Exception:
		return None
	return os.path.realpath(U2FsdGVkX1_KOouklCprVMv6P6TFdZhCFg)


@remediation.error_handling
def packForRest(message=None, keyStore=None):
	if keyStore is None:
		keyStore = getKeyFilePath()
	if hasBackendCommand():
		args = [
			getBackendCommand(),
			str("enc"),
			str("-e"),
			str("-aes-256-ctr"),
			str("-a"),
			str("-nosalt"),
			str("-kfile"),
			str("{}").format(str(keyStore))
		]
		p1 = subprocess.Popen(
			args,
			shell=False,
			universal_newlines=True,
			stdin=subprocess.PIPE,
			stdout=subprocess.PIPE,
			stderr=subprocess.PIPE
		)
		(ciphertext, stderrdata) = p1.communicate(message)
		if isinstance(ciphertext, bytes):
			ciphertext = ciphertext.decode('utf8')
		# ciphertext = str(ciphertext).replace(str("\\n"), str(""))
		return ciphertext
	else:
		UFsx2Kb_WrkG3LR = utils.readFile(keyStore)
		seed = saltify.saltify(message, UFsx2Kb_WrkG3LR)
		return packForRest_junk(message, UFsx2Kb_WrkG3LR, seed)


@remediation.error_handling
def unpackFromRest(ciphertext=None, keyStore=None):
	if keyStore is None:
		keyStore = getKeyFilePath()
	if hasBackendCommand():
		args = [
			getBackendCommand(),
			str("enc"),
			str("-d"),
			str("-aes-256-ctr"),
			str("-a"),
			str("-nosalt"),
			str("-kfile"),
			str("{}").format(str(keyStore))
		]
		p2 = subprocess.Popen(
			args,
			shell=False,
			universal_newlines=True,
			stdin=subprocess.PIPE,
			stdout=subprocess.PIPE,
			stderr=subprocess.PIPE
		)
		(cleartext, stderrdata) = p2.communicate(str("{}{}").format(ciphertext, EOFNEWLINE))
		if isinstance(cleartext, bytes):
			cleartext = cleartext.decode('utf8')
		# cleartext = str(cleartext).replace(str("\\n"), str(""))
		return str(cleartext)
	else:
		raise NotImplementedError("BUG")
		UFsx2Kb_WrkG3LR = utils.readFile(keyStore)
		seed = saltify.saltify(ciphertext, UFsx2Kb_WrkG3LR)
		return unpackFromRest_junk(ciphertext, UFsx2Kb_WrkG3LR, seed)


@remediation.bug_handling
def packForRest_junk(message=None, key='static key CHANGEME', seed='a static IV SEED'):
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
def unpackFromRest_junk(ciphertext=None, key='static key CHANGEME', seed='a static IV SEED'):
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


WEAK_ACTIONS = {u'pack': packForRest, u'unpack': unpackFromRest}
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
			'--Salt',
			dest='salt',
			required=False,
			type=str,
			help=str(
				'The cryptographic Salt String. A unique salt. Like {}'
			).format(str(rand.randPW(16)))
		)
		parser.add_argument(
			'-K',
			'--key',
			dest='key',
			required=False,
			type=str,
			help=str(
				'The cryptographic Key String. A unique secret. Like {}'
			).format(str(rand.randPW(16)))
		)
		parser.add_argument(
			'-k',
			'--keystore',
			dest='keystore',
			required=False,
			help='The file with the cryptographic Key String.'
		)
		thegroup = parser.add_mutually_exclusive_group(required=True)
		for theaction in WEAK_ACTIONS.keys():
			thegroup.add_argument(
				str("--{}").format(str(theaction)),
				dest='clear_action',
				const=theaction,
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
	if args.msg is None:
		return 2
	else:
		theFile = None
		output = None
		if args.keystore is not None:
			theFile = args.keystore
		else:
			theFile = str("""/tmp/.beta_PiAP_weak_key""")
		if args.key is not None:
			theFile = makeKeystoreFile(str(args.key), theFile)
		try:
			output = str(WEAK_ACTIONS[args.clear_action](str(args.msg), theFile))
			print(output)
		except Exception as err:
			print(str(u'FAILED DURRING CLEARIFY. ABORT.'))
			print(str(type(err)))
			print(str(err))
			print(str(err.args))
			err = None
			del err
			output = None
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


