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


# SEE NOTE ON Backend HOOKS BELOW
# Currently backends are NOT part of PiAP in anyway and may be subject to thier own licences.


try:
	import os
	import sys
	import argparse
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
	from . import rand as rand
except Exception:
	import rand as rand


try:
	from ..pku import remediation as remediation
except Exception:
	import pku.remediation as remediation

try:
	from remediation import PiAPError as PiAPError
except Exception:
	try:
		from piaplib.pku.remediation import PiAPError as PiAPError
	except Exception:
		raise ImportError("Error Importing PiAPError")

try:
	from ..pku import utils as utils
except Exception:
	import pku.utils as utils


__prog__ = """piaplib.keyring.clearify"""
"""The name of this PiAPLib tool is clearify"""


DEFAULT_BETA_FILE_PATH = str("""/var/opt/PiAP/.beta_W1AsYRUDzyZx""")
"""THIS IS A PLACEHOLDER. WILL move this to a config file."""


KEY_BLOCK_SIZE = 44
"""KEY_BLOCK_SIZE = len(base64.standard_b64encode(bytes(os.urandom(32)))) = 44"""


EOFNEWLINE = str(os.linesep)
"""newline to use"""


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


@remediation.error_passing
@utils.memoize
def getAlgoForOS():
	"""returns cbc for darwin and ctr for linux"""
	import sys
	if sys.platform.startswith("linux"):
		return str("-aes-256-ctr")
	else:
		return str("-aes-256-cbc")


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
def makeKeystoreFile(theKey=str(str(rand.randPW(16)).replace("%", "%%")), somePath=None):
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
	"""Serializes the given cleartext.
		param ciphertext - str the encrypted data.
		param keyStore - str the path to this file with the key.
	"""
	if keyStore is None:
		keyStore = getKeyFilePath()
	if hasBackendCommand():
		args = [
			getBackendCommand(),
			str("enc"),
			str("-e"),
			getAlgoForOS(),
			str("-a"),
			str("-A"),
			str("-salt"),
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
		(ciphertext, stderrdata) = p1.communicate(utils.literal_str(message))
		if isinstance(ciphertext, bytes):
			ciphertext = ciphertext.decode(u'utf-8')
		# ciphertext = str(ciphertext).replace(str("\\n"), str(""))
		return ciphertext
	else:
		raise NotImplementedError("No Implemented Backend - BUG")


@remediation.error_handling
def unpackFromRest(ciphertext=None, keyStore=None):
	"""Deserializes the given ciphertext.
		param ciphertext - str the encrypted data.
		param keyStore - str the path to this file with the key.
	"""
	if keyStore is None:
		keyStore = getKeyFilePath()
	if hasBackendCommand():
		args = [
			getBackendCommand(),
			str("enc"),
			str("-d"),
			getAlgoForOS(),
			str("-a"),
			str("-A"),
			str("-salt"),
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
			cleartext = cleartext.decode(u'utf-8')
		# cleartext = str(cleartext).replace(str("\\n"), str(""))
		return str(cleartext)
	else:
		raise NotImplementedError("No Implemented Backend - BUG")


@remediation.error_handling
def unpackFromFile(somefile, keyStore=None):
	"""Reads the raw encrypted file and decrypts it."""
	read_data = None
	try:
		someFilePath = utils.addExtension(somefile, str('enc'))
		with utils.open_func(someFilePath, mode=u'r', encoding=u'utf-8') as enc_data_file:
			read_enc_data = enc_data_file.read()
			read_data = unpackFromRest(read_enc_data, keyStore)
	except Exception as clearerr:
		read_data = None
		baton = PiAPError(clearerr, str("Failed to load or deycrypt file."))
		clearerr = None
		del clearerr
		raise baton
	return read_data


@remediation.error_handling
def packToFile(somefile, data, keyStore=None):
	"""Writes the raw encrypted file."""
	if data is None:
		return False
	if somefile is None:
		return False
	did_write = False
	try:
		someFilePath = utils.literal_code(utils.addExtension(str(somefile), str("enc")))
		if someFilePath is not None:
			encData = packForRest(data, keyStore)
			with utils.open_func(file=someFilePath, mode=u'wb+') as enc_data_file:
				utils.write_func(enc_data_file, utils.literal_str(encData).encode(u'utf-8'))
			del(encData)
		did_write = True
	except Exception as clearerr:
		raise remediation.PiAPError(clearerr, str("Failed to write or encrypt file."))
		del(clearerr)
		did_write = False
	return did_write


WEAK_ACTIONS = {u'pack': packForRest, u'unpack': unpackFromRest}
""" The Pocket bag Unit actions.
	pack - save/pack/pickle functions.
	unpack - load/unpack/unpickle functions.
	"""


@remediation.error_handling
def parseArgs(arguments=None):
	theArgs = argparse.Namespace()
	salt_rand = str(rand.randPW(16)).replace("%", "%%")
	key_rand = str(rand.randPW(16)).replace("%", "%%")
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
				str(
					"The cryptographic Salt String. A unique salt. Like {thevalue}"
				).format(thevalue=salt_rand)
			)
		)
		parser.add_argument(
			'-K',
			'--key',
			dest='key',
			required=False,
			type=str,
			help=str(
				str(
					"The cryptographic Key String. A unique secret. Like {thevalue}"
				).format(thevalue=key_rand)
			)
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
		print(str("FAILED DURRING CLEARIFY.. ABORT."))
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		print(str(key_rand))
		print(str(salt_rand))
		err = None
		del err
		theArgs = argparse.Namespace()
	return theArgs


@remediation.bug_handling
def main(argv=None):
	"""The main event"""
	args = parseArgs(argv)
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
		if __name__ in u'__main__':
			print(output)
		else:
			return output
	except Exception as err:
		print(str("FAILED DURRING CLEARIFY. ABORT."))
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		err = None
		del err
		output = None
		del output
	return 0


if __name__ in u'__main__':
	exitcode = 0
	try:
		import sys
		exitcode = main(sys.argv[1:])
	except Exception as err:
		print(str("MAIN FAILED DURRING CLEARIFY. ABORT."))
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		del err
		exit(255)
	finally:
		exit(exitcode)


