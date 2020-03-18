#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Pocket PiAP
# ......................................................................
# Copyright (c) 2017-2020, Kendrick Walls
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
# Currently backends are NOT part of PiAP in anyway and may be subject to their own licences.


"""CAVEAT: REMEMBER PYTHON HAS NO SECURE MEMORY.
	If there is a weakness in PiAP data io it is in memory.
	PYTHON STRINGS ARE IMUTABLE, THUS ONCE IN CLEAR, ALWAYS IN CLEAR."""


try:
	import os
	import os.path
	import sys
	import argparse
	import subprocess
	sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
except Exception:
	raise NotImplementedError("[CWE-758] We could not import the os. We're like in the matrix!")


try:
	if str("piaplib.keyring.rand") not in sys.modules:
		from piaplib.keyring import rand as rand
	else:
		rand = sys.modules[str("piaplib.keyring.rand")]
except Exception:
	try:
		import piaplib.keyring.rand as rand
	except Exception as err:
		raise ImportError(err, "Error Importing piaplib.keyring.rand")


try:
	if str("piaplib.pku.remediation") not in sys.modules:
		from piaplib.pku import remediation as remediation
	else:
		remediation = sys.modules[str("piaplib.pku.remediation")]
except Exception:
	try:
		import piaplib.pku.remediation as remediation
	except Exception as err:
		raise ImportError(err, "Error Importing remediation")


try:
	from remediation import PiAPError as PiAPError
except Exception:
	try:
		from piaplib.pku.remediation import PiAPError as PiAPError
	except Exception:
		raise ImportError("Error Importing PiAPError")


try:
	if str("piaplib.pku.utils") not in sys.modules:
		from piaplib.pku import utils as utils
	else:
		utils = sys.modules[str("piaplib.pku.utils")]
except Exception:
	try:
		import piaplib.pku.utils as utils
	except Exception as err:
		raise ImportError(err, "Error Importing piaplib.pku.utils")


__prog__ = """piaplib.keyring.clarify"""
"""The name of this PiAPLib tool is clarify"""


__description__ = """Handles PiAP keyring tools."""
"""The description of this PiAPLib tool is 'Handles PiAP keyring tools.'"""


__epilog__ = """PiAP Controller for cryptographic tools."""
"""...PiAP Controller for cryptographic tools."""


DEFAULT_BETA_FILE_PATH = str("""/opt/PiAP/.beta_W1AsYRUDzyZx""")
"""THIS IS A PLACEHOLDER. WILL move this to a config file."""


# KEY_BLOCK_SIZE = 44
# """KEY_BLOCK_SIZE = len(base64.standard_b64encode(bytes(os.urandom(32)))) = 44"""


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
	theArgs = ["""which""", """openssl"""]
	try:
		thetool = subprocess.check_output(theArgs)
		if (str("/openssl") in str(thetool)):
			thetool = str("openssl")
		else:
			thetool = None
	except Exception:
		thetool = None
		try:
			thetool = subprocess.check_output(theArgs)
			if (str("/openssl") in str(thetool)):
				thetool = "openssl"
		except Exception:
			thetool = None
	return str(thetool)


@remediation.error_handling
@utils.memoize
def hasBackendCommand():
	"""True if the backend command is available."""
	hasbackend = False
	try:
		if (getBackendCommand() is not None):
			hasbackend = True
	except Exception:
		hasbackend = False
	finally:
		return hasbackend


@utils.memoize
def getBackendVersionString():
	"""Function for backend openssl command if available.
		PLEASE NOTE THIS RETURNS NONE IF YOU HAVE NOT INSTALLED OPENSSL"""
	if hasBackendCommand():
		args = [
			getBackendCommand(),
			str("version")
		]
		versiontext = None
		stderrdata = None
		p0 = subprocess.Popen(
			args,
			shell=False,
			universal_newlines=True,
			stdin=subprocess.PIPE,
			stdout=subprocess.PIPE,
			stderr=subprocess.PIPE,
			close_fds=True
		)
		try:
			(versiontext, stderrdata) = p0.communicate(EOFNEWLINE)
		except Exception:
			p0.kill()
			versiontext = None
		finally:
			p0.wait()
		if stderrdata:  # pragma: no branch
			versiontext = str(stderrdata)
		if isinstance(versiontext, bytes):
			versiontext = versiontext.decode(encoding="""utf-8""", errors=getCTLModeForPY())
		return utils.literal_code(versiontext)
	else:
		raise NotImplementedError("[CWE-758] No Implemented Backend - BUG")


@utils.memoize
def getBackendVersion():
	"""Function for backend openssl command if available.
		PLEASE NOTE THIS RETURNS NONE IF YOU HAVE NOT INSTALLED OPENSSL"""
	if hasBackendCommand():
		versiontxt = str(getBackendVersionString())
		theVersion = utils.extractRegexPattern(versiontxt, """([0-9]+)+""")
		return [int(x) for x in theVersion[:2]]
	else:  # pragma: no branch
		return [0, 0]


@remediation.error_passing
@utils.memoize
def getAlgoForOS():
	"""returns blowfish (old) for darwin and AES-ctr (sane) for linux"""
	theAlgo = None
	if sys.platform.startswith("linux"):
		theAlgo = str("-aes-256-ctr")
	else:
		theAlgo = str("-blowfish")
	return theAlgo


@remediation.error_passing
def getArgsForBackend(decrypt=False):
	"""returns blowfish (old) for darwin and AES-ctr (sane) for linux"""
	theArgs = None
	if hasBackendCommand():
		theArgs = [getBackendCommand(), str("""enc"""), getAlgoForOS()]
		if decrypt is not True:
			theArgs.append(str("""-e"""))
		else:
			theArgs.append(str("""-d"""))
		theArgs.append(str("""-a"""))
		theArgs.append(str("""-A"""))
		theArgs.append(str("""-salt"""))
		if ([1, 1] <= getBackendVersion()) and (sys.platform.startswith("linux")):
			theArgs.append(str("""-pbkdf2"""))
		theArgs.append(str("""-kfile"""))
	return theArgs


@remediation.error_passing
@utils.memoize
def getCTLModeForPY():
	"""returns replace for python and surrogateescape for python3"""
	return utils.getCodeTextModeForPY()


@remediation.error_handling
def getKeyFilePath():
	"""THIS IS A PLACEHOLDER. WILL move this to a config file."""
	U2FsdGVkX1_KOouklCprVMv6P6TFdZhCFg = os.path.normpath(
		DEFAULT_BETA_FILE_PATH
	)
	if not utils.ensureDir(os.path.dirname(os.path.abspath(U2FsdGVkX1_KOouklCprVMv6P6TFdZhCFg))):
		return None
	if (os.path.isfile(U2FsdGVkX1_KOouklCprVMv6P6TFdZhCFg) is False):
		utils.writeFile(
			os.path.realpath(U2FsdGVkX1_KOouklCprVMv6P6TFdZhCFg),
			str(str(rand.randPW(32)).replace("%", "%%"))
		)
	return os.path.realpath(U2FsdGVkX1_KOouklCprVMv6P6TFdZhCFg)


@remediation.error_handling
def makeKeystoreFile(theKey=str(str(rand.randPW(16)).replace("%", "%%")), somePath=None):
	"""THIS IS A PLACEHOLDER. WILL move this to a config file."""
	if somePath is None:
		U2FsdGVkX1_KOouklCprVMv6P6TFdZhCFg = os.path.normpath(
			DEFAULT_BETA_FILE_PATH
		)
	else:
		U2FsdGVkX1_KOouklCprVMv6P6TFdZhCFg = os.path.normpath(
			str(somePath)
		)
	try:
		if theKey is not None:
			utils.ensureDir(os.path.dirname(os.path.realpath(U2FsdGVkX1_KOouklCprVMv6P6TFdZhCFg)))
			utils.writeFile(
				os.path.realpath(U2FsdGVkX1_KOouklCprVMv6P6TFdZhCFg),
				str(theKey)
			)
	except Exception:
		return None
	return os.path.realpath(U2FsdGVkX1_KOouklCprVMv6P6TFdZhCFg)


@remediation.error_handling
def packForRest(message, keyStore=None):
	"""Serializes the given cleartext.
		param ciphertext - str the encrypted data.
		param keyStore - str the path to this file with the key.
	"""
	if message is None:
		return None
	cmdArgs = []
	if keyStore is None:  # pragma: no branch
		keyStore = getKeyFilePath()
	if hasBackendCommand():
		ciphertext = None
		cmdArgs = getArgsForBackend(False)
		cmdArgs.append(str("""{}""").format(str(keyStore)))
		p1 = subprocess.Popen(
			args=cmdArgs,
			shell=False,
			universal_newlines=True,
			stdin=subprocess.PIPE,
			stdout=subprocess.PIPE,
			stderr=subprocess.PIPE,
			close_fds=True
		)
		try:
			(ciphertext, stderrdata) = p1.communicate(input=utils.literal_code(message))
		except Exception:
			p1.kill()
			ciphertext = None
		finally:
			p1.wait()
		if stderrdata:
			ciphertext = str(stderrdata)
		if isinstance(ciphertext, bytes):
			ciphertext = ciphertext.decode(encoding="""utf-8""", errors=getCTLModeForPY())
			# ciphertext = str(ciphertext).replace(str("\\n"), str(""))
		return utils.literal_code(ciphertext)
	else:
		raise NotImplementedError("[CWE-758] No Implemented Backend - BUG")


@remediation.error_handling
def unpackFromRest(ciphertext, keyStore=None):
	"""Deserializes the given ciphertext.
		param ciphertext - str the encrypted data.
		param keyStore - str the path to this file with the key.
	"""
	if ciphertext is None:  # pragma: no branch
		return None
	cmdArgs = []
	if keyStore is None:  # pragma: no branch
		keyStore = getKeyFilePath()
	if hasBackendCommand():
		cmdArgs = getArgsForBackend(True)
		cmdArgs.append(str("""{}""").format(str(keyStore)))
		ciptxtBuffer = str("""{}{}""").format(utils.literal_code(ciphertext), EOFNEWLINE)
		cleartext = None
		stderrdata = None
		p2 = subprocess.Popen(
			args=cmdArgs,
			shell=False,
			universal_newlines=True,
			stdin=subprocess.PIPE,
			stdout=subprocess.PIPE,
			stderr=subprocess.PIPE,
			close_fds=True
		)
		try:
			(cleartext, stderrdata) = p2.communicate(input=utils.literal_code(ciptxtBuffer))
		except Exception:
			p2.kill()
			cleartext = None
		finally:
			p2.wait()
		if stderrdata:
			cleartext = str(stderrdata)
		del(ciptxtBuffer)
		if isinstance(cleartext, bytes):  # pragma: no branch
			cleartext = cleartext.decode(encoding="""utf-8""", errors=getCTLModeForPY())
		return utils.literal_code(cleartext)
	else:
		raise NotImplementedError("[CWE-758] No Implemented Backend - BUG")


@remediation.error_handling
def unpackFromFile(somefile, keyStore=None):
	"""Reads the raw encrypted file and decrypts it."""
	read_data = None
	try:
		someFilePath = utils.literal_code(utils.addExtension(str(somefile), str("enc")))
		read_enc_data = utils.readFile(someFilePath)
		if isinstance(read_enc_data, bytes):  # pragma: no branch
			read_enc_data = read_enc_data.decode(encoding="""utf-8""", errors=getCTLModeForPY())
		read_data = utils.literal_code(unpackFromRest(read_enc_data, keyStore))
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
	if data is None:  # pragma: no branch
		return False
	if somefile is None:  # pragma: no branch
		return False
	did_write = False
	try:
		someFilePath = utils.literal_code(utils.addExtension(str(somefile), str("enc")))
		if someFilePath is not None:
			encData = packForRest(data, keyStore)
			utils.writeFile(
				os.path.abspath(someFilePath),
				utils.literal_code(encData)
			)
			del(encData)
		did_write = True
	except Exception as clearerr:
		did_write = False
		raise remediation.PiAPError(clearerr, str("Failed to write or encrypt file."))
	return did_write


WEAK_ACTIONS = {"""pack""": packForRest, """unpack""": unpackFromRest}
""" The Pocket bag Unit actions.
	pack - save/pack/pickle functions.
	unpack - load/unpack/unpickle functions.
	"""


@remediation.error_handling
def generateParser(calling_parser_group):
	"""Parses the CLI arguments."""
	if calling_parser_group is None:
		parser = argparse.ArgumentParser(
			prog=__prog__,
			description=__description__,
			epilog=__epilog__
		)
	else:
		parser = calling_parser_group.add_parser(
			str(__prog__).split(".")[-1], help=__description__
		)
	salt_rand = str(rand.randPW(24)).replace("%", "%%")
	key_rand = str(rand.randPW(24)).replace("%", "%%")
	parser.add_argument(
		'-m',
		'--msg',
		dest='msg',
		required=True,
		help=str("The Message data. A cleartext or cyphertext message.")
	)
	parser.add_argument(
		'-S',
		'--Salt',
		dest='salt',
		required=False,
		help=str(
			str(
				"The cryptographic Salt String. A unique salt. Like {thevalue}"
			).format(thevalue=salt_rand)
		)
	)
	key_group = parser.add_argument_group()
	key_group.add_argument(
		'-K',
		'--key',
		dest='key',
		required=False,
		help=str(
			str(
				"The cryptographic Key String. A unique secret. Like {thevalue}"
			).format(thevalue=key_rand)
		)
	)
	key_group.add_argument(
		'-k',
		'--keystore',
		dest='keystore',
		required=False,
		help=str("The file with the cryptographic Key String.")
	)
	parser = utils._handleVersionArgs(parser)
	thegroup = parser.add_mutually_exclusive_group(required=True)
	for theaction in sorted(WEAK_ACTIONS.keys()):
		thegroup.add_argument(
			str("--{act}").format(act=str(theaction)),
			dest='clear_action',
			const=theaction,
			action='store_const',
			help=str("The clarify service option.")
		)
	if calling_parser_group is None:
		calling_parser_group = parser
	return calling_parser_group


@remediation.error_handling
def parseArgs(arguments=None):
	"""Parses the CLI arguments."""
	theArgs = argparse.Namespace()
	try:
		parser = generateParser(None)
		theArgs, extra = parser.parse_known_args(arguments)
		del extra
	except Exception as err:
		print(str("FAILED DURING clarify.. ABORT."))
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
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
	if args.keystore is not None:  # pragma: no branch
		theFile = utils.literal_str(args.keystore)
	else:
		theFile = str("""/tmp/.beta_PiAP_weak_key""")
	if args.key is not None:
		theFile = makeKeystoreFile(utils.literal_str(args.key), theFile)
		if theFile is None:
			raise NotImplementedError("[CWE-758] No default keystore - homeless key bug")
	else:
		if not utils.xisfile(theFile):
			raise NotImplementedError("[CWE-758] No default key - empty key bug")
	try:
		output = utils.literal_code(
			WEAK_ACTIONS[args.clear_action](utils.literal_code(args.msg), theFile)
		)
		if __name__ in u'__main__':
			print(output)
		else:
			print(utils.literal_code(output))
		return output
	except Exception as err:
		print(str("FAILED DURING piaplib.keyring.clarify.main() - ABORT."))
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		err = None
		del err
		output = None
		del output
	return 1


if __name__ in u'__main__':
	exitcode = 0
	try:
		exitcode = main(sys.argv[1:])
		if not isinstance(exitcode, type(int(0))):
			exitcode = 0
	except Exception as err:
		print(str("MAIN FAILED DURING piaplib.keyring.clarify.__main__ - ABORT."))
		print(str(type(err)))
		print(str(err))
		print(str(err.args))
		del err
		exit(255)
	finally:
		exit(exitcode)


