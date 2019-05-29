#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Pocket PiAP
# ......................................................................
# Copyright (c) 2017-2019, Kendrick Walls
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


# try:
# 	from . import config as config
# except Exception:
# 	import config as config


try:
	import os
	import sys
	import argparse
	import re
	import fnmatch
	import os.path
	import functools
	for someModule in [os, sys, argparse, re, fnmatch, os.path, functools]:
		if someModule.__name__ is None:
			raise ImportError(str("OMG! we could not import {}. ABORT. ABORT.").format(someModule))
except Exception as err:
	raise ImportError(err)
	exit(3)


try:
	if 'piaplib' not in sys.modules:
		import piaplib as piaplib
	else:
		piaplib = sys.modules['piaplib']
except Exception:
	raise ImportError("PiAPLib failed to import.")


try:
	if str("piaplib.book.logs.logs") not in sys.modules:
		from piaplib.book.logs import logs as logs
	else:
		logs = sys.modules[str("piaplib.book.logs.logs")]
except Exception:
	try:
		import piaplib.book.logs.logs as logs
	except Exception as err:
		raise ImportError(err, "Error Importing piaplib.book.logs.logs")


try:
	if 'piaplib.pku.remediation' not in sys.modules:
		from . import remediation as remediation
	else:
		remediation = sys.modules['piaplib.pku.remediation']
except Exception:
	try:
		import remediation as remediation
	except Exception:
		raise ImportError("Error Importing remediation")


try:
	if (sys.version_info >= (3, 2)):
		from builtins import str

		class unicode(str):
			pass

except Exception:
	raise ImportError("Error Importing utils")


__prog__ = str("""piaplib.pku.utils""")
"""The name of this program is piaplib.pku.utils"""


@remediation.error_passing
def getCodeTextModeForPY():
	"""returns replace for python and surrogateescape for python3"""
	theResult = str("replace")
	try:
		if (sys.version_info >= (3, 2)):
			theResult = str("surrogateescape")
		else:
			theResult = str("replace")
	finally:
		return theResult


@remediation.error_passing
def trylog(*args, **kwargs):
	"""wrapper for try/catch around piaplib.book.log.log()"""
	try:
		logs.log(*args, **kwargs)
	except Exception as logError:
		if logError:
			logError = None
			del(logError)


@remediation.error_handling
def logOrPrint(*args, **kwargs):
	"""wrapper for try/catch around piaplib.book.log.log()"""
	try:
		logs.log(*args, **kwargs)
	except Exception as logError:
		if args[0]:
			print(str(args[0]))
		logError = None
		del(logError)


@remediation.error_handling
def literal_code(raw_input=None):
	"""A simple attempt at validating raw python unicode. Always expect CWE-20.
		param raw_input - the tainted given input.
		Returns:
			byte string / unicode - the literal code if possible to represent,
			None - otherwise
	"""
	try:
		if isinstance(raw_input, bytes) or isinstance(raw_input, unicode):
			return raw_input.decode("utf-8")
		elif isinstance(raw_input, str):
			return raw_input.encode("utf-8").decode("utf-8")
	except Exception as malformErr:
		trylog("[CWE-20] Possible malformed string attack occurred.", "info")
		malformErr = None
		del(malformErr)
	return None


@remediation.error_handling
def literal_str(raw_input=None):
	"""A simple attempt at validating utf-8 encoding. Always expect CWE-20.
		param raw_input - the tainted string given as input.
		Returns:
			String - the literal string if possible to represent,
			None - otherwise
	"""
	try:
		if isinstance(raw_input, bytes) or isinstance(raw_input, unicode):
			return raw_input.decode("utf-8", getCodeTextModeForPY())
		elif isinstance(raw_input, str):
			return raw_input.encode("utf-8").decode("utf-8", getCodeTextModeForPY())
		else:
			raise UnicodeDecodeError("CWE-135 Malformed Raw String")
	except Exception as malformErr:
		trylog(str("[CWE-20] Possible malformed string attack occurred."), "info")
		malformErr = None
		del(malformErr)
	return None


def parametrized(dec):
	"""parametrized wrapper"""
	@functools.wraps(dec)
	def layer(*args, **kwargs):
		@functools.wraps(dec)
		def repl(f):
			return dec(f, *args, **kwargs)
		return repl
	return layer


def memoize(func):
	"""memoize wrapper"""
	cache = func.cache = {}

	@functools.wraps(func)
	def memoized_func(*args, **kwargs):
		try:
			key = str(str(args) + str(kwargs))
			if key not in cache.keys():
				cache[key] = func(*args, **kwargs)
			return cache[key]
		except Exception as memoErr:
			logOrPrint(
				str("[CWE-233] Possible malformed argument attack occurred. Skipping cache."),
				"Warning"
			)
			memoErr = None
			del(memoErr)
			return func(*args, **kwargs)

	return memoized_func


@remediation.error_handling
@memoize
def extractRegexPattern(theInput_Str, theInputPattern):
	"""
	Extracts the given regex patern.
	:Param theInput_Str: - a String to extract from.
	:Param theInputPattern: - the pattern to extract
	"""
	sourceStr = literal_str(theInput_Str)
	prog = re.compile(theInputPattern)
	theList = prog.findall(sourceStr)
	return theList


@remediation.error_handling
@memoize
def compactSpace(theInput_Str):
	"""Try to remove the spaces from the input string."""
	sourceStr = literal_str(theInput_Str)
	theList = re.sub(r' +', str(""" """), sourceStr)
	return theList


@memoize
def splitDottedKeyPath(fullkey):
	"""splits off the last dotted notation chunck from the first."""
	kp = {}
	if fullkey is None:
		kp[0] = str(None)
	if str(""".""") not in str(fullkey):
		kp[0] = str(fullkey)
	else:
		kp = str(fullkey).rsplit(""".""", 1)
	return kp


def metaImport(module_named_x):
	"""Forces a meta-import
		Idea from:
		https://stackoverflow.com/questions/8718885/import-module-from-string-variable/28639730
		"""
	try:
		# because we want to import using a variable, do it this way
		module_obj = __import__(module_named_x)
		# create a global object containging our module
		globals()[module_named_x] = module_obj
	except ImportError as impErr:
		trylog(str("missing python module: {}").format(str(module_named_x)), "Debug")
		impErr = None
		del impErr


@remediation.error_handling
@memoize
def getRootFofOS():
	"""returns the root system file path, hopefully."""
	if sys.platform.startswith("Win"):
		return str("C:\\")  # pragma: no cover
	else:
		return str("""/""")


def find_files(directory, pattern):
	"""idea from: https://stackoverflow.com/a/2186673"""
	for root, dirs, files in os.walk(directory):
		for basename in files:
			if fnmatch.fnmatch(basename, pattern):
				filename = os.path.join(root, basename)
				yield filename


def find_dirs(directory, pattern):
	"""idea from: https://stackoverflow.com/a/2186673"""
	for root, dirs, files in os.walk(directory):
		for dirname in dirs:
			if fnmatch.fnmatch(dirname, pattern):
				filename = os.path.join(root, dirname)
				yield filename


@remediation.error_handling
@memoize
def search_files(pattern):
	"""searches for the given pattern"""
	theResult = []
	for search_path in sys.path:
		for searches in find_dirs(search_path, pattern):
			if searches not in theResult:
				theResult.append(searches)
	return theResult


@remediation.error_handling
@memoize
def getpkuPath():
	"""returns the likly paths for piaplib.pku.
		idea from:
		https://stackoverflow.com/questions/10043485/python-import-every-module-from-a-folder
	"""
	theResult = str("")
	if str("""pku""") not in str(os.path.abspath(os.curdir)):
		if str("""piaplib""") not in str(os.path.abspath(os.curdir)):
			theResult = search_files("pku")[0]
		else:
			theResult = os.path.abspath(os.path.join(os.path.abspath(os.curdir), "pku"))
	else:
		theResult = str(os.path.abspath(os.curdir))
	return theResult


@remediation.error_handling
def superMetaImport():
	"""Forces a SUPER meta-import
		Idea from:
		https://stackoverflow.com/questions/10043485/python-import-every-module-from-a-folder
		"""
	try:
		for name in os.listdir(getpkuPath()):
			modulename = None
			if name.endswith(".py") and not name.startswith("_"):
				# strip the extension
				modulename = name[:-3]
				# set the module name in the current global name space:
				globals()[modulename] = __import__(str("piaplib.pku.{}").format(modulename))
	except ImportError as err:
		raise remediation.PiAPError(msg="Super Meta Import failed!", cause=err)


def getFunctionListDict(someModuleHandle):
	"""Generates a locals() like dict for the given module.
		Idea from:
		https://stackoverflow.com/questions/139180/how-to-list-all-functions-in-a-python-module
	"""
	import types
	metaImport(someModuleHandle)
	mod = sys.modules.get(someModuleHandle)
	flst = [getattr(mod, a) for a in dir(mod) if isinstance(getattr(mod, a), types.FunctionType)]
	listOfFunctions = dict({})
	for someFunc in flst:
		listOfFunctions[str(someFunc.__name__)] = someFunc
	return listOfFunctions


def getHandle(handler):
	"""gets the function handle (name) for a given function"""
	handle = getANYHandle(handler)
	if locals() is not None and handle is None:
		local_search = locals().copy()
		for someFunc in local_search.keys():
			if handler == local_search[someFunc]:
				handle = someFunc
	for theFunc in globals().copy().keys():
		if handler == globals()[theFunc]:
			handle = theFunc
	if handle is None:
		raise NotImplementedError(
			str("[CWE-758] Function {} not implemented").format(repr(handler))
		)
	return handle


@remediation.error_handling
def getANYHandle(handler):
	"""gets the function handle (name) for a given function if able otherwise returns none"""
	handle = None
	superMetaImport()
	for mod in sys.modules.keys():
		try:
			if str(mod).startswith("piaplib."):
				check_group = getFunctionListDict(mod)
				check_prekey = str(mod)
				for someFunc in check_group:
					if handler == check_group[someFunc]:
						handle = str("{}.{}").format(str(check_prekey), str(someFunc))
		except BaseException as err:
			err = None
			del err
	return handle


def getHandler(handle):
	possibles = globals().copy()
	possibles.update(locals())
	handler = possibles.get(handle)
	if str(".") in str(handle) and isinstance(handler, type(None)):
		best_guess = getFunctionListDict(str(splitDottedKeyPath(handle)[0]))
		handler = best_guess.get(str(splitDottedKeyPath(handle)[1]))
	if isinstance(handler, type(None)):
		raise NotImplementedError(
			str("[CWE-758] Function with name {} not implemented").format(str(handle))
		)
	return handler


@remediation.error_handling
@memoize
def extractMACAddr(theInputStr):
	"""Extract the MAC addresses from a string."""
	theResult = []
	theResult = extractRegexPattern(
		theInputStr,
		"""(?:(?:[[:print:]]*){0,1}(?P<Mac>(?:(?:[0-9a-fA-F]{1,2}[:]{1}){5}""" +
		"""(?:[0-9a-fA-F]{1,2}){1}){1})+(?:[[:print:]]*){0,1})+"""
	)
	return theResult


@remediation.error_handling
@memoize
def extractInts(theInputStr):
	"""Extract the ints from a string."""
	theResult = extractRegexPattern(theInputStr, """(\d+)+""")
	return theResult


@remediation.error_handling
@memoize
def extractInt(theInputStr):
	"""Extract an int from a string."""
	theResult = extractInts(theInputStr)
	return theResult[0]


@remediation.error_handling
@memoize
def extractIfaceNames(theInputStr):
	"""Extracts the expected iface names."""
	return extractRegexPattern(
		theInputStr,
		"""(?:(?:[[:print:]]*){0,1}""" +
		"""(?P<iface_name>[br|mon|usb|lan|vlan|wan|wla|eth|enp0s|lo|en]{2,5}[n]?[0-9]+){1}""" +
		"""(?:[[:print:]]*){0,1})+"""
	)


@remediation.error_handling
@memoize
def extractTTYs(theInputStr):
	"""Extract the TTYs from a string."""
	theResult = []
	theResult = extractRegexPattern(
		theInputStr,
		"""(?:(?:[[:print:]]*){0,1}(?P<TTYs>(?:(?:pts|tty|console|ptty)""" +
		"""{1}[/]?[0-9]+){1})+(?:[[:print:]]*){0,1})+"""
	)
	return theResult


@remediation.error_handling
@memoize
def extractIPv4(theInputStr):
	"""Extract the Ipv4 addresses from a string. Simple x.x.x.x matching, no checks."""
	theResult = []
	theResult = extractRegexPattern(
		theInputStr,
		"""(?:(?:(?:^|[^0-9]{1}){1}(?P<IP>(?:(?:[12]{1}[0-9]{1}[0-9]{1}|[1-9]{1}[0-9]{1}|""" +
		"""[0-9]{1}){1}[.]{1}){3}(?:[12]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9]{1}){1}){1}""" +
		"""(?:[^0-9.]?|$){1}){1})"""
	)
	return theResult


@remediation.error_handling
@memoize
def extractIPAddr(theInputStr):
	"""Extract the Ipv4 addresses from a string. Simple x.x.x.x matching, no checks."""
	theResult = []
	theResult = extractRegexPattern(
		theInputStr,
		"""(?:(?:(?:^|[^0-9]{1}){1}(?P<IP>(?:(?:[12]{1}[0-9]{1}[0-9]{1}|[1-9]{1}[0-9]{1}|""" +
		"""[0-9]{1}){1}[.]{1}){3}(?:[12]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9]{1}){1}){1}""" +
		"""(?:[/]{1}(?:[^0-9.]?|$){1})?){1})"""
	)
	return theResult


@remediation.error_handling
@memoize
def isLineForMatch(someLine=None, toMatch=None):
	"""Determins if a raw output line is for a matching string"""
	return ((toMatch is None) or (literal_str(
		someLine
	).startswith(literal_str(
		toMatch
	)) is True))


@remediation.warning_handling
@memoize
def compactList(unsortedList, intern_func=None):
	"""
	Compacts Lists
	Adapted from some now forgoten forum about flattening arrays, and sorting.
	Cleaned up to be Pep8 compatible.
	"""
	if intern_func is None:
		def intern_func(x):
			return x
	seen = {}
	result = []
	for item in unsortedList:
		marker = intern_func(item)
		if marker in seen:
			continue
		seen[marker] = 1
		result.append(item)
	return result


@remediation.error_handling
def xstr(some_str=None):
	"""
	buffers strings for comparison.
	use for exact matches like thus
		if xstr(test) in xstr(ref):
	"""
	try:
		return str("_x_" + literal_str(some_str) + "_x_")
	except Exception:
		return None


@remediation.error_handling
@memoize
def isWhiteListed(someString=None, whitelist=[]):
	"""Determins if a raw input string is an exact string in the whitelist."""
	for validString in [xstr(x) for x in compactList(whitelist)]:
		if xstr(someString) in validString:
			return True
	return False


""" Argument Parsing """


@remediation.error_passing
def _handleVerbosityArgs(argParser, default=False):
	"""utility function to handle the verbosity flags for the given argument parser."""
	if ((argParser is None) or (not isinstance(argParser, argparse.ArgumentParser))):
		raise argparse.ArgumentError("argParser must be of type argparse.ArgumentParser")
	the_action = argParser.add_mutually_exclusive_group(required=False)
	the_action.add_argument(
		'-v', '--verbose',
		dest='verbose_mode', default=False,
		action='store_true', help='Enable verbose mode.'
	)
	the_action.add_argument(
		'-q', '--quiet',
		dest='verbose_mode', default=False,
		action='store_false', help='Disable the given interface.'
	)
	return argParser


@remediation.error_passing
def _handleVersionArgs(argParser):
	"""utility function to handle the verbosity flags for the given argument parser."""
	if ((argParser is None) or (not isinstance(argParser, argparse.ArgumentParser))):
		raise argparse.ArgumentError("argParser must be of type argparse.ArgumentParser")
	argParser.add_argument(
		'-V',
		'--version',
		action='version',
		version=str(
			"%(prog)s {}"
		).format(str(piaplib.__version__))
	)
	return argParser


""" I/O and Files """


@remediation.error_passing
def canAddExtension(somefile, extension):
	"""Ensures the given extension can even be used."""
	return (((somefile is None) or (extension is None)) is False)


@remediation.error_passing
def checkExtension(somefile, extension):
	"""Ensures the given extension can be added."""
	theResult = False
	if canAddExtension(somefile, extension) is not True:
		theResult = True
	elif (len(str(somefile)) > len(extension)):
		offset = (-1 * len(extension))
		if (extension in str(somefile)[offset:]) and (str(".") in str(somefile)):
			theResult = True
	return theResult


@remediation.error_passing
def addExtension(somefile, extension):
	"""Ensures the given extension is used."""
	theResult = None
	if checkExtension(somefile, extension):
		theResult = somefile
	else:
		theResult = str("{filename}.{sufix}").format(filename=somefile, sufix=extension)
	return theResult


@remediation.error_handling
def xisfile(somefile):
	"""tests the given file is available for reading."""
	if (somefile is None):
		return False
	if os.path.isabs(somefile) and os.path.isfile(somefile):
		return os.access(somefile, os.F_OK ^ os.R_OK)
	return os.path.isfile(os.path.abspath(somefile))


@remediation.error_handling
def xisdir(somedir):
	"""tests the given directory is available for use."""
	if (somedir is None):
		return False
	if os.path.isabs(somedir) and os.path.isdir(somedir):
		return os.access(somedir, os.X_OK ^ os.F_OK ^ os.R_OK)
	return os.path.isdir(os.path.abspath(somedir))


@remediation.error_handling
def ensureDir(somedir):
	"""Ensures the given directory is available for use."""
	if somedir is None:
		return False
	if (xisdir(somedir)):
		return True
	if os.path.isabs(somedir) and (os.path.islink(somedir) or os.path.ismount(somedir)):
		return True
	else:
		ensureDir(os.path.dirname(os.path.abspath(somedir)))
		oldmask = os.umask(2)
		os.mkdir(os.path.abspath(somedir))
		os.umask(oldmask)
		return os.access(somedir, os.X_OK ^ os.F_OK ^ os.R_OK)


@remediation.error_passing
def _check_for_read(file, mode):
	"""checks if can read a file ; used before opening"""
	if xstr("r+") in xstr(mode):
		if not xisfile(file):
			trylog(
				str("[CWE-73] File expected, but not found. Redacted filename."),
				"Info"
			)
			file = None
	return file


@remediation.error_passing
def _check_for_write(file, mode):
	"""checks if can read a file ; used before opening"""
	if xstr("w+") in xstr(mode):
		if not xisfile(file):
			if not xisdir(os.path.dirname(os.path.abspath(file))):
				trylog(
					str("[CWE-73] Redacted filename."),
					"Info"
				)
				file = None
	return file


@remediation.error_passing
def _open(file, mode='r+', buffering=-1, encoding=None):
	""" cross-python open function """
	if encoding is None:
		encoding = str("""utf-8""")
	try:
		if (sys.version_info < (3, 2)):
			import io
			return io.open(file, mode, buffering, encoding)
		return open(file, mode, buffering, encoding)
	except Exception:
		import io
		return io.open(file, mode, buffering, encoding)
	raise AssertionError("File could not be opened")


@remediation.error_passing
def open_func(file, mode='r+', buffering=-1, encoding=None):
	""" cross-python open function """
	file = _check_for_read(file, mode)
	if file is None:
		raise AssertionError("File could not be opened")
	if encoding is None:
		encoding = str("""utf-8""")
	return _open(file, mode, buffering, encoding)
	raise AssertionError("File could not be opened")


@remediation.error_passing
def write_func(someFile, the_data=None):
	""" cross-python write function """
	if (someFile is None) or (the_data is None):
		return None
	try:
		if (sys.version_info < (3, 2)):
			return someFile.write(literal_code(the_data))
		return someFile.write(the_data)
	except Exception:
		return someFile.write(literal_code(the_data))


@remediation.error_handling
def readFile(somefile):
	"""Reads the raw contents of a file."""
	read_data = None
	theReadPath = str(somefile)
	try:
		with open_func(file=theReadPath, mode=u'r+', encoding="""utf-8""") as f:
			read_data = f.read()
		f.close()
		trylog(str(str("read file {}").format(theReadPath)), "Debug")
	except AssertionError:
		read_data = None
	return read_data


@remediation.error_handling
def writeFile(somefile, somedata):
	"""Writes the raw contents of a file."""
	theWritePath = _check_for_write(somefile, u'w+')
	f = None
	theResult = False
	try:
		with open_func(file=theWritePath, mode=u'w+', encoding="""utf-8""") as f:
			write_func(f, somedata)
		theResult = True
	except OSError as nonerr:
		trylog(str(type(nonerr)), "Warning")
		theResult = False
	except Exception as write_err:
		theResult = False
		logOrPrint(str("Write Failed on file {}").format(theWritePath), "debug")
		write_err = piaplib.pku.remediation.error_breakpoint(error=write_err, context=writeFile)
		del write_err
	finally:
		if f:
			f.close()
	if theResult:
		trylog(str("wrote to file {}").format(str(theWritePath)), "Debug")
	return theResult


@remediation.error_handling
def appendFile(somefile, somedata):
	"""Apends to the raw contents of a file."""
	theWritePath = _check_for_write(somefile, u'w+')
	f = None
	theResult = False
	try:
		with open_func(theWritePath, mode=u'a', encoding="""utf-8""") as f:
			write_func(f, somedata)
			write_func(f, os.linesep)
		theResult = True
	except OSError:
		theResult = False
	except Exception as write_err:
		theResult = False
		trylog(str("Write Failed on file {}").format(theWritePath), "Debug")
		write_err = piaplib.pku.remediation.error_breakpoint(error=write_err, context=appendFile)
		del write_err
	finally:
		if f:
			f.close()
	if theResult:
		logOrPrint(str("wrote to file {}").format(theWritePath), str("Debug"))
	return theResult


def getUserAgent():
	"""returns the non-descript mozilla/5.0 (Linux) - PLACEHOLDER - need to randomize this."""
	return str("""mozilla/5.0 (Linux)""")


@remediation.error_passing
def urlretrieve(url, filename):
	""" cross-python urlretrive function """
	try:
		if (sys.version_info < (3, 4)):
			return _python2urlretrieve(url, filename)
		else:
			import requests
			piaplib_headers = {'DNT': '1', 'Connection': 'close', 'user-agent': getUserAgent()}
			r = requests.get(url, headers=piaplib_headers)
			if r is None:
				raise AssertionError("URL could not be opened - ERROR")
			if (r.status_code is not None) and (r.status_code >= 200) and (r.status_code < 400):
				r.encoding = "utf-8"
				return writeFile(filename, r.content)
	except Exception:
		theurl = url
		thefile = filename
		return _python2urlretrieve(theurl, thefile)
	raise AssertionError("URL could not be opened - BUG")


@remediation.error_passing
def _python2urlretrieve(url, filename):
	""" python2 url function. DO NOT CALL DIRECTLY. """
	import warnings
	with warnings.catch_warnings():
		warnings.filterwarnings("ignore", category=DeprecationWarning)
		import urllib
		try:
			tempfile = urllib.FancyURLopener()
			tempfile.addheader('DNT', '1')
			tempfile.addheader('Connection', 'close')
			tempfile.addheader('user-agent', getUserAgent())
			return tempfile.retrieve(url, filename)
		except Exception:
			import urllib.request
			import ssl
			sslContext = None
			try:
				sslContext = ssl.create_default_context(ssl.PROTOCOL_TLSv1_2)
			except Exception:
				sslContext = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
			try:
				return urllib.request.urlretrieve(url, filename, context=sslContext)
			except TypeError:
				return urllib.request.urlretrieve(url, filename)
	raise AssertionError("URL could not be opened securely - UNSUPPORTED")


@remediation.error_handling
def getFileResource(someURL, outFile):
	"""Downloads a file from the given URL."""
	try:
		urlretrieve(url=someURL, filename=outFile)
	except Exception as err:
		logs.log(str("Failed to fetched file {}").format(str(someURL)), "Debug")
		remediation.error_breakpoint(error=err, contex=getFileResource)
		return False
	try:
		logs.log(str("fetched file {}").format(someURL), "Debug")
	except Exception:
		pass
	return True


@remediation.error_handling
def cleanFileResource(theFile):
	"""cleans up a downloaded given file."""
	theResult = False
	try:
		os.remove(str(theFile))
		theResult = True
	except OSError:
		theResult = False
	except Exception:
		logs.log(str("Error: Failed to remove file"), "Warning")
		theResult = False
	try:
		if theResult:
			logs.log(str("purged file {}").format(theFile), "debug")
	except Exception:
		pass
	return theResult


@remediation.error_handling
def moveFileResource(theSrc, theDest):
	"""cleans up a downloaded given file."""
	theResult = False
	try:
		os.rename(str(theSrc), str(theDest))
		theResult = True
	except OSError:
		theResult = False
	except Exception:
		logs.log(str("Error: Failed to rename file"), "Warning")
		theResult = False
	try:
		if theResult:
			logs.log(str("Moved file {} to {}").format(theSrc, theDest), "debug")
	except Exception:
		pass
	return theResult


@remediation.bug_handling
def main(argv=None):
	"""The Main Event makes no sense to utils."""
	raise NotImplementedError("[CWE-758] CRITICAL - PKU Uitls main() not implemented. yet?")
	exit(3)


if __name__ in u'__main__':
	try:
		if (sys.argv is not None and (sys.argv is not []) and (len(sys.argv) > 1)):
			exit(main(sys.argv[1:]))
		else:
			exit(main(["--help"]))
	except Exception:
		raise ImportError("Error running main")
	exit(0)

