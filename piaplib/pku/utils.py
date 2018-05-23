#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Pocket PiAP
# ......................................................................
# Copyright (c) 2017-2018, Kendrick Walls
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
	if os.__name__ is None:
		raise ImportError("OMG! we could not import os. We're like in the matrix! ABORT. ABORT.")
except Exception as err:
	raise ImportError(err)
	exit(3)

try:
	import sys
	if sys.__name__ is None:
		raise ImportError("OMG! we could not import sys. We're like in the matrix! ABORT. ABORT.")
except Exception as err:
	raise ImportError(err)
	exit(3)

try:
	import argparse
	if argparse.__name__ is None:
		raise ImportError("OMG! we could not import argparse. ABORT.")
except Exception as err:
	raise ImportError(err)
	exit(3)

try:
	import re
	if re.__name__ is None:
		raise ImportError("OMG! we could not import regex. ABORT.")
except Exception as err:
	raise ImportError(err)
	exit(3)

try:
	import piaplib as piaplib
except Exception:
	from . import piaplib as piaplib

try:
	from piaplib.book.logs import logs as logs
except Exception:
	try:
		from book.logs import logs as logs
	except Exception:
		try:
			from piaplib.book.logs import logs as logs
		except Exception:
			raise ImportError("Error Importing logs")


try:
	from . import remediation as remediation
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
		logs.log("[CWE-20] Possible malformed string attack occurred.", "info")
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
		if isinstance(raw_input, bytes):
			return raw_input.decode("utf-8")
		elif isinstance(raw_input, str) or isinstance(raw_input, unicode):
			return raw_input.encode("utf-8").decode("utf-8")
		else:
			raise UnicodeDecodeError("Malformed Raw String")
	except Exception as malformErr:
		logs.log(str("[CWE-20] Possible malformed string attack occurred."), "info")
		malformErr = None
		del(malformErr)
	return None


def memoize(func):
	"""memoize wrapper"""
	cache = func.cache = {}
	import functools

	@functools.wraps(func)
	def memoized_func(*args, **kwargs):
		try:
			key = str(str(args) + str(kwargs))
			if key not in cache.keys():
				cache[key] = func(*args, **kwargs)
			return cache[key]
		except Exception as memoErr:
			logs.log(
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
	Param theInput_Str - a String to extract from.
	Param theInputPattern - the pattern to extract
	"""
	sourceStr = literal_str(theInput_Str)
	prog = re.compile(theInputPattern)
	theList = prog.findall(sourceStr)
	return theList


@remediation.error_handling
@memoize
def compactSpace(theInput_Str):
	"""Try to remove the spaces from the input string."""
	import re
	sourceStr = literal_str(theInput_Str)
	theList = re.sub(r' +', str(""" """), sourceStr)
	return theList


@remediation.error_handling
@memoize
def extractMACAddr(theInputStr):
	"""Extract the MAC addresses from a string."""
	theResult = []
	theResult = extractRegexPattern(
		theInputStr,
		"""(?:(?:[[:print:]]*){0,1}(?P<Mac>(?:(?:[0-9a-fA-F]{1,2}[\:]{1}){5}""" +
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
		"""{1}[\/]?[0-9]+){1})+(?:[[:print:]]*){0,1})+"""
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
		"""[0-9]{1}){1}[\.]{1}){3}(?:[12]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9]{1}){1}){1}""" +
		"""(?:[^0-9\.]?|$){1}){1})"""
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
		"""[0-9]{1}){1}[\.]{1}){3}(?:[12]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9]{1}){1}){1}""" +
		"""(?:[/]{1}(?:[^0-9\.]?|$){1})?){1})"""
	)
	return theResult


@remediation.error_handling
@memoize
def isLineForMatch(someLine=None, toMatch=None):
	"""Determins if a raw output line is for a matching string"""
	if ((toMatch is None) or (literal_str(
		someLine
	).startswith(literal_str(
		toMatch
	)) is True)):
		return True
	else:
		return False


@remediation.warning_handling
@memoize
def compactList(list, intern_func=None):
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
	for item in list:
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
		raise argparse.InvalidArgumentError("argParser must be of type argparse.ArgumentParser")
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
		raise argparse.InvalidArgumentError("argParser must be of type argparse.ArgumentParser")
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
def addExtension(somefile, extension):
	"""Ensures the given extension is used."""
	if (somefile is None):
		return None
	if (extension is None):
		return somefile
	if (len(str(somefile)) > len(extension)):
		offset = (-1 * len(extension))
		if (extension in str(somefile)[offset:]) and (str(".") in str(somefile)):
			return somefile
		else:
			return str("{}.{}").format(somefile, extension)
	else:
		return str("{}.{}").format(somefile, extension)


@remediation.error_handling
def xisfile(somefile):
	"""tests the given file is available for reading."""
	if (somefile is None):
		return False
	import os.path
	if os.path.isabs(somefile) and os.path.isfile(somefile):
		return os.access(somefile, os.F_OK ^ os.R_OK)
	else:
		return os.path.isfile(os.path.abspath(somefile))


@remediation.error_handling
def xisdir(somedir):
	"""tests the given directory is available for use."""
	if (somedir is None):
		return False
	import os.path
	if os.path.isabs(somedir) and os.path.isdir(somedir):
		return os.access(somedir, os.X_OK ^ os.F_OK ^ os.R_OK)
	else:
		return os.path.isdir(os.path.abspath(somedir))


@remediation.error_handling
def ensureDir(somedir):
	"""Ensures the given directory is available for use."""
	if somedir is None:
		return False
	if (xisdir(somedir)):
		return True
	import os.path
	if os.path.isabs(somedir) and (os.path.islink(somedir) or os.path.ismount(somedir)):
		return True
	else:
		ensureDir(os.path.dirname(os.path.abspath(somedir)))
		oldmask = os.umask(2)
		os.mkdir(os.path.abspath(somedir))
		os.umask(oldmask)
		return os.access(somedir, os.X_OK ^ os.F_OK ^ os.R_OK)


@remediation.error_passing
def open_func(file, mode='r', buffering=-1, encoding=None):
	""" cross-python open function """
	if xstr("r") in xstr(mode):
		if not xisfile(file):
			logs.log(str("[CWE-73] File expected, but not found. Redacted filename."), "Info")
			file = None
	try:
		import six
		if six.PY2:
			import io
			return io.open(file, mode, buffering, encoding)
		else:
			return open(file, mode, buffering, encoding)
	except Exception:
		import io
		return io.open(file, mode, buffering, encoding)
	raise AssertionError("File could not be opened")


@remediation.error_passing
def write_func(someFile, the_data=None):
	""" cross-python write function """
	try:
		import six
		if six.PY2:
			return someFile.write(literal_code(the_data))
		else:
			return someFile.write(the_data)
	except Exception:
		return someFile.write(literal_code(the_data))


@remediation.error_handling
def readFile(somefile):
	"""Reads the raw contents of a file."""
	read_data = None
	theReadPath = str(somefile)
	with open_func(theReadPath, u'r', encoding=u'utf-8') as f:
		read_data = f.read()
	f.close()
	try:
		logs.log(str(str("read file {}").format(theReadPath)), "Debug")
	except Exception:
		pass
	return read_data


@remediation.error_handling
def writeFile(somefile, somedata):
	"""Writes the raw contents of a file."""
	theWritePath = str(somefile)
	f = None
	theResult = False
	try:
		with open_func(file=theWritePath, mode=u'w+', encoding=u'utf-8') as f:
			write_func(f, somedata)
		theResult = True
	except IOError as ioErr:
		logs.log(str(type(ioErr)), "Warning")
		theResult = False
	except OSError as nonerr:
		logs.log(str(type(nonerr)), "Warning")
		theResult = False
	except Exception as err:
		logs.log(str("Write Failed on file {}").format(theWritePath), "Warning")
		logs.log(str(type(err)), "Warning")
		logs.log(str(err), "Warning")
		logs.log(str((err.args)), "Warning")
		err = None
		del err
		theResult = False
	finally:
		if f:
			f.close()
	try:
		logs.log(str("wrote to file {}").format(str(theWritePath)), "Debug")
	except Exception as err:
		print(str("logging error"))
		print(str(err))
		print(str(type(err)))
		print(str((err.args)))
	return theResult


@remediation.error_handling
def appendFile(somefile, somedata):
	"""Apends to the raw contents of a file."""
	theWritePath = str(somefile)
	f = None
	theResult = False
	try:
		with open_func(theWritePath, mode=u'a', encoding=u'utf-8') as f:
			write_func(f, somedata)
			write_func(f, os.linesep)
		theResult = True
	except IOError:
		theResult = False
	except OSError:
		theResult = False
	except Exception as err:
		logs.log(str("Write Failed on file {}").format(theWritePath), "Debug")
		logs.log(str(type(err)), "Warning")
		logs.log(str(err), "Warning")
		logs.log(str((err.args)), "Warning")
		err = None
		del err
		theResult = False
	finally:
		if f:
			f.close()
	try:
		logs.log(str("wrote to file {}").format(theWritePath), str("Debug"))
	except Exception:
		pass
	return theResult


def getUserAgent():
	"""returns the non-descript mozilla/5.0 (Linux) - PLACEHOLDER - need to randomize this."""
	return str("""mozilla/5.0 (Linux)""")


@remediation.error_passing
def urlretrieve(url, filename):
	""" cross-python urlretrive function """
	try:
		import six
		if six.PY2:
			return _python2urlretrieve(url, filename)
		else:
			import requests
			piaplib_headers = {'DNT': '1', 'Connection': 'close', 'user-agent': getUserAgent()}
			r = requests.get(url, headers=piaplib_headers)
			if r is None:
				raise AssertionError("URL could not be opened - BUG")
			if r.status_code is not None:
				r.encoding = "utf-8"
				return writeFile(filename, r.content)
	except Exception as err:
		remediation.error_breakpoint(err)
		return _python2urlretrieve(url, filename)
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
		except Exception:
			import urllib.request
			return urllib.request.urlretrieve(url, filename)
		return tempfile.retrieve(url, filename)
	raise AssertionError("URL could not be opened - BUG")


@remediation.error_handling
def getFileResource(someURL, outFile):
	"""Downloads a file from the given URL."""
	try:
		urlretrieve(url=someURL, filename=outFile)
	except Exception as err:
		remediation.error_breakpoint(err)
		logs.log(str("Failed to fetched file {}").format(someURL), "Debug")
		return False
	try:
		logs.log(str("fetched file {}").format(someURL), "Debug")
	except Exception:
		pass
	return True


@remediation.error_handling
def cleanFileResource(theFile):
	"""cleans up a downloaded given file."""
	import os
	theResult = False
	try:
		os.remove(str(theFile))
		theResult = True
	except IOError:
		theResult = False
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


@remediation.bug_handling
def main(argv=None):
	"""The Main Event makes no sense to utils."""
	raise NotImplementedError("CRITICAL - PKU Uitls main() not implemented. yet?")
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

