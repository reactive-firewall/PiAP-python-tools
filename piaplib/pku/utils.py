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


def literal_code(raw_input=None):
	"""A simple attempt at validating raw python unicode. Always expect CWE-20.
		param raw_input - the tainted given input.
		Returns:
			byte string / unicode - the literal code if posible to represent,
			None - otherwise
	"""
	try:
		if isinstance(raw_input, bytes):
			return raw_input.decode("utf-8")
		elif isinstance(raw_input, str):
			return raw_input.encode("utf-8").decode("utf-8")
	except Exception as malformErr:
		malformErr = None
		del malformErr
		return None
	return None


def literal_str(raw_input=None):
	"""A simple attempt at validating utf-8 encoding. Always expect CWE-20.
		param raw_input - the tainted string given as input.
		Returns:
			String - the literal string if posible to represent,
			None - otherwise
	"""
	try:
		if isinstance(raw_input, bytes):
			return str(raw_input.decode("utf-8"))
		elif isinstance(raw_input, str):
			return str(raw_input.encode("utf-8").decode("utf-8"))
	except Exception as malformErr:
		malformErr = None
		del malformErr
		return None
	return None


def extractRegexPattern(theInput_Str, theInputPattern):
	"""
	Extracts the given regex patern.
	Param theInput_Str - a String to extract from.
	Param theInputPattern - the pattern to extract
	"""
	import re
	sourceStr = literal_str(theInput_Str)
	prog = re.compile(theInputPattern)
	theList = prog.findall(sourceStr)
	return theList


def compactSpace(theInput_Str):
	"""Try to remove the spaces from the input string."""
	import re
	sourceStr = literal_str(theInput_Str)
	theList = re.sub(r' +', u' ', sourceStr)
	return theList


def extractMACAddr(theInputStr):
	"""Extract the MAC addresses from a string."""
	theResult = []
	try:
		theResult = extractRegexPattern(
			theInputStr,
			"""(?:(?:[[:print:]]*){0,1}(?P<Mac>(?:(?:[0-9a-fA-F]{1,2}[\:]{1}){5}""" +
			"""(?:[0-9a-fA-F]{1,2}){1}){1})+(?:[[:print:]]*){0,1})+"""
		)
	except DeprecationWarning:
		theResult = extractRegexPattern(
			theInputStr,
			"""(?:(?:[[:print:]]*){0,1}(?P<Mac>(?:(?:[0-9a-fA-F]{1,2}[\\:]{1}){5}""" +
			"""(?:[0-9a-fA-F]{1,2}){1}){1})+(?:[[:print:]]*){0,1})+"""
		)
	return theResult


def extractIfaceNames(theInputStr):
	"""Extracts the expected iface names."""
	return extractRegexPattern(
		theInputStr,
		"(?:(?:[[:print:]]*){0,1}(?P<iface_name>[abehlstuw]{3}[n]?[0-9]+){1}(?:[[:print:]]*){0,1})+"
	)


def extractTTYs(theInputStr):
	"""Extract the TTYs from a string."""
	theResult = []
	try:
		theResult = extractRegexPattern(
			theInputStr,
			"""(?:(?:[[:print:]]*){0,1}(?P<TTYs>(?:(?:pts|tty|console|ptty)""" +
			"""{1}[\/]?[0-9]+){1})+(?:[[:print:]]*){0,1})+"""
		)
	except DeprecationWarning:
		theResult = extractRegexPattern(
			theInputStr,
			"""(?:(?:[[:print:]]*){0,1}(?P<TTYs>(?:(?:pts|tty|console|ptty)""" +
			"""{1}[\\/]?[0-9]+){1})+(?:[[:print:]]*){0,1})+"""
		)
	return theResult


def extractIPv4(theInputStr):
	"""Extract the Ipv4 addresses from a string. Simple x.x.x.x matching, no checks."""
	theResult = []
	try:
		theResult = extractRegexPattern(
			theInputStr,
			"""(?:(?:(?:^|[^0-9]{1}){1}(?P<IP>(?:(?:[12]{1}[0-9]{1}[0-9]{1}|[1-9]{1}[0-9]{1}|""" +
			"""[0-9]{1}){1}[\.]{1}){3}(?:[12]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9]{1}){1}){1}""" +
			"""(?:[^0-9\.]?|$){1}){1})"""
		)
	except DeprecationWarning:
		theResult = extractRegexPattern(
			theInputStr,
			"""(?:(?:(?:^|[^0-9]{1}){1}(?P<IP>(?:(?:[12]{1}[0-9]{1}[0-9]{1}|[1-9]{1}[0-9]{1}|""" +
			"""[0-9]{1}){1}[\\.]{1}){3}(?:[12]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9]{1}){1}){1}""" +
			"""(?:[^0-9\\.]?|$){1}){1})"""
		)
	return theResult


def extractIPAddr(theInputStr):
	"""Extract the Ipv4 addresses from a string. Simple x.x.x.x matching, no checks."""
	theResult = []
	try:
		theResult = extractRegexPattern(
			theInputStr,
			"""(?:(?:(?:^|[^0-9]{1}){1}(?P<IP>(?:(?:[12]{1}[0-9]{1}[0-9]{1}|[1-9]{1}[0-9]{1}|""" +
			"""[0-9]{1}){1}[\.]{1}){3}(?:[12]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9]{1}){1}){1}""" +
			"""(?:[/]{1}){1}(?:[^0-9\.]?|$){1}){1})"""
		)
	except DeprecationWarning:
		theResult = extractRegexPattern(
			theInputStr,
			"""(?:(?:(?:^|[^0-9]{1}){1}(?P<IP>(?:(?:[12]{1}[0-9]{1}[0-9]{1}|[1-9]{1}[0-9]{1}|""" +
			"""[0-9]{1}){1}[\\.]{1}){3}(?:[12]{1}[0-9]{2}|[1-9]{1}[0-9]{1}|[0-9]{1}){1}){1}""" +
			"""(?:[\\/]{1}){1}(?:[^0-9\\.]?|$){1}){1})"""
		)
	return theResult


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


def compactList(list, intern_func=None):
	"""
	Compacts Lists
	Adapted from some now forgoten form about flattening arrays, and sorting.
	Cleaned up to be Pep8 compatable.
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


""" I/O and Files """


def open_func(file, mode='r', buffering=-1, encoding=None):
	""" cross-python open function """
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


def write_func(someFile, the_data=None):
	""" cross-python open function """
	try:
		import six
		if six.PY2:
			return someFile.write(literal_code(the_data))
		else:
			return someFile.write(the_data)
	except Exception:
		return someFile.write(literal_code(the_data))


def readFile(somefile):
	"""Reads the raw contents of a file."""
	read_data = None
	theReadPath = str(somefile)
	with open_func(theReadPath, u'r', encoding='utf-8') as f:
		read_data = f.read()
	f.close()
	return read_data


def writeFile(somefile, somedata):
	"""Writes the raw contents of a file."""
	theWritePath = str(somefile)
	f = None
	theResult = False
	try:
		with open_func(theWritePath, u'w+', encoding='utf-8') as f:
			write_func(f, somedata)
		theResult = True
	except IOError:
		theResult = False
	finally:
		if f:
			f.close()
	return theResult


def appendFile(somefile, somedata):
	"""Apends to the raw contents of a file."""
	theWritePath = str(somefile)
	f = None
	theResult = False
	try:
		with open_func(theWritePath, u'a', encoding='utf-8') as f:
			write_func(f, somedata)
			write_func(f, os.linesep)
		theResult = True
	except IOError:
		theResult = False
	finally:
		if f:
			f.close()
	return theResult


def getFileList(someURL, outFile):
	"""Downloads a file from the given URL."""
	import urllib
	try:
		tempfile = urllib.FancyURLopener()
	except Exception:
		import urllib.request
		tempfile = urllib.request.FancyURLopener()
	tempfile.retrieve(someURL, outFile)
	return True


def main(argv=None):
	"""The Main Event makes no sense to utils."""
	raise NotImplementedError("CRITICAL - PKU Uitls main() not implemented. yet?")
	exit(3)


if __name__ in u'__main__':
	try:
		import sys
		main(sys.argv[1:])
	except Exception:
		exit(3)


