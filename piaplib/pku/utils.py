#! /usr/bin/env python
# -*- coding: utf-8 -*-


# Pocket PiAP
# 
# Copyright (c) 2017, Kendrick Walls
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
# http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


try:
	from . import config as config
except Exception:
	import config as config


def literal_str(raw_input=None):
	"""A simple attempt at validating utf-8 encoding. Always expect CWE-20."""
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


def test_literal_str():
	"""Tests the literal string functions"""
	theResult = literal_str(b'test') in literal_str(str(u'test')) and literal_str(str(u'test')) in literal_str(b'test')
	return theResult


def main(argv=None):
	"""The Main Event makes no sense to utils."""
	raise NotImplementedError("CRITICAL - PKU Uitls main() not implemented. yet?")
	exit(3)


if __name__ in u'__main__':
	import sys
	main(sys.argv[1:])


