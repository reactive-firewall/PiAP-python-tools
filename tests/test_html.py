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

import unittest


class BasicHTMLTestSuite(unittest.TestCase):
	"""Basic functional test cases."""

	def test_absolute_truth_and_meaning(self):
		"""Insanitty Test."""
		assert True

	def test_syntax(self):
		"""Test case importing code."""
		theResult = False
		try:
			from .context import piaplib
			if piaplib.__name__ is None:
				theResult = False
			from piaplib import pocket
			if pocket.__name__ is None:
				theResult = False
			theResult = True
		except Exception as impErr:
			print(str(type(impErr)))
			print(str(impErr))
			theResult = False
		assert theResult

	def test_actual_depends(self):
		"""Test case importing depends."""
		theResult = True
		try:
			import sys
			if sys.__name__ is None:
				theResult = False
			import os
			if os.__name__ is None:
				theResult = False
			import argparse
			if argparse.__name__ is None:
				theResult = False
			import subprocess
			if subprocess.__name__ is None:
				theResult = False
		except Exception as impErr:
			print(str(""))
			print(str(type(impErr)))
			print(str(impErr))
			print(str((impErr.args)))
			print(str(""))
			theResult = False
		assert theResult

	def test_c_html_special_chars(self):
		"""Test case for piaplib.* --help."""
		theResult = False
		try:
			from .. import html_generator as html_generator
		except Exception:
			import lint.html_generator as html_generator
		if html_generator.__name__ is None:
			theResult = False
		else:
			try:
				for fuzz_test in [str("""\""""), str("""\'"""), str("""\\""")]:
					if (html_generatorhas_special_html_chars(utils.xstr(fuzz_test)):
						theResult = True
					else:
						theResult = False
			except Exception as err:
				print(str(""))
				print(str(type(err)))
				print(str(err))
				print(str((err.args)))
				print(str(""))
				othererr = None
				del othererr
				theResult = False
		assert theResult

	def test_d_html_gen_tr(self):
		"""Test case for piaplib.* --help."""
		theResult = False
		try:
			from .. import html_generator as html_generator
		except Exception:
			import lint.html_generator as html_generator
		if html_generator.__name__ is None:
			theResult = False
		else:
			try:
				for fuzz_test in [str("""\""""), str("""\'"""), str("""\\""")]:
				output_gen = html_generator.gen_html_tr(content=None, id=None, name=None):
						theResult = True
					else:
						theResult = False
			except Exception as err:
				print(str(""))
				print(str(type(err)))
				print(str(err))
				print(str((err.args)))
				print(str(""))
				othererr = None
				del othererr
				theResult = False
		assert theResult


if __name__ == '__main__':
	unittest.main()
