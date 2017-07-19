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

	def test_c_html_special_chars(self):  # noqa
		"""Test case for piaplib.lint.html_generator.has_special_html_chars."""
		theResult = False
		try:
			from lint import html_generator as html_generator
		except Exception:
			import lint.html_generator as html_generator
		if html_generator.__name__ is None:
			theResult = False
		try:
			from pku import utils as utils
		except Exception:
			import pku.utils as utils
		if html_generator.__name__ is None:
			theResult = False
		else:
			try:
				for fuzz_test in [str("""\""""), str("""\'"""), str("""\\""")]:
					if (html_generator.has_special_html_chars(utils.xstr(fuzz_test))):
						theResult = True
					else:
						theResult = False
			except Exception as err:
				print(str(""))
				print(str(type(err)))
				print(str(err))
				print(str((err.args)))
				print(str(""))
				err = None
				del err
				theResult = False
		assert theResult

	def test_c_html_special_chars_none(self):  # noqa
		"""Test case for piaplib.lint.html_generator.has_special_html_chars(None)."""
		theResult = True
		try:
			from lint import html_generator as html_generator
		except Exception:
			import lint.html_generator as html_generator
		if html_generator.__name__ is None:
			theResult = False
		else:
			try:
				self.assertTrue(html_generator.has_special_html_chars(None))
			except Exception as err:
				print(str(""))
				print(str(type(err)))
				print(str(err))
				print(str((err.args)))
				print(str(""))
				err = None
				del err
				theResult = False
		assert theResult

	def test_d_html_gen_tr(self):
		"""Test case for gen TR."""
		theResult = False
		try:
			from lint import html_generator as html_generator
		except Exception:
			import lint.html_generator as html_generator
		if html_generator.__name__ is None:
			theResult = False
		else:
			try:
				output_gen = html_generator.gen_html_tr(
					content="this is a test",
					id="test_id",
					name="test_tr"
				)
				if (str("<tr") in output_gen and str("</tr>") in output_gen):
						theResult = True
				else:
					theResult = False
			except Exception as err:
				print(str(""))
				print(str(type(err)))
				print(str(err))
				print(str((err.args)))
				print(str(""))
				err = None
				del err
				theResult = False
		assert theResult

	def test_d_html_gen_tr_no_id(self):
		"""Test case for gen TR."""
		theResult = False
		try:
			from lint import html_generator as html_generator
		except Exception:
			import lint.html_generator as html_generator
		if html_generator.__name__ is None:
			theResult = False
		else:
			try:
				output_gen = html_generator.gen_html_tr(
					content="this is a test",
					id=None,
					name="test_tr"
				)
				if (str("<tr") in output_gen and str("</tr>") in output_gen):
						theResult = True
				else:
					theResult = False
			except Exception as err:
				print(str(""))
				print(str(type(err)))
				print(str(err))
				print(str((err.args)))
				print(str(""))
				err = None
				del err
				theResult = False
		assert theResult

	def test_d_html_gen_tr_no_name(self):
		"""Test case for gen TR."""
		theResult = False
		try:
			from lint import html_generator as html_generator
		except Exception:
			import lint.html_generator as html_generator
		if html_generator.__name__ is None:
			theResult = False
		else:
			try:
				output_gen = html_generator.gen_html_tr(
					content="this is a test"
				)
				if (str("<tr") in output_gen and str("</tr>") in output_gen):
						theResult = True
				else:
					theResult = False
			except Exception as err:
				print(str(""))
				print(str(type(err)))
				print(str(err))
				print(str((err.args)))
				print(str(""))
				err = None
				del err
				theResult = False
		assert theResult

	def test_d_html_gen_td(self):
		"""Test case for gen TD"""
		theResult = False
		try:
			from lint import html_generator as html_generator
		except Exception:
			import lint.html_generator as html_generator
		if html_generator.__name__ is None:
			theResult = False
		else:
			try:
				output_gen = html_generator.gen_html_td(
					content="this is a test",
					id="test_id",
					name="test_td"
				)
				if (str("<td") in output_gen and str("</td>") in output_gen):
					theResult = True
				else:
					theResult = False
			except Exception as err:
				print(str(""))
				print(str(type(err)))
				print(str(err))
				print(str((err.args)))
				print(str(""))
				err = None
				del err
				theResult = False
		assert theResult

	def test_d_html_gen_td_no_id(self):
		"""Test case for gen TD with no id."""
		theResult = False
		try:
			from lint import html_generator as html_generator
		except Exception:
			import lint.html_generator as html_generator
		if html_generator.__name__ is None:
			theResult = False
		else:
			try:
				output_gen = html_generator.gen_html_td(
					content="this is a test",
					id=None,
					name="test_td"
				)
				if (str("<td") in output_gen and str("</td>") in output_gen):
						theResult = True
				else:
					theResult = False
			except Exception as err:
				print(str(""))
				print(str(type(err)))
				print(str(err))
				print(str((err.args)))
				print(str(""))
				err = None
				del err
				theResult = False
		assert theResult

	def test_d_html_gen_td_no_name(self):
		"""Test case for gen TD with no name or ID."""
		theResult = False
		try:
			from lint import html_generator as html_generator
		except Exception:
			import lint.html_generator as html_generator
		if html_generator.__name__ is None:
			theResult = False
		else:
			try:
				output_gen = html_generator.gen_html_td(
					content="this is a test"
				)
				if (str("<td") in output_gen and str("</td>") in output_gen):
						theResult = True
				else:
					theResult = False
			except Exception as err:
				print(str(""))
				print(str(type(err)))
				print(str(err))
				print(str((err.args)))
				print(str(""))
				err = None
				del err
				theResult = False
		assert theResult

	def test_d_html_gen_ul(self):
		"""Test case for gen UL"""
		theResult = False
		try:
			from lint import html_generator as html_generator
		except Exception:
			import lint.html_generator as html_generator
		if html_generator.__name__ is None:
			theResult = False
		else:
			try:
				output_gen = html_generator.gen_html_ul(
					["this is a test"],
					id="test_id",
					name="test_ul"
				)
				if (str("<ul") in output_gen and str("</ul>") in output_gen):
					theResult = True
				else:
					theResult = False
			except Exception as err:
				print(str(""))
				print(str(type(err)))
				print(str(err))
				print(str((err.args)))
				print(str(""))
				err = None
				del err
				theResult = False
		assert theResult

	def test_d_html_gen_ul_no_id(self):
		"""Test case for gen UL without ID."""
		theResult = False
		try:
			from lint import html_generator as html_generator
		except Exception:
			import lint.html_generator as html_generator
		if html_generator.__name__ is None:
			theResult = False
		else:
			try:
				output_gen = html_generator.gen_html_ul(
					["this is a test"],
					None,
					"test_ul"
				)
				if (str("<ul") in output_gen and str("</ul>") in output_gen):
					theResult = True
				else:
					theResult = False
			except Exception as err:
				print(str(""))
				print(str(type(err)))
				print(str(err))
				print(str((err.args)))
				print(str(""))
				err = None
				del err
				theResult = False
		assert theResult

	def test_d_html_gen_ul_no_name(self):
		"""Test case for gen UL without name"""
		theResult = False
		try:
			from lint import html_generator as html_generator
		except Exception:
			import lint.html_generator as html_generator
		if html_generator.__name__ is None:
			theResult = False
		else:
			try:
				output_gen = html_generator.gen_html_ul(
					["this is a test"]
				)
				if (str("<ul") in output_gen and str("</ul>") in output_gen):
					theResult = True
				else:
					theResult = False
			except Exception as err:
				print(str(""))
				print(str(type(err)))
				print(str(err))
				print(str((err.args)))
				print(str(""))
				err = None
				del err
				theResult = False
		assert theResult

	def test_d_html_gen_ul_no_value(self):
		"""Test case for gen UL without name"""
		theResult = True
		try:
			from lint import html_generator as html_generator
		except Exception:
			import lint.html_generator as html_generator
		if html_generator.__name__ is None:
			theResult = False
		else:
			try:
				output_gen = html_generator.gen_html_ul(
					[None]
				)
				if (str("<ul") in output_gen and str("</ul>") in output_gen):
					theResult = True
				else:
					theResult = False
			except Exception as err:
				print(str(""))
				print(str(type(err)))
				print(str(err))
				print(str((err.args)))
				print(str(""))
				err = None
				del err
				theResult = False
		assert theResult

	def test_d_html_gen_lable(self):
		"""Test case for gen lable"""
		theResult = False
		try:
			from lint import html_generator as html_generator
		except Exception:
			import lint.html_generator as html_generator
		if html_generator.__name__ is None:
			theResult = False
		else:
			try:
				for role_label in range(5):
					output_gen = html_generator.gen_html_label(
						"this is a test",
						html_generator.HTML_LABEL_ROLES[role_label],
						"test_id",
						"test_lable"
					)
					if (str("<span") in output_gen and str("</span>") in output_gen):
						if (str(html_generator.HTML_LABEL_ROLES[role_label]) in output_gen):
							theResult = True
						else:
							theResult = False
					else:
						theResult = False
			except Exception as err:
				print(str(""))
				print(str(type(err)))
				print(str(err))
				print(str((err.args)))
				print(str(""))
				err = None
				del err
				theResult = False
		assert theResult

	def test_e_html_gen_li(self):
		"""Test case for gen Li."""
		theResult = False
		try:
			from lint import html_generator as html_generator
		except Exception:
			import lint.html_generator as html_generator
		if html_generator.__name__ is None:
			theResult = False
		else:
			try:
				output_gen = html_generator.gen_html_li(
					["this is a test"],
					"test_id",
					"test_li"
				)
				if (str("<li") in output_gen and str("</li>") in output_gen):
					theResult = True
				else:
					theResult = False
			except Exception as err:
				print(str(""))
				print(str(type(err)))
				print(str(err))
				print(str((err.args)))
				print(str(""))
				err = None
				del err
				theResult = False
		assert theResult

	def test_e_html_gen_li_no_id(self):
		"""Test case for gen Li without ID."""
		theResult = False
		try:
			from lint import html_generator as html_generator
		except Exception:
			import lint.html_generator as html_generator
		if html_generator.__name__ is None:
			theResult = False
		else:
			try:
				output_gen = html_generator.gen_html_li(
					["this is a test"],
					None,
					"test_li"
				)
				if (str("<li") in output_gen and str("</li>") in output_gen):
					theResult = True
				else:
					theResult = False
			except Exception as err:
				print(str(""))
				print(str(type(err)))
				print(str(err))
				print(str((err.args)))
				print(str(""))
				err = None
				del err
				theResult = False
		assert theResult


if __name__ == '__main__':
	unittest.main()
