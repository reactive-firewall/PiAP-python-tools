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


"""
	A collection of utility functions to generate html taglets for php
"""


try:
	import os
	import sys
	sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
	try:
		from .. import utils as utils
	except Exception:
		import pku.utils as utils
	if utils.__name__ is None:
		raise ImportError("Failed to open PKU Utils")
except Exception as importErr:
	print(str(importErr))
	print(str(importErr.args))
	importErr = None
	del importErr
	raise ImportError("Failed to generate HTML5 Pocket Lint")


HTML_LABEL_STATUS = {
	u'OK': u'success',
	u'WARNING': u'warning',
	u'CRITICAL': u'danger',
	u'UNKNOWN': u'disabled',
	u'DEBUG': u'info'
}
"""The basic status mappings to labels"""


HTML_LABEL_ROLES = [
	u'default', HTML_LABEL_STATUS[u'DEBUG'],
	HTML_LABEL_STATUS[u'OK'], HTML_LABEL_STATUS[u'WARNING'],
	HTML_LABEL_STATUS[u'CRITICAL'], HTML_LABEL_STATUS[u'UNKNOWN']
]
"""the types of labels that can be used in html output"""


def has_special_html_chars(raw_str=None):
	"""
	Determines if the string have special html charterers.
	param somestr -- The string to test.
	Returns:
	True -- if the string has special charterers.
	False -- otherwise.
	"""
	try:
		somestr = utils.literal_str(raw_str)
		if somestr is None:
			return True
		badchars = [
			u'\"', u'\'', u'\\', u'%', u'>',
			u'<', u'=', str("""\""""), str("""\'"""), str("""\\"""),
			str("""%"""), str(""">"""), str("""<"""), str("""='""")
		]
		for badchar in badchars:
			if badchar in somestr:
				return True
	except Exception as badinput:
		print(str("Bad html render string input."))
		print(str(type(badinput)))
		badinput = None
		del badinput
		return True
	return False


def gen_html_tag(tag="div", content=None, tagid=None, name=None):
	"""
	Generates a table row html tr taglet.
	param tag -- The type of taglet.
	param content -- The content of the taglet.
	param name -- The optional name of the taglet.
	param tagid -- The optional tagid of the taglet.
	Returns:
	str -- the html string of the taglet.
	"""
	if tag is None or (isinstance(tag, str) is False):
		return content
	if tagid is not None and has_special_html_chars(tagid) is not True:
		if name is not None and has_special_html_chars(name) is not True:
			return str(
				u'<{thetag} name=\"{thename}\" id=\"{theid}\">{thecontent}</{thetag}>'
			).format(
				thetag=utils.literal_str(tag),
				thename=utils.literal_str(name),
				theid=utils.literal_str(tagid),
				thecontent=utils.literal_str(content)
			)
		else:
			return str(
				u'<{thetag} id=\"{theid}\">{thecontent}</{thetag}>'
			).format(
				thetag=utils.literal_str(tag),
				theid=utils.literal_str(tagid),
				thecontent=utils.literal_str(content)
			)
	elif name is not None and has_special_html_chars(name) is not True:
		return str(
			u'<{thetag} name=\"{thename}\">{thecontent}</{thetag}>'
		).format(
			thetag=utils.literal_str(tag),
			thename=utils.literal_str(name),
			thecontent=utils.literal_str(content)
		)
	else:
		return str(
			u'<{thetag}>{thecontent}</{thetag}>'
		).format(
			thetag=utils.literal_str(tag),
			thecontent=utils.literal_str(content)
		)


def gen_html_tr(content=None, tagid=None, name=None):
	"""
	Generates a table row html tr taglet.
	param content -- The content of the tr taglet.
	param name -- The optional name of the tr taglet.
	param tagid -- The optional tagid of the tr taglet.
	Returns:
	str -- the html string of the tr taglet.
	"""
	return gen_html_tag("tr", content, tagid, name)


def gen_html_td(content=None, tagid=None, name=None):
	"""
	Generates a table data html td taglet.
	param content -- The content of the td taglet.
	param name -- The optional name of the td taglet.
	param tagid -- The optional tagid of the td taglet.
	Returns:
	str -- the html string of the td taglet.
	"""
	return gen_html_tag("td", content, tagid, name)


def gen_html_ul(somelist=None, tagid=None, name=None):
	"""
	Generates a list html ul taglet.
	param somelist -- The content of the ul taglet.
	param name -- The optional name of the li taglet.
	param tagid -- The optional tagid of the li taglet.
	Returns:
	str -- the html string of the li taglet.
	"""
	if somelist is None or somelist is [None]:
		return None
	items = [gen_html_li(x) for x in somelist]
	theresult = None
	if tagid is not None and has_special_html_chars(tagid) is not True:
		if name is None or has_special_html_chars(name) is True:
			name = utils.literal_str(tagid)
		theresult = str(u'<ul name=\"{}\" id=\"{}\">').format(
			utils.literal_str(name),
			utils.literal_str(tagid)
		)
		for item in items:
			theresult = str(theresult + item)
	elif name is not None and has_special_html_chars(name) is not True:
		theresult = str(u'<ul name=\"{}\">').format(utils.literal_str(name))
		for item in items:
			theresult = str(theresult + item)
	else:
		theresult = str(u'<ul>')
		for item in items:
			theresult = str(theresult + item)
	theresult = str(theresult + u'</ul>')
	return theresult


def gen_html_li(item=None, tagid=None, name=None):
	"""
	Generates a list item html li taglet.
	param item -- The content of the li taglet.
	param name -- The optional name of the li taglet.
	param tagid -- The optional tagid of the li taglet.
	Returns:
	str -- the html string of the li taglet.
	"""
	return gen_html_tag("li", item, tagid, name)


def gen_html_label(content=None, role=HTML_LABEL_ROLES[0], tagid=None, name=None):
	"""
	Generates a table data html label taglet.
	param content -- The content of the td taglet.
	param role -- The label class of the span taglet.
	param name -- The optional name of the td taglet.
	param tagid -- The optional tagid of the td taglet.
	Returns:
	str -- the html string of the td taglet.
	"""
	# WARN: not ready for prod - check types, errors, etc,
	# security auditors: if you are reading this you found something
	# I forgot to make ready for prod. patches welcome. CWE-20 BUG
	if tagid is not None and has_special_html_chars(tagid) is not True:
		if name is not None and has_special_html_chars(name) is not True:
			return str(
				u'<span class=\"label label-{}\" name=\"{}\" id=\"{}\">{}</span>'
			).format(
				role,
				utils.literal_str(name),
				utils.literal_str(tagid),
				utils.literal_str(content)
			)
		else:
			return str(
				u'<span class=\"label label-{}\" id=\"{}\">{}</span>'
			).format(role, has_special_html_chars(tagid), utils.literal_str(content))
	elif name is not None and has_special_html_chars(name) is not True:
		return str(
			u'<span class=\"label label-{}\" name=\"{}\">{}</span>'
		).format(role, utils.literal_str(name), utils.literal_str(content))
	else:
		return str(
			u'<span class=\"label label-{}\">{}</span>'
		).format(role, utils.literal_str(content))

