#! /usr/bin/env python
# -*- coding: utf-8 -*-

#
# Pocket PiAP
#
# Copyright (c) 2017, Kendrick Walls
#	
#	Licensed under the Apache License, Version 2.0 (the "License");
#		you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#	   
#	   http://www.apache.org/licenses/LICENSE-2.0
#   
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#

HTML_LABEL_ROLES=[u'default', u'success', u'info', u'warning', u'danger']
"""the types of labels that can be used in html output"""

def gen_html_tr(content=None, id=None, name=None):
	"""
	Generates a table row html tr taglet.
	
	param content -- The content of the tr taglet.
	param name -- The optional name of the tr taglet.
	param id -- The optional id of the tr taglet.
	Returns:
	str -- the html string of the tr taglet.
	"""
	if id is not None and has_special_html_chars(id) is not True:
		if name is not None and has_special_html_chars(name) is not True:
			return str(u'<tr name=\"{}\" id=\"{}\">{}</tr>').format(str(name), str(id), str(content))
		else:
			return str(u'<tr id=\"{}\">{}</tr>').format(id, str(content))
	elif name is not None and has_special_html_chars(name) is not True:
			return str(u'<tr name=\"{}\">{}</tr>').format(id, str(content))
	else:
		return str(u'<tr>{}</tr>').format(str(content))

def has_special_html_chars(somestr=None):
	"""
	Determins if the string have special html charterers.
	
	param somestr -- The string to test.
	Returns:
	True -- if the string has special charterers.
	False -- otherwise.
	"""
	try:
		if somestr is None:
			return True
		badchars=[u'\"', u'\'', u'\\', u'%', u'>', u'<', u'=']
		for badchar in badchars:
			if badchar in somestr:
				return True
	except Exception as badinput:
		print(str("Bad html render string input."))
		del badinput
		return True
	return False

def gen_html_td(content=None, id=None, name=None):
	"""
	Generates a table data html td taglet.
	
	param content -- The content of the td taglet.
	param name -- The optional name of the td taglet.
	param id -- The optional id of the td taglet.
	Returns:
	str -- the html string of the td taglet.
	"""
	if id is not None and has_special_html_chars(id) is not True:
		if name is not None and has_special_html_chars(name) is not True:
			return str(u'<td name=\"{}\" id=\"{}\">{}</td>').format(str(name), str(id), str(content))
		else:
			return str(u'<td id=\"{}\">{}</td>').format(id, str(content))
	elif name is not None and has_special_html_chars(name) is not True:
			return str(u'<td name=\"{}\">{}</td>').format(id, str(content))
	else:
		return str(u'<td>{}</td>').format(str(content))

def gen_html_ul(somelist=None, id=None, name=None):
	"""
	Generates a list html ul taglet.
	
	param somelist -- The content of the ul taglet.
	param name -- The optional name of the li taglet.
	param id -- The optional id of the li taglet.
	Returns:
	str -- the html string of the li taglet.
	"""
	if somelist is None or somelist is [None]:
		return None
	items = [gen_html_li(x) for x in somelist]
	theresult = None
	if id is not None and has_special_html_chars(id) is not True:
		if name is not None and has_special_html_chars(name) is not True:
			theresult = str(u'<ul name=\"{}\" id=\"{}\">').format(str(name), str(id))
			for item in items:
				theresult = str(theresult + item)
		else:
			theresult = str(u'<ul id=\"{}\">').format(str(id))
			for item in items:
				theresult = str(theresult + item)
	elif name is not None and has_special_html_chars(name) is not True:
		theresult = str(u'<ul name=\"{}\">').format(str(name))
		for item in items:
			theresult = str(theresult + item)
	else:
		theresult = str(u'<ul>')
		for item in items:
			theresult = str(theresult + item)
	theresult = str(theresult + u'</ul>')
	return theresult

def gen_html_li(item=None, id=None, name=None):
	"""
	Generates a list item html li taglet.
	
	param item -- The content of the li taglet.
	param name -- The optional name of the li taglet.
	param id -- The optional id of the li taglet.
	Returns:
	str -- the html string of the li taglet.
	"""
	if id is not None and has_special_html_chars(id) is not True:
		if name is not None and has_special_html_chars(name) is not True:
			return str(u'<li name=\"{}\" id=\"{}\">{}</li>').format(str(name), str(id), str(item))
		else:
			return str(u'<li id=\"{}\">{}</li>').format(id, str(item))
	elif name is not None and has_special_html_chars(name) is not True:
			return str(u'<li name=\"{}\">{}</li>').format(id, str(item))
	else:
		return str(u'<li>{}</li>').format(str(item))

def gen_html_label(content=None, role=HTML_LABEL_ROLES[0], id=None, name=None):
	"""
	Generates a table data html lable taglet.
	
	param content -- The content of the td taglet.
	param role -- The lable class of the span taglet.
	param name -- The optional name of the td taglet.
	param id -- The optional id of the td taglet.
	Returns:
	str -- the html string of the td taglet.
	"""
	#WARN:not ready for prod - check types, errors, etc,
	# security auditors: if you are reading this you found somthing I forgot to make ready for prod. patches welcome.
	if id is not None and has_special_html_chars(id) is not True:
		if name is not None and has_special_html_chars(name) is not True:
			return str(u'<span class=\"lable lable-{}\" name=\"{}\" id=\"{}\">{}</span>').format(role, str(name), str(id), str(content))
		else:
			return str(u'<span class=\"lable lable-{}\" id=\"{}\">{}</span>').format(role, id, str(content))
	elif name is not None and has_special_html_chars(name) is not True:
			return str(u'<span class=\"lable lable-{}\" name=\"{}\">{}</span>').format(role, id, str(content))
	else:
		return str(u'<span class=\"lable lable-{}\">{}</span>').format(role, str(content))

