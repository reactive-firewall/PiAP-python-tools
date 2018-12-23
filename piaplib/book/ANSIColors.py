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


"""ANSI colored text"""


try:
	import sys
	import os
	import os.path
	if str("book") in __file__:
		__sys_path__ = os.path.abspath(os.path.join(os.path.dirname(__file__), '.'))
		if __sys_path__ not in sys.path:
			sys.path.insert(0, __sys_path__)
except Exception:
	raise ImportError("Pocket Book Colors failed to import.")


__prog__ = """piaplib.book.ANSIColors"""
"""The name of this PiAPLib tool is Pocket Knife config Unit"""


ENDC = """\033[0m"""
BOLD = """\033[1m"""
ITALIC = """\033[3m"""
URL = """\033[4m"""
BLINK = """\033[5m"""
BLINK2 = """\033[6m"""
SELECTED = """\033[7m"""

BLACK = """\033[30m"""
RED = """\033[31m"""
GREEN = """\033[32m"""
YELLOW = """\033[33m"""
BLUE = """\033[34m"""
VIOLET = """\033[35m"""
BEIGE = """\033[36m"""
WHITE = """\033[37m"""

BLACKBG = """\033[40m"""
REDBG = """\033[41m"""
GREENBG = """\033[42m"""
YELLOWBG = """\033[43m"""
BLUEBG = """\033[44m"""
VIOLETBG = """\033[45m"""
BEIGEBG = """\033[46m"""
WHITEBG = """\033[47m"""

GREY = """\033[90m"""
RED2 = """\033[91m"""
GREEN2 = """\033[92m"""
YELLOW2 = """\033[93m"""
AMBER = """\033[93m"""
BLUE2 = """\033[94m"""
VIOLET2 = """\033[95m"""
BEIGE2 = """\033[96m"""
WHITE2 = """\033[97m"""

GREYBG = """\033[100m"""
REDBG2 = """\033[101m"""
GREENBG2 = """\033[102m"""
YELLOWBG2 = """\033[103m"""
BLUEBG2 = """\033[104m"""
VIOLETBG2 = """\033[105m"""
BEIGEBG2 = """\033[106m"""
WHITEBG2 = """\033[107m"""
WARNING = AMBER
OKBLUE = BLUE
OKGREEN = GREEN
HEADER = VIOLET
FAIL = RED
