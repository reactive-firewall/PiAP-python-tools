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


global __package__


# PEP 366
if __package__ is None:
	__package__ = """piaplib"""


try:
	import sys
	if 'piaplib.pocket' not in sys.modules:
		from . import pocket as pocket
except Exception as importErr:
	del importErr
	import pocket as pocket


if __name__ in u'__main__':
	pocket.main(sys.argv[1:])
	sys.exit(0)
