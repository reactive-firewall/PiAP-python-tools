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
	import sys
	import os
	if 'pku' in __file__:
		sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
except Exception as ImportErr:
	print(str(type(ImportErr)))
	print(str(ImportErr))
	print(str((ImportErr.args)))
	ImportErr = None
	del ImportErr
	raise ImportError(u'Pocket Knife Unit PKU failed to import.')


try:
	from . import pku as pku
except Exception as impErr:
	impErr = None
	del impErr
	try:
		import pku as pku
	except Exception as importErr:
		ImportErr = None
		del ImportErr
		raise ImportError(u'Pocket Knife Unit PKU failed to import.')


