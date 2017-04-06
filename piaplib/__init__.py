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

try:
	import sys
	import os
	if 'piaplib' in __file__:
		sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
except Exception as ImportErr:
	print(str(type(ImportErr)))
	print(str(ImportErr))
	print(str((ImportErr.args)))
	ImportErr = None
	del ImportErr
	raise ImportError(u'PiAPlib Failed to Import')

try:
	from . import pocket as pocket
except Exception as importErr:
	del importErr
	import pocket as pocket

try:
	from . import pku as pku
except Exception as importErr:
	del importErr
	import pku as pku

try:
	from . import keyring as keyring
except Exception as importErr:
	del importErr
	import keyring as keyring

try:
	from . import lint as lint
except Exception as importErr:
	del importErr
	import lint as lint

if __name__ in u'__main__':
	if pku.__name__ is None:
		raise ImportError("Failed to open Pocket Knife Unit")
	if keyring.__name__ is None:
		raise ImportError("Failed to find Pocket Keyring")
	if lint.__name__ is None:
		raise ImportError("Failed to gather Pocket Lint")
	pocket.main()
	exit(0)

