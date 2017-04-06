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
	sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
except Exception as ImportErr:
	print('')
	print(str(type(ImportErr)))
	print(str(ImportErr))
	print(str((ImportErr.args)))
	print('')
	ImportErr = None
	del ImportErr
	raise ImportError(str(u'Test module failed completely.'))

try:
	from tests import test_basic
	if test_basic.__name__ is None:
		raise ImportError(str(u'Test module failed to import even the basic tests.'))
except Exception as importErr:
	print('')
	print(str(type(importErr)))
	print(str(importErr))
	print(str((importErr.args)))
	print('')
	importErr = None
	del importErr
	raise ImportError(str(u'Test module failed completely.'))
	exit(0)

