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
	try:
		import sys
		import os
		sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), str('..'))))
	except Exception as ImportErr:
		print(str(''))
		print(str(type(ImportErr)))
		print(str(ImportErr))
		print(str((ImportErr.args)))
		print(str(''))
		ImportErr = None
		del ImportErr
		raise ImportError(str("Test module failed completely."))
	try:
		from tests import profiling as profiling
		if profiling.__name__ is None:
			raise ImportError(str("Test module failed to import even the profiling framework."))
	except Exception as impErr:
		print(str(''))
		print(str(type(impErr)))
		print(str(impErr))
		print(str((impErr.args)))
		print(str(''))
		impErr = None
		del impErr
		raise ImportError(str("Test module failed completely."))
		exit(1)
	try:
		from tests import test_basic
		if test_basic.__name__ is None:
			raise ImportError(str("Test module failed to import even the basic tests."))
	except Exception as impErr:
		print(str(''))
		print(str(type(impErr)))
		print(str(impErr))
		print(str((impErr.args)))
		print(str(''))
		impErr = None
		del impErr
		raise ImportError(str("Test module failed completely."))
		exit(1)
	try:
		from tests import test_strings
		if test_strings.__name__ is None:
			raise ImportError(str("Test module failed to import even the string tests."))
	except Exception as impErr:
		print(str(''))
		print(str(type(impErr)))
		print(str(impErr))
		print(str((impErr.args)))
		print(str(''))
		impErr = None
		del impErr
		raise ImportError(str("Test module failed completely."))
		exit(1)
	try:
		from tests import test_utils
		if test_utils.__name__ is None:
			raise ImportError(str("Test module failed to import even the utils tests."))
	except Exception as impErr:
		print(str(''))
		print(str(type(impErr)))
		print(str(impErr))
		print(str((impErr.args)))
		print(str(''))
		impErr = None
		del impErr
		raise ImportError(str("Test module failed completely."))
		exit(1)
	try:
		from tests import test_pocket
		if test_pocket.__name__ is None:
			raise ImportError(str("Test module failed to import even the pocket tests."))
	except Exception as impErr:
		print(str(''))
		print(str(type(impErr)))
		print(str(impErr))
		print(str((impErr.args)))
		print(str(''))
		impErr = None
		del impErr
		raise ImportError(str("Test module failed completely."))
		exit(1)
	try:
		from tests import test_config
		if test_config.__name__ is None:
			raise ImportError(str("Test module failed to import even the configs tests."))
	except Exception as impErr:
		print(str(''))
		print(str(type(impErr)))
		print(str(impErr))
		print(str((impErr.args)))
		print(str(''))
		impErr = None
		del impErr
		raise ImportError(str("Test module failed completely."))
		exit(1)
	try:
		from tests import test_rand
		if test_rand.__name__ is None:
			raise ImportError(str("Test module failed to import even the random tests."))
	except Exception as impErr:
		print(str(''))
		print(str(type(impErr)))
		print(str(impErr))
		print(str((impErr.args)))
		print(str(''))
		impErr = None
		del impErr
		raise ImportError(str("Test module failed completely."))
		exit(1)
	try:
		from tests import test_salt
		if test_salt.__name__ is None:
			raise ImportError(str("Test module failed to import even the salt tests."))
	except Exception as impErr:
		print(str(''))
		print(str(type(impErr)))
		print(str(impErr))
		print(str((impErr.args)))
		print(str(''))
		impErr = None
		del impErr
		raise ImportError(str("Test module failed completely."))
		exit(1)
	try:
		from tests import test_lint
		if test_lint.__name__ is None:
			raise ImportError(str("Test module failed to import even the lint special tests."))
	except Exception as impErr:
		print(str(''))
		print(str(type(impErr)))
		print(str(impErr))
		print(str((impErr.args)))
		print(str(''))
		impErr = None
		del impErr
		raise ImportError(str("Test module failed completely."))
		exit(1)
	try:
		from tests import test_book
		if test_book.__name__ is None:
			raise ImportError(str("Test module failed to import even the book special tests."))
	except Exception as impErr:
		print(str(''))
		print(str(type(impErr)))
		print(str(impErr))
		print(str((impErr.args)))
		print(str(''))
		impErr = None
		del impErr
		raise ImportError(str("Test module failed completely."))
		exit(1)
	try:
		from tests import test_interface
		if test_interface.__name__ is None:
			raise ImportError(str("Test module failed to import even the iface special tests."))
	except Exception as impErr:
		print(str(''))
		print(str(type(impErr)))
		print(str(impErr))
		print(str((impErr.args)))
		print(str(''))
		impErr = None
		del impErr
		raise ImportError(str("Test module failed completely."))
		exit(1)
except Exception as badErr:
	print(str(''))
	print(str(type(badErr)))
	print(str(badErr))
	print(str((badErr.args)))
	print(str(''))
	badErr = None
	del badErr
	exit(0)
