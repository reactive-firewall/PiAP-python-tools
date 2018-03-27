# -*- coding: utf-8 -*-

# Pocket PiAP
# ......................................................................
# Copyright (c) 2017, Kendrick Walls
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
	from tests import profiling as profiling
	from tests import test_basic
	from tests import test_strings
	from tests import test_utils
	from tests import test_pocket
	from tests import test_config
	from tests import test_rand
	from tests import test_salt
	from tests import test_lint
	from tests import test_book
	from tests import test_logs
	from tests import test_pku
	from tests import test_version
	from tests import test_clients_check
	from tests import test_interface
	from tests import test_enc
	from tests import test_lint_iface
	depends = [
		profiling, test_basic, test_strings, test_utils, test_pocket, test_config,
		test_rand, test_salt, test_lint, test_book, test_logs, test_pku, test_version,
		test_clients_check, test_interface, test_enc, test_lint_iface
	]
	for unit_test in depends:
		try:
			if unit_test.__name__ is None:
				raise ImportError(
					str("Test module failed to import even the {} tests.").format(str(unit_test))
				)
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
