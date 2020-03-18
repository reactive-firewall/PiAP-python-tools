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


try:
	import sys
	if sys.__name__ is None:  # pragma: no branch
		raise ImportError("[CWE-758] OMG! we could not import sys. ABORT. ABORT.")
except Exception as err:  # pragma: no branch
	raise ImportError(err)


try:
	if 'os' not in sys.modules:
		import os
	else:  # pragma: no branch
		os = sys.modules["""os"""]
except Exception:  # pragma: no branch
	raise ImportError("[CWE-758] OS Failed to import.")


try:
	if 'unittest' not in sys.modules:
		import unittest
	else:  # pragma: no branch
		unittest = sys.modules["""unittest"""]
except Exception:  # pragma: no branch
	raise ImportError("[CWE-758] unittest Failed to import.")


try:
	if 'piaplib' not in sys.modules:
		import piaplib
	else:  # pragma: no branch
		piaplib = sys.modules["""piaplib"""]
except Exception:  # pragma: no branch
	raise ImportError("[CWE-758] piaplib Failed to import.")


try:
	_DIR_NAME = str(".")
	_PARENT_DIR_NAME = str("..")
	_BASE_NAME = os.path.dirname(__file__)
	if 'piaplib' in __file__:
		sys.path.insert(0, os.path.abspath(os.path.join(_BASE_NAME, _PARENT_DIR_NAME)))
	if 'tests' in __file__:
		sys.path.insert(0, os.path.abspath(os.path.join(_BASE_NAME, _DIR_NAME)))
	from tests import profiling as profiling
	from tests import test_basic
	from tests import test_pocket
	from tests import test_pku
	from tests import test_strings
	from tests import test_utils
	from tests import test_interface
	from tests import test_config
	from tests import test_keyring
	from tests import test_rand
	from tests import test_salt
	from tests import test_enc
	from tests import test_lint
	from tests import test_html
	from tests import test_lint_users
	from tests import test_lint_iface
	from tests import test_clients_check
	from tests import test_book
	from tests import test_logs
	from tests import test_version
	from tests import test_usage

	depends = [
		profiling, test_basic, test_strings, test_utils, test_pocket, test_config,
		test_rand, test_salt, test_lint, test_book, test_logs, test_pku, test_version,
		test_clients_check, test_interface, test_enc, test_lint_iface, test_html,
		test_lint_users, test_keyring, test_usage
	]
	for unit_test in depends:
		try:
			if unit_test.__name__ is None:  # pragma: no branch
				raise ImportError(
					str("Test module failed to import even the {} tests.").format(str(unit_test))
				)
		except Exception as impErr:  # pragma: no branch
			print(str(''))
			print(str(type(impErr)))
			print(str(impErr))
			print(str((impErr.args)))
			print(str(''))
			impErr = None
			del impErr
			raise ImportError(str("[CWE-758] Test module failed completely."))
except Exception as badErr:  # pragma: no branch
	print(str(''))
	print(str(type(badErr)))
	print(str(badErr))
	print(str((badErr.args)))
	print(str(''))
	badErr = None
	del badErr
	exit(0)
