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


global __version__


__version__ = """0.4.3"""


try:
	import sys
	import os
	import os.path
	_DIR_NAME = str(".")
	_PARENT_DIR_NAME = str("..")
	_BASE_NAME = os.path.dirname(__file__)
	try:
		if str("piaplib") in __file__:
			search_list = [
				os.path.abspath(os.path.join(_BASE_NAME, _PARENT_DIR_NAME)),
				os.path.abspath(os.path.join(_BASE_NAME, _DIR_NAME))
			]
			for __sys_path__ in search_list:
				if __sys_path__ not in sys.path:
					sys.path.insert(0, __sys_path__)
	except Exception:
		raise ImportError("PiAPlib failed to import.")
except Exception as ImportErr:
	print(str(type(ImportErr)))
	print(str(ImportErr))
	print(str((ImportErr.args)))
	ImportErr = None
	del ImportErr
	raise ImportError(str(u'PiAPlib Failed to Import'))


try:
	if 'piaplib.book' not in sys.modules:
		from . import book as book
	else:  # pragma: no branch
		book = sys.modules["""piaplib.book"""]
except Exception as importErr:
	del importErr
	import book as book


try:
	if 'piaplib.pku' not in sys.modules:
		from . import pku as pku
	else:  # pragma: no branch
		pku = sys.modules["""piaplib.pku"""]
except Exception as importErr:
	del importErr
	import pku as pku


try:
	if 'piaplib.keyring' not in sys.modules:
		from . import keyring as keyring
	else:  # pragma: no branch
		keyring = sys.modules["""piaplib.keyring"""]
except Exception as importErr:
	del importErr
	import keyring as keyring


try:
	if 'piaplib.lint' not in sys.modules:
		from . import lint as lint
	else:  # pragma: no branch
		lint = sys.modules["""piaplib.lint"""]
except Exception as importErr:
	del importErr
	import lint as lint


if __name__ in u'__main__':
	try:
		if 'piaplib.pocket' not in sys.modules:
			from . import pocket as pocket
		else:  # pragma: no branch
			pocket = sys.modules["""piaplib.pocket"""]
	except Exception:
		import pocket as pocket
	if pku.__name__ is None:
		raise ImportError(str(u'Failed to open Pocket Knife Unit'))
	if keyring.__name__ is None:
		raise ImportError(str(u'Failed to find Pocket Keyring'))
	if lint.__name__ is None:
		raise ImportError(str(u'Failed to gather Pocket Lint'))
	if book.__name__ is None:
		raise ImportError(str(u'Failed to open Pocket Book'))
	pocket.main(sys.argv[1:])
	exit(0)

