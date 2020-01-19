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
	import os
	try:
		if str("keyring") in __file__:
			__sys_path__ = os.path.abspath(os.path.dirname(__file__))
			if __sys_path__ not in sys.path:
				sys.path.insert(0, __sys_path__)
	except Exception:
		raise ImportError("PiAPlib keyring failed to import.")
except Exception as ImportErr:
	print(str(type(ImportErr)))
	print(str(ImportErr))
	print(str((ImportErr.args)))
	ImportErr = None
	del ImportErr
	raise ImportError(u'Keyring Failed to Import')


def main(argv=None):
	"""The main event"""
	import piaplib.keyring.__main__
	return piaplib.keyring.__main__.main(argv)


if __name__ in u'__main__':
	main(sys.argv[1:])


