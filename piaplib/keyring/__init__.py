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
	if sys.__name__ is None:
		raise ImportError("OMG! we could not import os. We're like in the matrix! ABORT. ABORT.")
except Exception as err:
	raise ImportError(err)


try:
	if 'os' not in sys.modules:
		import os
	else:  # pragma: no branch
		os = sys.modules["""os"""]
except Exception:
	raise ImportError("OS Failed to import.")


try:
	if str("keyring") in __file__:
		__sys_path__ = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
		if __sys_path__ not in sys.path:
			sys.path.insert(0, __sys_path__)
except Exception:
	raise ImportError("Pocket Keyring failed to import.")


try:
	if 'piaplib' not in sys.modules:
		raise ImportError("Pocket PKU failed to import.")  # import piaplib as piaplib
	piaplib = sys.modules["""piaplib"""]
except Exception:
	raise ImportError("Pocket Keyring failed to import.")


def generateParser(calling_parser_group):
	try:
		if 'piaplib.keyring.__main__' not in sys.modules:
			import piaplib.keyring.__main__
		else:
			piaplib.keyring.__main__ = sys.modules["""piaplib.keyring.__main__"""]
		if piaplib.keyring.__main__.__name__ is None:
			raise ImportError("Failed to import piaplib.keyring.__main__")
	except Exception as importErr:
		del importErr
		import piaplib.keyring.__main__
	return piaplib.keyring.__main__.generateParser(calling_parser_group)


def main(argv=None):
	"""The main event"""
	try:
		if 'piaplib.keyring.__main__' not in sys.modules:
			import piaplib.keyring.__main__
		else:
			piaplib.keyring.__main__ = sys.modules["""piaplib.keyring.__main__"""]
		if piaplib.keyring.__main__.__name__ is None:
			raise ImportError("Failed to import piaplib.keyring.__main__")
	except Exception as importErr:
		del importErr
		import piaplib.keyring.__main__
	return piaplib.keyring.__main__.main(argv)


if __name__ in u'__main__':
	main(sys.argv[1:])


