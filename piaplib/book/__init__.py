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


# PEP 366
__package__ = """piaplib.book"""


try:
	import sys
	import os
	if str("book") in __file__:
		__sys_path__ = os.path.abspath(os.path.join(os.path.dirname(__file__), '.'))
		if __sys_path__ not in sys.path:
			sys.path.insert(0, __sys_path__)
except Exception:
	raise ImportError("Pocket Book failed to import.")


try:
	if 'piaplib' not in sys.modules:
		import piaplib as piaplib
	else:
		piaplib = sys.modules['piaplib']
except Exception:
	raise ImportError("Pocket Book failed to import.")


def main(argv=None):
	"""The main event"""
	try:
		if 'piaplib.book.__main__' not in sys.modules:
			import piaplib.book.__main__
			if piaplib.book.__main__.__name__ is None:
				raise ImportError("Failed to import piaplib.book.__main__")
	except Exception as importErr:
		del importErr
		import piaplib.book.__main__
	return piaplib.book.__main__.main(argv)


if __name__ in u'__main__':
	main(sys.argv[1:])

