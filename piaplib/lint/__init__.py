# -*- coding: utf-8 -*-

# Pocket PiAP
# ......................................................................
# Copyright (c) 2017-2019, Kendrick Walls
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
		if str("lint") in __file__:
			__sys_path__ = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
			if __sys_path__ not in sys.path:
				sys.path.insert(0, __sys_path__)
	except Exception:
		raise ImportError("Pocket Knife Unit Lint failed to import.")
except Exception as ImportErr:
	print(str(type(ImportErr)))
	print(str(ImportErr))
	print(str((ImportErr.args)))
	ImportErr = None
	del ImportErr
	raise ImportError(u'Pocket Lint Failed to accumulate')

try:
	from . import lint as lint
	if lint.__name__ is False:
		raise ImportError(u'Failed to import Pocket Lint')
except Exception as importErr:
	del importErr
	import lint as lint

