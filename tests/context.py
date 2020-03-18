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
		raise ImportError("[CWE-758] OMG! we could not import sys! ABORT. ABORT.")
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

