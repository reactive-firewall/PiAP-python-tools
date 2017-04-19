#! /usr/bin/env python
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
	from . import config as config
except Exception:
	try:
		import config as config
	except Exception:
		raise ImportError("Error Importing config")

try:
	from . import utils as utils
except Exception:
	try:
		import utils as utils
	except Exception:
		raise ImportError("Error Importing utils")

try:
	from . import interfaces as interfaces
except Exception:
	try:
		import interfaces as interfaces
	except Exception:
		raise ImportError("Error Importing interfaces")


def main(argv=None):
	"""The Main Event."""
	print("PKU not implemented yet")
	exit(0)


if __name__ in u'__main__':
	if utils.__name__ is None:
		raise ImportError("Error Importing utils")
	if config.__name__ is None:
		raise ImportError("Error Importing config")
	if interfaces.__name__ is None:
		raise ImportError("Error Importing interfaces")
	try:
		import sys
	except Exception:
		raise ImportError("Error Importing builtin sys")
	main(sys.argv[1:])

