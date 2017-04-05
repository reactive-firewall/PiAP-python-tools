#! /usr/bin/env python
# -*- coding: utf-8 -*-


# Pocket PiAP
# 
# Copyright (c) 2017, Kendrick Walls
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
# http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


try:
	from . import config as config
except Exception:
	import config as config


try:
	from . import utils as utils
except Exception:
	import utils as utils


def main(argv=None):
	"""The Main Event."""
	print("PKU not implemented yet")
	exit(0)


if __name__ in u'__main__':
	import sys
	main(sys.argv[1:])


