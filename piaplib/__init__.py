# -*- coding: utf-8 -*-

import sys
import os
if 'piaplib' in __file__:
	sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
	from . import pocket
except Exception:
	import pocket
