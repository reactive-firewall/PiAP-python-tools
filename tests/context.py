# -*- coding: utf-8 -*-

try:
	import sys
	import os
	if 'piaplib' in __file__:
		sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
except Exception as ImportErr:
	print(str(type(ImportErr)))
	print(str(ImportErr))
	print(str((ImportErr.args)))
	ImportErr = None
	del ImportErr
	raise ImportError(u'PiAPlib Failed to Import')

try:
	import piaplib
except Exception as importErr:
	importErr = None
	del importErr
	raise ImportError(u'Test module failed to load piaplib for test.')
	exit(0)

