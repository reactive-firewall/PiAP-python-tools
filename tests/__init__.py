# -*- coding: utf-8 -*-
	
try:
	import sys
	import os
	sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
except Exception as ImportErr:
	print(str(type(ImportErr)))
	print(str(ImportErr))
	print(str((ImportErr.args)))
	ImportErr = None
	del ImportErr
	raise ImportError(u'Test module failed completely.')

try:
	from tests import test_basic
except Exception as importErr:
	importErr = None
	del importErr
	raise ImportError(u'Test module failed completely.')
	exit(0)

