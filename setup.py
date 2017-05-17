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
	from setuptools import setup
	from setuptools import find_packages
except Exception:
	raise ImportError("Not Implemented.")

try:
	with open(u'./requirements.txt') as f:
		requirements = f.read().splitlines()
except Exception:
	requirements = None

try:
	with open(u'./README.md') as f:
		readme = f.read()
except Exception:
	readme = str("""See https://github.com/reactive-firewall/PiAP-python-tools/README.md""")

try:
	with open(u'./LICENSE.rst') as f:
		license = f.read()
except Exception:
	readme = str("""See https://github.com/reactive-firewall/PiAP-python-tools/LICENSE.rst""")


setup(
	name='piaplib',
	version='0.2.4',
	description='Beta for PiAP python tools',
	long_description=readme,
	install_requires=requirements,
	author='reactive-firewall',
	author_email='reactive-firewall@users.noreply.github.com',
	url='https://github.com/reactive-firewall/PiAP-python-tools.git',
	license=license,
	packages=find_packages(exclude=('tests', 'docs'))
)

