#! /usr/bin/env python
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
	from setuptools import setup
	from setuptools import find_packages
except Exception:
	raise ImportError("""Not Implemented.""")

try:
	with open("""./requirements.txt""") as f:
		requirements = f.read().splitlines()
except Exception:
	requirements = None

try:
	with open("""./README.md""") as f:
		readme = f.read()
except Exception:
	readme = str("""See https://github.com/reactive-firewall/PiAP-python-tools/README.md""")

try:
	with open("""./LICENSE.rst""") as f:
		license = f.read()
except Exception:
	license = str("""See https://github.com/reactive-firewall/PiAP-python-tools/LICENSE.rst""")

try:
	class_tags = [
		str("""Development Status :: 4 - Beta"""),
		str("""Operating System :: POSIX :: Linux"""),
		str("""License :: OSI Approved :: MIT License"""),
		str("""Programming Language :: Python"""),
		str("""Programming Language :: Python :: 3.7"""),
		str("""Programming Language :: Python :: 3.6"""),
		str("""Programming Language :: Python :: 3.5"""),
		str("""Programming Language :: Python :: 3.4"""),
		str("""Programming Language :: Python :: 3.3"""),
		str("""Programming Language :: Python :: 2.7"""),
		str("""Topic :: Security""")
	]
except Exception:
	class_tags = str("""Development Status :: 4 - Beta""")

setup(
	name="""piaplib""",
	version="""0.4.1""",
	description="""Beta for PiAP python tools""",
	long_description=readme,
	long_description_content_type="""text/markdown""",
	zip_safe=False,
	include_package_data=True,
	install_requires=requirements,
	author="""reactive-firewall""",
	author_email="""reactive-firewall@users.noreply.github.com""",
	classifiers=class_tags,
	url="""https://github.com/reactive-firewall/PiAP-python-tools.git@stable""",
	license=license,
	packages=find_packages(exclude=("""tests""", """docs""")),
)

