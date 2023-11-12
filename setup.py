#!/usr/bin/env python3
#
# Copyright (c) SAS Institute Inc. and contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from Cython.Build import cythonize
from setuptools import Extension, setup


with open("README.rst", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="turkeyutils",
    version="0.7.0",
    description="keyutils bindings for Python",
    long_description=long_description,
    author="Daniel Goldman",
    author_email="danielgoldman4@gmail.com",
    url="https://github.com/lilatomic/turkeyutils",
    license="Apache 2.0",
    packages=["keyutils"],
    classifiers=[
        "Topic :: Security",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    platforms=[
        "Linux",
    ],
    ext_modules=cythonize([
        Extension(
            "keyutils._keyutils",
            ["keyutils/_keyutils.pyx"],
            libraries=["keyutils"],
        ),
    ]),
    setup_requires=[],
    tests_require=["pytest", "pytest-runner"],
)
