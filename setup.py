#!/usr/bin/env python
"""Setuptools based setup module for 'poh'.
"""

# Always prefer setuptools over distutils
from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

import io
import re

dunder_re = re.compile(r"^__(.*?)__ = '([^']*)'")
main_pkg_init_fpath = path.join(here, 'poh', '__init__.py')

METADATA = {}
with io.open(main_pkg_init_fpath) as module_file:
    for line in module_file.readlines():
        if dunder_re.match(line):
            key, val = dunder_re.search(line).groups()
            METADATA[key] = val

setup(
    name='poh',
    version=METADATA['versionstr'],
    description='ssh commands runner',
    long_description=long_description,
    url='https://github.com/slashfoo/poh',
    author='Jamiel Almeida',
    author_email='jamiel.almeida@gmail.com',
    license='MIT',

    classifiers=[
        'Development Status :: 3 - Alpha',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
    ],
    keywords='ssh admin remote command execution',
    packages=find_packages(),
    install_requires=[],
    extras_require={},
    package_data={},
    data_files=[],
    entry_points={
        'console_scripts': [
            'poh=poh.poh:main_exe',
        ],
    },
)
