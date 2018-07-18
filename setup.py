#! /usr/bin/env python
# -*- coding: utf-8 -*-

# *****************************************************************************
# aping.py --> main program module                                            *
#                                                                             *
# *****************************************************************************
# Copyright (C) 2007, 2008 Kantor A. Zsolt <kantorzsolt@yahoo.com>            *
# Overtaken and maintained by Emmanuel Arias <emmanuelarias30@gmail.com>      *
# *****************************************************************************
# This file is part of APing.                                                 *
#                                                                             *
# APing is free software; you can redistribute it and/or modify               *
# it under the terms of the GNU General Public License as published by        *
# the Free Software Foundation; either version 3 of the License, or           *
# (at your option) any later version.                                         *
#                                                                             *
# Aping is distributed in the hope that it will be useful,                    *
# but WITHOUT ANY WARRANTY; without even the implied warranty of              *
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the               *
# GNU General Public License for more details.                                *
#                                                                             *
# You should have received a copy of the GNU General Public License           *
# along with this program.  If not, see <http://www.gnu.org/licenses/>.       *
# *****************************************************************************

from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='Aping',
    version='0.1b4',
    description='Advanced ping program',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/eamanu/Aping',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: GNU General Public License '
            'v3 or later (GPLv3+)',
        'Programming Language :: Python :: 2',
    ],
    keywords='network tool development ping',
    packages=find_packages(),
    project_urls={
        'Bug Reports': 'https://github.com/eamanu/Aping/issues',
        'Source': 'https://github.com/eamanu/Aping',
    },
)
