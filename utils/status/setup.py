#!/usr/bin/env python3
#
# Copyright (c) 2021 Versity Software, Inc. All rights reserved.
#

from setuptools import setup, find_packages

setup(
    name='scoutfs_status',
    version='1.0.0',
    description='A CLI Tool to get ScoutFS Status',
    license='GPLv2',
    author='Bryant Duffy-Ly',
    author_email='bduffyly@versity.com',
    url='http://github.com/versity/scoutfs',
    packages=find_packages(),
    install_requires=[
        'click',
        'bson'
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
    ],
)
