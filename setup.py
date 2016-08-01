#!/usr/bin/env python3
from setuptools import setup, find_packages

setup(
    name = 'butcher',
    version = '0.1',
    packages = find_packages(),
    author = 'Daniil Migalin',
    author_email = 'me@miga.me.uk',
    description = 'Convenient shmux-based shell for executing commands within Chef-managed infrastructure',
    license = 'MIT',
    entry_points={
        'console_scripts': [
            'butcher = butcher:main'
            ]
        },
    keywords = '',
    zip_safe = False,
    install_requires = ['PyYAML']
)
