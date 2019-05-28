#!/usr/bin/env/python
#

from setuptools import setup, find_packages

setup(name="iprange_acl",
        version="1.0.0",
        description="Swift middleware for controlling access to containers based on IP",
        url="https://github.com/CAIDA/",
        author="Shane Alcock",
        author_email="shane.alcock@waikato.ac.nz",
        license="Apache 2.0",
        packages=find_packages(),
        install_requires=['swift', 'ipaddress', 'pytricia'],
        entry_points={'paste.filter_factory':
                ['iprange_acl=iprange_acl.iprange_acl:filter_factory']}
)

