# -*- coding: utf-8 -*-
from __future__ import with_statement
from setuptools import setup


setup(
    name='export_ldap',
    version='0.1.0',
    description="",
    author='Pablo Martin',
    author_email='goinnn@gmail.com',
    url='https://github.com/gecos-team',
    license='GPL v2.0',
    py_modules=['export_ldap'],
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        'requests==2.5.0',
        'python-ldap==2.4.18',
    ],
    entry_points={
        'console_scripts': [
            'export_ldap = export_ldap:main',
        ],
    },
)