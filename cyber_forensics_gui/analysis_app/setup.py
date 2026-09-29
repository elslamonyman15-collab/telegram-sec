"""
Cyber Forensics Analysis App v1.0.0
Setup configuration for installation
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_file(filename):
    with open(os.path.join(os.path.dirname(__file__), filename), encoding='utf-8') as f:
        return f.read()

setup(
    name='cyber-forensics-analysis',
    version='1.0.0',
    author='Cyber Forensics Toolkit Contributors',
    author_email='security@example.com',
    description='Report analysis application for Cyber Forensics Toolkit',
    long_description=read_file('README.md'),
    long_description_content_type='text/markdown',
    url='https://github.com/elslamonyman15-collab/telegram-sec',
    packages=find_packages(),
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
        'Topic :: Security',
        'Topic :: System :: Systems Administration',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Operating System :: Microsoft :: Windows',
    ],
    python_requires='>=3.7',
    install_requires=[
        'pandas>=2.0.0',
        'openpyxl>=3.1.2',
        'xlsxwriter>=3.1.9',
        'reportlab>=4.0.4',
    ],
    entry_points={
        'console_scripts': [
            'cyber-forensics-analysis=analysis_gui:main',
        ],
    },
    include_package_data=True,
    zip_safe=False,
    keywords='forensics analysis report security',
    project_urls={
        'Bug Reports': 'https://github.com/elslamonyman15-collab/telegram-sec/issues',
        'Source': 'https://github.com/elslamonyman15-collab/telegram-sec',
        'Documentation': 'https://github.com/elslamonyman15-collab/telegram-sec/wiki',
    },
)
