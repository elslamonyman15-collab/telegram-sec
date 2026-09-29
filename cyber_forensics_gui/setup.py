"""
Cyber Forensics Toolkit v8.0 - Enterprise Edition
Setup configuration for installation
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_file(filename):
    with open(os.path.join(os.path.dirname(__file__), filename), encoding='utf-8') as f:
        return f.read()

setup(
    name='cyber-forensics-toolkit',
    version='8.0.0',
    author='Cyber Forensics Toolkit Contributors',
    author_email='security@example.com',
    description='Enterprise-grade Windows security forensics and threat analysis toolkit',
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
        'python-telegram-bot==20.7',
        'pytsk3==20231205',
        'volatility3==2.5.0',
        'evtx==0.8.1',
        'pefile==2023.2.7',
        'yara-python==4.3.1',
        'pywin32==306',
        'wmi==1.5.1',
        'cryptography==41.0.7',
        'requests==2.31.0',
        'abuseipdb==1.0.0',
        'vt-py==0.7.0',
        'scikit-learn==1.3.0',
        'numpy==1.24.0',
        'pandas==2.0.0',
        'joblib==1.3.0',
        'openpyxl==3.1.2',
        'xlsxwriter==3.1.9',
        'reportlab==4.0.4',
    ],
    entry_points={
        'console_scripts': [
            'cyber-forensics=cyber_forensics_gui:main',
            'cyber-forensics-bot=telegram_bot:main',
        ],
    },
    include_package_data=True,
    zip_safe=False,
    keywords='forensics security analysis windows threat-detection malware',
    project_urls={
        'Bug Reports': 'https://github.com/elslamonyman15-collab/telegram-sec/issues',
        'Source': 'https://github.com/elslamonyman15-collab/telegram-sec',
        'Documentation': 'https://github.com/elslamonyman15-collab/telegram-sec/wiki',
    },
)
