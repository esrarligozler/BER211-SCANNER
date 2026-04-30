#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="ber211-scanner",
    version="1.1.0",
    author="ESRAR-I-GOZLER",
    description="Yetkili güvenlik testleri için tahribatsız web uygulama tarayıcısı",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/ber211-scanner",
    project_urls={
        "Documentation": "https://github.com/esrarligozler/BER211-SCANNER#readme",
        "Source": "https://github.com/esrarligozler/BER211-SCANNER",
        "Tracker": "https://github.com/esrarligozler/BER211-SCANNER/issues",
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Operating System :: OS Independent",
    ],
    py_modules=["main"],
    python_requires=">=3.8",
    install_requires=[
        "aiohttp>=3.8.0",
        "requests>=2.28.0",
        "beautifulsoup4>=4.11.0",
        "dnspython>=2.2.0",
        "python-whois>=0.8.0",
        "ipwhois>=1.2.0",
        "tldextract>=3.3.0",
        "urllib3>=1.26.0",
    ],
    entry_points={
        "console_scripts": [
            "ber211-scanner = main:main_cli",
        ],
    },
)
