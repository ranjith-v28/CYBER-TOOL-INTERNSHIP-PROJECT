#!/usr/bin/env python3
"""
Setup script for CyberTool
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="cybertool",
    version="1.0.0",
    author="CyberTool Team",
    author_email="education@cybertool.local",
    description="All-in-One Cybersecurity Toolkit for Educational Purposes",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/cybertool/cybertool",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Education",
        "Topic :: Security",
        "Topic :: Education",
        "License :: Educational Use Only",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "cybertool=main:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)