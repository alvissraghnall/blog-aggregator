# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

try:
    long_description = open("README.rst").read()
except IOError:
    long_description = ""

setup(
    name="content-processor",
    version="0.1.0",
    description="Consumes RSS feeds, processes articles, and stores them in MongoDB.",
    license="MIT",
    author="Your Name",
    packages=find_packages(),
    install_requires=[
        "pika",
        "pymongo",
        "yake",
        "requests",
        "readabilipy",
        "feedparser",
        "python-dotenv",
        "beautifulsoup4"
    ],
    long_description=long_description,
    classifiers=[
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.12",
    ],
)
