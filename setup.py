import pathlib
import pkg_resources
from setuptools import setup

setup(
    name="cryptotools",
    version='be7582a',
    description="Zero dependency implementation of common cryptographic functions for working with cryptocurrency.",
    long_description=(pathlib.Path(__file__).parent / "README.rst").read_text(),
    long_description_content_type="text/x-rst",
    url="https://github.com/mcdallas/cryptotools",
    author="Mike Dallas",
    author_email="mcdallas@protonmail.com",
    license="MIT",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
    ],
    packages=["cryptotools"]
)
