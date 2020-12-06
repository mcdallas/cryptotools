import pathlib
import pkg_resources
from setuptools import setup

from cryptotools import __doc__ as docstring

setup(
    name="cryptotools",
    version="0.1",
    description=docstring.strip(),
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
    packages=[
        "cryptotools",
        "cryptotools.ECDSA",
        "cryptotools.RSA",
        "cryptotools.BTC",
        "cryptotools.BTC.HD",
    ],
    package_data={
        'cryptotools': [ 'BTC/HD/wordlist.txt' ]
    }
)
