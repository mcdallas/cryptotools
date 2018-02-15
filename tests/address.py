import sys, pathlib
sys.path.append(str(pathlib.Path(__file__).absolute().parent.parent))

import bs4
import requests

from btctools.address import pubkey_to_address
from ECDS.secp256k1 import private_to_public, encode_public_key
from transformations import hex_to_int

url = 'http://gobittest.appspot.com/Address'

r = requests.post(url, data={'Random': 'Random'})
soup = bs4.BeautifulSoup(r.text, 'lxml')

private = soup.find('input', {'name': 'private'})['value']
address = soup.find('input', {'name': 'Base58'})['value']

assert pubkey_to_address(encode_public_key(private_to_public(hex_to_int(private)))) == address
print('All good')
