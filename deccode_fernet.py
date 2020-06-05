import base64
import binascii
import struct
import time
import six

_MAX_CLOCK_SKEW=60

#import cryptography libraries
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.fernet import Fernet

import sys

#key {first part}
key= "hBU9lesroX_veFoHz-xUcaz4_ymH-D8p28IP_4rtjq0=";

# token {second_part}
token = "gAAAAABaDDCRPXCPdGDcBKFqEFz9zvnaiLUbWHqxXqScTTYWfZJcz-WhH7rf_fYHo67zGzJAdkrwATuMptY-nJmU-eYG3HKLO9WDLmO27sex1-R85CZEFCU=";

# check from command line parameter
if(len(sys.argv)>1):
  key=sys.argv[1]

if(len(sys.argv)>2):
  toekn=sys.argv[2]

#algoithm for decrypt
def decrypt(self,token,ttl=None):

  current_time=int(time.time())

  print("=======================================")

  #check if token in bytes
  if not isinstance(token,bytes):
    raise TypeError("token must be bytes")

   #lets first decode the base64 token
  try:
      data=base64.urlsafe_b64decode(token)
  except (TypeError,binascii.Error):
      raise InvalidToken


  print("Decoded Token")
  print("======================================")
    #print data
  print(binascii.hexlify(bytearray(data)))  

  print("++++++++++Analysis++++++++")


  print("=============================")
    
  if not data or six.indexbytes(data,0) !=0x80:
      raise InvalidToken

  try:
     timestamp,=struct.unpack(">Q",data[1:9])
     print("Time stamp:\t",timestamp)

  except struct.error:
     raise InvalidToken

  if ttl is not None:

    if timestamp + ttl < current_time: 
             raise InvalidToken
    if current_time + _MAX_CLOCK_SKEW < timestamp:
              raise InvalidToken

  h=HMAC(self._signing_key,hashes.SHA256(),backend=self._backend)
  h.update(data[:-32])

  try:
        h.verify(data[-32:])
  except InvalidSignature:
        raise InvalidToken

  iv = data[9:25]

  chipertext = data[25:-32]

  decryptor = Cipher(algorithms.AES(self._encryption_key), modes.CBC(iv),self._backend).decryptor()

  plaintext_padded = decryptor.update(chipertext)

  try:
        plaintext_padded += decryptor.finalize()
  except ValueEror:
        raise InvalidToken

  unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

  unpadded = unpadder.update(plaintext_padded)

  try:
        unpadded += unpadder.finalize()
  except ValueEror:
        raise InvalidToken

  print("++++++++++++++++++++++++++++++++++++++++++")
  print("Decoded Value")
  print("===========================================")
  print(unpadded)

  return unpadded


key
f= Fernet(key)
decrypt(f,token.encode())       

    


  