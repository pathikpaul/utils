import sys
import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

if len(sys.argv) != 4 :
   sys.exit( """      Usage : {} SecretKey ENCRYPT|DECRYPT FileTobeEncryptedDecrypted """.format(sys.argv[0]))
password_provided = sys.argv[1] 
Operation =  sys.argv[2]
input_file = sys.argv[3]

password = password_provided.encode() # Convert to type bytes
salt = b'salt_' # CHANGE THIS - recommend using a key from os.urandom(16), must be of type bytes
kdf = PBKDF2HMAC( algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
key = base64.urlsafe_b64encode(kdf.derive(password)) # Can only use kdf once
if Operation == 'ENCRYPT':
    output_file = input_file+'.encrypted'
    if os.path.isfile(output_file):
        sys.exit('File Found :: {}'.format(output_file))
    with open(input_file, 'rb') as f:
        data = f.read()
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data)
    with open(output_file, 'wb') as f:
        f.write(encrypted)
if Operation == 'DECRYPT':
    output_file = input_file+'.decrypted'
    if os.path.isfile(output_file):
        sys.exit('File Found :: {}'.format(output_file))
    with open(input_file, 'rb') as f:
        data = f.read()
    fernet = Fernet(key)
    decrypted = fernet.decrypt(data)
    with open(output_file, 'wb') as f:
        f.write(decrypted)

###
### Ref: https://nitratine.net/blog/post/encryption-and-decryption-in-python/
### 
