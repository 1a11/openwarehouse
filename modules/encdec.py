import base64
from cryptography.fernet import Fernet
import hashlib
import random
import os
import uuid
import string

os.environ['HASHING_SALT'] = 'OHNOOMG' #    TODO: CHANGE ME 
seedSalt = os.getenv('HASHING_SALT')

class EncDec(object):
    def __init__(self, seed=None):
        self.key = self.generateKey(seed)
        self.hasher = hashlib.blake2s()

    def generateKey(self, seed=None):
        self.seed = seed + seedSalt
        random.seed(self.seed)
        key = random.randbytes(32)
        key = base64.urlsafe_b64encode(key)
        return key
        
    def encode(self, message):
        message_bytes = message.encode('utf8')
        base64_bytes = base64.b64encode(message_bytes)
        base64_message = base64_bytes.decode('utf8')
        return base64_message

    def encrypt(self, message):
        f = Fernet(self.key)
        message = message.encode()
        encrypted = f.encrypt(message)
        return encrypted

    def decrypt(self, encrypted):
        f = Fernet(self.key)
        decrypted = f.decrypt(encrypted)
        return decrypted.decode()
    
    def hash_data(self, data, salt):
        return hashlib.sha256(str(data+salt).encode()).hexdigest()

    def get_uid(self):
        return str(uuid.uuid4())
    
    def gen_user_salt(self):
        random.seed()
        return "".join(random.choices(string.ascii_letters+string.digits, k=25))
    
    def decrypt_data_mass(self, data):
        allowed = [list, dict, tuple]
        if type(data) in allowed:
            decrypted = type(data)() if type(data) == list or type(data) == dict else list()
            for record in data:
                if type(data) == dict:
                    if type(data[record]) == str:
                        decrypted[record] = self.decrypt(data[record])
                    else:
                        raise TypeError("Can't decrypt data type %s. Expected Str." % type(data(record)))
                elif type(data) == list or type(data) == tuple:
                    if type(record) == str:
                        decrypted.append(self.decrypt(record))
                    else:
                        raise TypeError("Can't decrypt data type %s. Expected Str." % type(record))
            return decrypted
        else:
            raise TypeError("Expected data types %s but got %s" % (allowed, type(data)))