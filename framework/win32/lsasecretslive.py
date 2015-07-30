# This file is part of creddump.
#
# creddump is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# creddump is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with creddump.  If not, see <http://www.gnu.org/licenses/>.

"""
@author:       Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      bdolangavitt@wesleyan.edu
"""

# Modified by pentestmonkey

from framework.win32.hashdumplive import get_bootkey,str_to_key
from Crypto.Hash import MD5,SHA256
from Crypto.Cipher import ARC4,DES,AES
from struct import unpack,pack
from wpc.regkey import regkey
from binascii import hexlify
xp = None


def get_lsa_key(bootkey):
    global xp
    r = regkey("HKEY_LOCAL_MACHINE\\SECURITY\\Policy\\PolSecretEncryptionKey")
	
    if r.is_present():
		xp = 1
    else:
		r = regkey("HKEY_LOCAL_MACHINE\\SECURITY\\Policy\\PolEKList")
		if r.is_present:
			xp = 0
		else:
			return None

    obf_lsa_key = r.get_value("")
    if not obf_lsa_key:
        return None

    if xp:
	    md5 = MD5.new()
	    md5.update(bootkey)
	    for i in range(1000):
	        md5.update(obf_lsa_key[60:76])
	    rc4key = md5.digest()
	
	    rc4 = ARC4.new(rc4key)
	    lsa_key = rc4.decrypt(obf_lsa_key[12:60])
	    return lsa_key[0x10:0x20]
    else:
		lsa_key = decrypt_lsa(obf_lsa_key, bootkey)
		return lsa_key[68:100]


def decrypt_secret(secret, key):
	    """Python implementation of SystemFunction005.

	    Decrypts a block of data with DES using given key.
	    Note that key can be longer than 7 bytes."""
	    decrypted_data = ''
	    j = 0   # key index
	    for i in range(0,len(secret),8):
	        enc_block = secret[i:i+8]
	        block_key = key[j:j+7]
	        des_key = str_to_key(block_key)
	        des = DES.new(des_key, DES.MODE_ECB)
	        decrypted_data += des.decrypt(enc_block)
	        
	        j += 7
	        if len(key[j:j+7]) < 7:
	            j = len(key[j:j+7])
	
	    (dec_data_len,) = unpack("<L", decrypted_data[:4])
	    return decrypted_data[8:8+dec_data_len]

def decrypt_lsa(ciphertext, bootkey):
	# vista+
	sha256 = SHA256.new()
	sha256.update(bootkey)
	for i in range(1000):
		sha256.update(ciphertext[28:60])
	aeskey = sha256.digest()

	aes = AES.new(aeskey, AES.MODE_ECB)
	cleartext = aes.decrypt(ciphertext[60:len(ciphertext)])

	return cleartext

def decrypt_lsa2(ciphertext, bootkey):
	ciphertext2 = decrypt_lsa(ciphertext, bootkey)

	(length,) = unpack("<L", ciphertext2[:4])
	return ciphertext2[16:16+length]

def get_secret_by_name(name, lsakey):
    global xp
    r = regkey("HKEY_LOCAL_MACHINE\\SECURITY\\Policy\\Secrets\\%s\\CurrVal" % name)
    if not r.is_present():
        return None

    enc_secret = r.get_value("")

    if xp:
		encryptedSecretSize = unpack('<I', enc_secret[:4])[0]
		offset = len(enc_secret)-encryptedSecretSize
		secret = decrypt_secret(enc_secret[offset:], lsakey)
		return decrypt_secret(enc_secret[0xC:], lsakey)
    else:
		return decrypt_lsa2(enc_secret, lsakey)

def get_secrets():
    global xp
    bootkey = get_bootkey()
    lsakey = get_lsa_key(bootkey)
    r = regkey("HKEY_LOCAL_MACHINE\\SECURITY\\Policy\\Secrets")
    if not r.is_present:
        print "[E] Secrets key not accessible: HKEY_LOCAL_MACHINE\\SECURITY\\Policy\\Secrets"
        return None
    
    secrets = {}
    for service_key in r.get_subkeys():
			service_name = service_key.get_name().split("\\")[-1]
			skey = regkey(service_key.get_name() + "\\CurrVal")
			enc_secret = skey.get_value("")
			if not enc_secret:
				continue
			
			if xp:
					encryptedSecretSize = unpack('<I', enc_secret[:4])[0]
					offset = len(enc_secret)-encryptedSecretSize
					secret = decrypt_secret(enc_secret[offset:], lsakey)
			else:
					secret = decrypt_lsa2(enc_secret, lsakey)
			secrets[service_name] = secret

    return secrets

def get_live_secrets():
    return get_secrets()
