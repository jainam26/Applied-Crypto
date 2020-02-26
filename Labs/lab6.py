#!/usr/bin/env python3
# -*- coding: utf-8 -*-

################################################################## LAB 6 ##################################################################

"""
List you collaborators here:
                                party one 
                                party two...


Your task is to fill in the body of the functions below. The specification of each of the functions is commented out.
"""

import lab6_helper
import os
from Cryptodome.Hash import CMAC
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.backends import default_backend
from Cryptodome.Cipher import AES
from Cryptodome.Util.strxor import strxor

BLOCK_SIZE = 16
def unpadd(msg):
    count = msg[-1]
    msg = msg[:-count]
    return msg
def checkPadding(msg):
    count = msg[-1]
    count_copy = count
    if(count > 16):
        return False
    padding_chars = msg[-count:]
    for chars in padding_chars:
        if(chars == count_copy):
            count = count - 1
    if(count!=0):
        return False
    else:
        return True

def q1_encrypt_mac(enc_key, hmac_key, blob):
    """Question 1: Encrypt-then-MAC

    In Lecture 12, we discussed the difference in behavior between MAC-then-Encrypt 
    and Encrypt-then-MAC. We concluded that the latter was the better way to 
    protect + authenticate data in transit because the former was plagued by the 
    fact that the receiver might try to decrypt data before verifying that it 
    comes from the correct source.

    The scenario:
        In this problem, you will take on the role of Bob. Assume that Alice sends 
        you messages that follow the Encrypt-then-MAC paradigm. 
        That is: Alice first encrypts her messages using AES in CBC mode with 
        PKCS#7 padding, and then she MACs the message using HMAC-SHA1. 

        You (Bob) possess both the `aes-key` and the `hmac-key`.


    Your Task:
        Construct the verify-then-decrypt routine for Bob to use in order to 
        validate and then read messages sent by Alice. You should parse the blob 
        sent by Alice in the following way: 

        the first 16 bytes are the IV for CBC mode, the last 20 bytes are the 
        HMAC-SHA1 tag, and everything in the middle is the CBC ciphertext 
        corresponding to the padded message.

        Your function should return the correct message if it was properly 
        Encrypted-then-MAC'd, or it should output the string 'ERROR' (without the quotes) 
        if there is an issue. (You may assume that Alice will never send you the 
        string ERROR intentionally.)

    Args:
        enc_key     (str):  16-bytes hex-encoded key to be used for AES
        hmac_key    (str):  20-bytes hex-encoded key to be used for HMAC
        blob  (str):  arbitrary-length hex-encoded data (ciphertext)
    Output:
        ret         (str):  ASCII-encoded, unpadded message (or 'ERROR' if there 
                            is a problem with the input blob invalid)           
    Test vectors:
        assert(q1_encrypt_mac(  '7369787465656e2062797465206b6579', 
                                '7477656e74792062797465206c6f6e67206b6579', 
                                (00000000000000000000000000000000a70c430ebf'
                                '35441874ac9f758c59ee10e931378c49507b45b278'
                                'f922db372a682e13bf25')) == 'valid message')

        assert(q1_encrypt_mac(  '7369787465656e2062797465206b6579', 
                                '7477656e74792062797465206c6f6e67206b6579', 
                                ('00000000000000000000000000000000a70c430ebf'
                                '35441874ac9f758c59ee10e931378c49507b45b278'
                                'f922db372a682e13bf34')) == 'ERROR') #1-byte change
    """
    cbc_IV = blob[0:32]
    correctTag = blob[-40:]
    cipherText = blob[32:len(blob)- 40]
    hmac_input = cbc_IV + cipherText
    tag = lab6_helper.hmacsha1(bytes.fromhex(hmac_key),bytes.fromhex(hmac_input))
    if(tag != correctTag):
        return 'ERROR'
    message = b''
    aes_obj = AES.new(bytes.fromhex(enc_key),AES.MODE_CBC,bytes.fromhex(cbc_IV))
    msg = aes_obj.decrypt(bytes.fromhex(cipherText))
    message = message + msg
    if(checkPadding(message)):
        message = unpadd(message)
        decodedMessage = message.decode('ascii')
        return decodedMessage
    else:
        return 'ERROR'

    

def q2_siv_mode_enc(enc_key, mac_key, plaintext, associated_data):
    """Question 2 (part 1): Synthetic Initialization Vector (SIV) Authenticated Encryption

    Your Task:
        Your function should implement the SIV mode for authenticated encryption
        as illustrated in lecture 13. For this implementation, you would have to
        use the AES block cipher in CTR mode, along with CMAC as a MAC.
    Args:
        enc_key         (str):  16-bytes hex-encoded key to be used for AES
        mac_key         (str):  16-bytes hex-encoded key to be used for CMAC
        plaintext       (str):  arbitrary-length ASCII encoded plaintext
        associated_data (str):  arbitrary-length hex-encoded data to be 
                                authenticated, but not encrypted
    Output:
        ret             (str):  hex-encoded, ciphertext formatted as
                                    tag + ciphertext (as shown in Lecture slides)
    Test vectors:
        assert(q2_siv_mode_enc( enc_key="7f7e7d7c7b7a79787776757473727170", 
                        mac_key="404142434445464748494a4b4c4d4e4f",
                        plaintext="this is some plaintext to encrypt using SIV-AES",
                        associated_data = "00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100"
                ) == "2550eb1783787e5f2d4e56fba6dff0a7df554c297854c8c4e4833435e66989314b6b2791862c7d11498c2ef034bfbb63808c73bc5ea23e64cb58a8e1a5775a")
    Note:

        Also Feel free to use componenets from the Cryptodome/cryptography libraries 
        to build this function (ex. `from Crypto.Hash import CMAC`). That being 
        said, you should not use the SIV mode provided by any library, you should 
        combine the building blocks to implement the SIV mode on your own.

        When using the tag as a nonce for the CTR mode, some CTR implementations
        would not allow the nonce to be equal to the block_size (for example, 
        the `Cryptodome.Cipher` class with throw an error when using a nonce
        of size > block_size - 1), so I recommend using the CTR mode provided by
        the library `cryptography` instead 
        (e.g `from cryptography.hazmat.primitives.ciphers import Cipher`).

        Also note that for this implementation, there's no need to clear any bits
        of the tag before using it as a nonce. You can assume that the number of
        blocks we would test against would not overflow the counter bits.
    """
    backend = default_backend()
    cmac_input = bytes.fromhex(associated_data) + plaintext.encode('ascii')
    cobj = CMAC.new(bytes.fromhex(mac_key),ciphermod=AES)
    cobj.update(cmac_input)
    tag = cobj.digest()
    cipher = Cipher(algorithms.AES(bytes.fromhex(enc_key)),modes.CTR(tag),backend)
    encryptor = cipher.encryptor()
    cipherText = encryptor.update(plaintext.encode('ascii'))
    return tag.hex() + cipherText.hex()
def q2_siv_mode_dec(enc_key, mac_key, ciphertext, associated_data):
    """Question 2 (part 2): Synthetic Initialization Vector (SIV) Authenticated Encryption

    Your Task:
        Similar to the first part of this question, your function should decrypt
        the output produced by the function in the first part and return the 
        plaintext if the tag is valid, and return ERROR otherwise.
    Args:
        enc_key         (str):  16-bytes hex-encoded key to be used for AES
        mac_key         (str):  16-bytes hex-encoded key to be used for CMAC
        ciphertext      (str):  arbitrary-length hec-encoded ciphertext (same format
                                as the output of q2_siv_mode_enc)
        associated_data (str):  arbitrary-length hex-encoded data to be 
                                authenticated, but not encrypted
    Output:
        ret             (str):  ASCII-encoded, plaintext (or 'ERROR')
    Test vectors:
        Use the same test case provided in part 1 of this question.
    """
    backend = default_backend()
    tag = ciphertext[:32]
    cipherMessage = ciphertext[32:]
    cipher = Cipher(algorithms.AES(bytes.fromhex(enc_key)),modes.CTR(bytes.fromhex(tag)),backend)
    decryptor = cipher.decryptor()
    message = decryptor.update(bytes.fromhex(cipherMessage))
    cmac_input = bytes.fromhex(associated_data) + message
    cobj = CMAC.new(bytes.fromhex(mac_key),ciphermod=AES)
    cobj.update(cmac_input)
    ComputedTag = cobj.hexdigest()
    if(tag != ComputedTag):
        return 'ERROR'
    else:
        return message.decode('ascii')



def q3_block_cipher_timing_attack(leaky_encipher=lab6_helper.leaky_encipher_example):
    """Question 3: Collision timing attack on AES

    Your Task:
        In this function, we'll perform a first round timing attack on AES. This
        attack is different from the one in the last lab since you will be trying
        to extract the enciphering key used by only observing the number of colliding
        bytes by timing the cache when performing the S-Box substitutions on the 
        first round of AES.

        The routine 'leaky_encipher' can be used to query the number of distinct
        bytes of the internal state after the first round of substitutions that
        AES performs, the routine also returns the final ciphertext produced by
        AES on the given plaintext (using a secret key).

        For example (using 4-bytes as an example, the routine handles 
            16-bytes state values), this is how `leaky_encipher` would work:
            internal_state="01 02 03 04" -> 4
            internal_state="01 01 03 04" -> 3
            internal_state="01 01 01 04" -> 2
            internal_state="01 01 01 01" -> 1
    Args:
        leaky_encipher  (func)  : performs an AES encipher on a 16-bytes input
                                    (check lab6_helper.leaky_encipher_example 
                                        for more details)
    Output:
        ret             (str)   : hex-encoded 16-bytes string that represents
                                    the secret key used in leaky_encipher.
    How to verify your answer:
        assert(q3_block_cipher_timing_attack() == lab5_helper.TEST_KEY)
    """
    key_xors = []
    averages = {}
    distinct_vals = []
    for i in range(0,256):
        for _ in range(0,50):
            result = leaky_encipher(b'0'+bytes([i])+os.urandom(14))
            distinct_vals.append(result[0])
        averages[i] = (sum(distinct_vals)/len(distinct_vals)) 
        distinct_vals.clear()
    min_val = min(averages.values())
    for x,y in averages.items():
        if y == min_val:
            key_xors.append(x)
    averages.clear()
    for j in range(1,15):
        for i in range(0,256):
            for _ in range(0,50):
                result = leaky_encipher(b'0'+os.urandom(j)+bytes([i])+os.urandom(16-2-j))
                distinct_vals.append(result[0])
            averages[i] = (sum(distinct_vals)/len(distinct_vals)) 
            distinct_vals.clear()
        min_val = min(averages.values())
        for x,y in averages.items():
            if y == min_val:
                key_xors.append(x)
        averages.clear()
    print(key_xors)
    possible_keys = []
    k_0 = 0
    distinct_vals.append(0)
    for vals in key_xors:
        output = vals ^ k_0
        distinct_vals.append(output)
    print(len(distinct_vals))          
q3_block_cipher_timing_attack()