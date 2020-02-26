#!/usr/bin/env python3
# -*- coding: utf-8 -*-

################################################################## LAB 2 ##################################################################

"""
List you collaborators here:
                                Jainam Shah


Your task is to fill in the body of the functions below. The specification of each of the functions is commented out, and an example test case is provided for your convenience.
"""
# Feel free to use either of `AES` or `Fernet` below
from Cryptodome.Cipher import AES
import binascii

def aes_encipher(key, plaintext):
    """Performs an AES encipher on the input "plaintext" using the default ECB mode.
    Args:
        key (str): hex-encoded string of length 16-bytes (default AES block input size).
        plaintext (str): hex-encoded string of length 16 bytes (default AES block input size).

    Returns:
        str: The ciphertext output as a hex-encoded string

    Note:
        One thing you'll find in cryptography is that tests are your friend. Granted, unit tests are important in all of software 
        development, but cryptography has two properties that make testing even more important still:
            -   The output of any cryptosystem is supposed to look random. So spot-checking the output won't help you to distinguish 
                whether it was implemented correctly or not.
            -   It is essential that your implementation interoperate with everybody else's implementation of the same cipher, 
                so that Alice and Bob can produce the same results when one of them uses your code and the other uses someone else's code. 
                Ergo, it is important that everybody follows the cipher designers' spec exactly, even down to low-level details like whether strings 
                follow big or little endianness. (Note: if you don't know what `endianness' means, just ignore that last comment.)
        For this question, here are some test vectors you can use. I provide an AES-128 key (16 bytes long) and a plaintext (16 bytes long) along with 
        the associated 16-byte ciphertext for the plaintext.

    Test vectors:
        aes_encipher(key = "00000000000000000000000000000000", plaintext = "f34481ec3cc627bacd5dc3fb08f273e6") == "0336763e966d92595a567cc9ce537f5e"
        aes_encipher(key = "00000000000000000000000000000000", plaintext = "9798c4640bad75c7c3227db910174e72") == "a9a1631bf4996954ebc093957b234589"
        aes_encipher(key = "00000000000000000000000000000000", plaintext = "96ab5c2ff612d9dfaae8c31f30c42168") == "ff4f8391a6a40ca5b25d23bedd44a597"
    """
    encodedKey = binascii.unhexlify(key)
    encodedPlaintext = binascii.unhexlify(plaintext)
    aesCipher = AES.new(encodedKey,AES.MODE_ECB)
    cipherText = aesCipher.encrypt(encodedPlaintext)
    cipherText = cipherText.hex()
    return cipherText


def find_key(plaintext, ciphertext):
    """Given a plaintext and a ciphertext, find the 16-bytes key that was used under AES (ECB mode, just like in `aes_encipher`) to produce the given ciphertext. 

    Args:
        plaintext (str): hex-encoded string of length 16 bytes.
        ciphertext (str): hex-encoded string of length 16 bytes.

    Returns:
        str: hex-encoded 16-bytes key used to produce 'ciphertext' given 'plaintext' under AES (ECB-mode)
    
    Note:
        Keep in mind that AES keys are 128-bits (16 bytes), and you should assume for this question that the first **108-bits** of the AES key are all zeros.

    Hint:
        Use brute-force!

    Examples:
        find_key(plaintext = "f34481ec3cc627bacd5dc3fb08f273e6", ciphertext = "3ed20de893c03d47c6d24f09cb8a7fd2") ==  "00000000000000000000000000000001"
        find_key(plaintext = "f34481ec3cc627bacd5dc3fb08f273e6", ciphertext = "ac021ba807067a148456ffb140cd485f") ==  "0000000000000000000000000000d7f6"
        find_key(plaintext = "f34481ec3cc627bacd5dc3fb08f273e6", ciphertext = "78e7e91df1a6792fce896e3e1925461d") ==  "0000000000000000000000000001dae9"
    """
    encodedPlainTxt = binascii.unhexlify(plaintext)
    encodedCipherTxt = binascii.unhexlify(ciphertext)
    allKeys = [0] * 0x100000
    for i in range(0, 0x100000):
	    allKeys[i] =  hex(i)[2:].zfill(32)
    print(allKeys)
    for key in allKeys:
        candidate_key = binascii.unhexlify(key)
        aesDecoder = AES.new(candidate_key,AES.MODE_ECB)
        if encodedPlainTxt == aesDecoder.decrypt(encodedCipherTxt):
            return key
    
commonWordList = ['the','be','to','of','and','a','in','that','have','I','it','for','not','on','with','he','as','you','do','at','this','but','his','by','from','they','we','say','here','she','or',
    'an','will','my','one','all','would','there','their','what','so','up','out','if','about','who','get','which','go','me','when','make','can','like','time','no','just','him','know','take','people',
    'into','year','your','good','some','could','them','see','other','than','then','now','look','only','come','its','over','think','also','back','after','use','two','how','our','work','first','well',
    'way','even','new','want','because','any','these','give','day','most','us']

"""the check functions simply xors the candidate string that we pass with the xor(c1,c2) and determnies if
if the ASCII of the resulting characters of the string is part of the commonword list """
def check(string,xord):
    print(string)
    if len(string) > len(xord):
            return False
    if len(string) == len(xord):
        complete = True
    else:
        complete = False
    new_string = ''.join([chr(ord(string[i]) ^ xord[i]) for i in range(len(string))])
    print(new_string)
    words = new_string.split()
    print(words)
    if not complete:
        for word in words[:-1]:# by doing this i don't wait for the string to be constructed fully. i check it partially and the last word which i get could be a part of another word.
            if not word in commonWordList:
                return False
        last = words[-1]
        for test in commonWordList:
            if test.startswith(last):
                return True
        return False
    else:
        for word in words:
            if not word in commonWordList:
                return False
        return True
""" the construct funtion contains the words that are valid uptill now .For possible sentences it will call the function check
that will only return true if words we passed and the xor of it with the xor(c1,c2) is part of the list
if it returns true then the constrcut function will call itself again meaning that it should proceed 
ahead by creating a possisble candidate substring by adding the previously matched to a new string.
If the check returns false then it means that the we should not search further since none of the characters are part of the list """
def construct(prefix,xord): 
    if len(prefix) == len(xord):
        return prefix 
    for word in commonWordList:
        word = word.lower()
        if prefix != "":
            new_word = prefix + " " + word
        else:
            new_word = word
        if (check(new_word,xord)): 
            res = construct(new_word,xord)
            if res != None:
                return res
    if prefix == "":
        for word in commonWordList:
            word = word.lower().capitalize()
            new_word = word
            if(check(new_word,xord)):
                res = construct(new_word,xord)
                if res != None:
                    return res
    return None

def two_time_pad():
    """A one-time pad simply involves the xor of a message with a key to produce a ciphertext: c = m ^ k.
        It is essential that the key be as long as the message, or in other words that the key not be repeated for two distinct message blocks.

    Your task:
        In this problem you will break a cipher when the one-time pad is re-used.
        c_1 = 3801025f45561a49131a1e180702
        c_2 = 07010051455001060e551c571106
        These are two hex-encoded ciphertexts that were formed by applying a “one-time pad” to two different messages with 
        the same key. Find the two corresponding messages m_1 and m_2.
    
    Okay, to make your search simpler, let me lay out a few ground rules. First, every character in the text is either 
    a lowercase letter or a space, aside from perhaps the first character in the first message which might be capitalized. 
    As a consequence, no punctuation appears in the messages. Second, the messages consist of English words in ASCII. 
    Finally, all of the words within each message is guaranteed to come from the set of the 100 most 
    common English words: https://en.wikipedia.org/wiki/Most_common_words_in_English.

    Returns:
        Output the concatenation of strings m_1 and m_2. (Don't worry if words get smashed together as a result.)
    """
    c_1 = '3801025f45561a49131a1e180702'
    c_2 = '07010051455001060e551c571106'
    # converting the hexadecimal representaiton to integers for every 2 bytes since it xor operations become on integers 
    c_1_int = [int(c_1[i] + c_1[i+1], 16) for i in range(0, len(c_1), 2)] 
    c_2_int = [int(c_2[i] + c_2[i+1], 16) for i in range(0, len(c_1), 2)]
    xord = [c_1_int[i] ^ c_2_int[i] for i in range(len(c_1_int))] #xor of the two lists which are integer representations 
    result = construct('',xord)
    if result == None:
        return None
    else: 
        print(result)
        new_string = ''.join([chr(ord(result[i]) ^ xord[i]) for i in range(len(result))])
        return new_string + result
# f1 = two_time_pad()
# print(f1)

# ans = find_key("f34481ec3cc627bacd5dc3fb08f273e6","3ed20de893c03d47c6d24f09cb8a7fd2")
# print(ans)