#!/usr/bin/env python3
# -*- coding: utf-8 -*-


################################################################## LAB 4 ##################################################################

"""
List you collaborators here:
                    NA

Your task is to fill in the body of the functions below. The specification of each of the functions is commented out.
"""
import math
from binascii import hexlify,unhexlify
from Cryptodome.Util.strxor import strxor
from sample_cipher import Sample_Cipher
from Cryptodome.Cipher import AES
import string,random,ast


def padding(msg,value):
    if len(msg) % value == 0:
        bytesTopPad = value
        complete_block_padding = chr(bytesTopPad)
        for _ in range(0,bytesTopPad):
            msg += complete_block_padding
    else:
        numberOfBlocks = math.ceil(len(msg)/value)
        bytesTopad = (value * numberOfBlocks) - len(msg)
        partial_block_padding = chr(bytesTopad)
        for _ in range(0,bytesTopad):
            msg += partial_block_padding
    return msg
def unpadd(msg):
    count = ord(msg[-1])
    msg = msg[:-count]
    return msg

def q1_enc_cbc_mode(key, message, iv, cipher=Sample_Cipher):
    """Question 1 (part 1): Implement CBC Mode encryption (with PKCS#7 padding, using the provided block cipher `cipher`)

        Before starting to implement this function, take a look at the CBC mode in the lecture slides. Also note that
        your CBC mode implementation should accept an arbitrary length message, and should pad the message according to the block
        size of the `cipher` method provided (cipher.BLOCK_SIZE).

        For the padding scheme, we will use the PKCS#7 standard. The PKCS#7 padding standard is a common method to pad messages 
        to a multiple of the block length. Let's take AES as an example, in which case the block length is 16 bytes.

        Given a string `s` that is n bytes short of being a multiple of the block length, PKCS#7 padding simply adds n bytes each 
        of which have the byte value n. 
        For instance, the string
            `TEST STRING`
        is 11 characters long and thus needs 5 bytes of padding. So, it gets padded to the string:
            `TEST STRING\x05\x05\x05\x05\x05`

        Here, the "\x05" denotes the byte value 5 in hex form (this is valid Python syntax, by the way).
        If we choose to use padding, then we must **always** do so because the person on the other end of the wire is 
        planning to remove the padding. In particular, if the string length is already a multiple of the block length, 
        then we must add a new block and fill it with padding.
        For instance, the 16-byte string
            `A COMPLETE BLOCK`
        gets PKCS#7 padded to the following 32-byte string:
            `A COMPLETE BLOCK\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10`
        where "\x10" denotes the hex value 10 (i.e., decimal value 16, the block length).

        I recommend implementing the following methods first to help you implement the CBC mode
            - `pad(msg, block_size)`
                should take an input of arbitrary length and return a padded string based on the block_size 
                and following the PKCS#7 standard.
            - `unpad(padded_msg, block_size)`
                should remove the padding from the padded_msg and return the original un-padded message.
            You can use the examples above as test vectors for your padding implementation
    Your Task:
        This question has two parts, part one is the function `q1_enc_cbc_mode` that encrypts message under CBC, and the
        function `q1_dec_cbc_mode` that decrypts under CBC.
    Args:
        key     (str):      hex-encoded string (cipher.BLOCK_SIZE-bytes long)
        message (str):      ascii input string with an arbitrary length
        iv      (str):      hex-encoded string of an IV that should be used for the CBC encryption (cipher.BLOCK_SIZE long)
        cipher  (Cipher):   Cipher class (check `sample_cipher.py`) that provides access to a sample block cipher.
                                +   cipher.encipher(key, message)
    Output:
        ret     (str):  hex-encoded ciphertext (don't return the IV as part of the ciphertext)
    Test vectors:
        q1_enc_cbc_mode(key="a8c0eeef71c4f0ad7942cb2eefb0dff0", message="w)0EA@W`j-3O~FhxwS~OixkV$D<2'v[apPoW[", iv="45054c1d141b6ae136b45c37800c7840", cipher=Sample_Cipher()) == "100ea146471f4ddc46fb829f6d9d5518229e2961bece0661d61656c2e989e157856b2cda53b8a46b308d5bba38934961"
        q1_enc_cbc_mode(key="68cf01cdb03ca97d1312b9e106c64ab4", message=",}54KK:'W,X-LAQ6P\/%aw70>~{Om~sqPu!_S=PeUlSx{_ID-&lcc\_RqgcFY|aeS", iv="8bdcc6f47a583fdf18d14dbac639bc6a", cipher=Sample_Cipher()) == "e250881abc2938ea59cd28d96268162f3fe125448c968d2181203e1407b65f33adf66a3b18b43b6fd54af1bcdcd3009af30fc4e7af741474ba67484eea3fbb07804575f27a9c9e1237c802011784f1d1"
        q1_enc_cbc_mode(key="77ea003e2f1c5911af304ac2faa638cc", message="g@$Q?qX(YK*Zqp`C>z0|4<ZeCzUuF$6Bhbk?|k%?Xoc%F[dxb|6ix=QYoL)8.,;E", iv="922687e8d2e82ef1bc11b5dab6e7913b", cipher=Sample_Cipher()) == "648e0a290a8b4cf9793249eedd61e541af988041ad7edd4c858cfb0915b7d1469020e937941d6bbbef56ffea29706545e0a49eee01f7a21cbad59408ae8b0b8760b219849d13b0b5c4d6c195e1811ef5"
    """
    final_cipher = ''
    paddedMsg = padding(message,cipher.BLOCK_SIZE)
    blocksToPad = [paddedMsg[i:i+cipher.BLOCK_SIZE] for i in range(0,len(paddedMsg),cipher.BLOCK_SIZE)]
    intermediate_state = strxor(blocksToPad[0].encode('ascii'),bytes.fromhex(iv))
    cipherText = cipher.encipher(key,intermediate_state.hex())
    final_cipher += cipherText
    for byte in blocksToPad[1:]:
        intermediate_state = strxor(bytes.fromhex(cipherText),byte.encode('ascii'))
        cipherText = cipher.encipher(key,intermediate_state.hex())
        final_cipher += cipherText
    return final_cipher


def q1_dec_cbc_mode(key, ciphertext, iv, cipher=Sample_Cipher):
    """Question 1 (part 2): Implement CBC Mode **decryption** (with PKCS#7 padding, using the provided block cipher `cipher`)

    Your Task:
        The problem description is similar to the one in the previous problem, just note the different inputs and expected outputs

    Args:
        key         (str):      hex-encoded string (cipher.BLOCK_SIZE-bytes long)
        ciphertext  (str):      hex-encoded ciphertext (multiple cipher.BLOCK_SIZE-bytes long)
        iv          (str):      hex-encoded string of an IV that should be used for the CBC decryption (cipher.BLOCK_SIZE-bytes long)
        cipher      (Cipher):   Cipher class (check `sample_cipher.py`) that provides access to a sample block cipher.
                                +   cipher.decipher(key, ciphertext)
    Output:
        ret     (str):          ascii output string with an arbitrary length (with the padding removed)
    Test vectors:
        You can use the same test vectors from `q1_enc_cbc_mode` in the reverse order to double check your solution
    """
    message = []
    blocksToDecrypt = [ciphertext[i:i+cipher.BLOCK_SIZE*2] for i in range(0,len(ciphertext),cipher.BLOCK_SIZE*2)]
    prev_cipher = blocksToDecrypt[0]
    temp_value = cipher.decipher(key,prev_cipher)
    m1 = strxor(bytes.fromhex(iv),bytes.fromhex(temp_value))
    message.append(m1.decode())
    for byte in blocksToDecrypt[1:]:
        temp_value = cipher.decipher(key,byte)
        m1 = strxor(bytes.fromhex(temp_value),bytes.fromhex(prev_cipher))
        message.append(m1.decode())
        prev_cipher = byte
    message[len(message)-1] = unpadd(message[len(message)-1])
    return ''.join(message)




def q2_enc_ctr_mode(key, message, nonce, cipher=Sample_Cipher):
    """Question 2 (part 1): Implement Counter (CTR) Mode encryption (using the provided block cipher `cipher`)

    Your Task:
        Before starting to implement this function, take a look at the CTR mode in the lecture slides. This question has two parts, 
        part one is the function `q2_enc_ctr_mode` that encrypts under CTR, and the function `q2_dec_ctr_mode` that decrypts under CTR.     
    Note:
        You can assume that the BLOCK_SIZE is at least 4 bytes, so the nonce you get as an input will always have a length
        of 4 bytes less than the BLOCK_SIZE of the cipher given. So make sure to append a counter of size 4 bytes to your nonce
        when using it. You can also assume that we would never  the counter to go up to UINT32_MAX (0xFFFFFFFF).    
    Args:
        key     (str):      hex-encoded string (cipher.BLOCK_SIZE-bytes long)
        message (str):      ascii input string with an arbitrary length
        nonce   (str):      hex-encoded string of a nonce that should be used for the CTR encryption (cipher.BLOCK_SIZE - 4bytes long)
        cipher  (Cipher):   Cipher class (check `sample_cipher.py`) that provides access to a sample block cipher.
                                +   cipher.encipher(key, message)
    Output:
        ret     (str):  hex-encoded ciphertext (arbitrary length)
    Test vectors:
        q2_enc_ctr_mode(key="99cd2b776f71f87e87c8cb9ccf8bcbe4", message=":.DU|C61RtcUj[km)<6", nonce="fd7ed96cbfa3f7369a964fee", cipher=Sample_Cipher()) == "e08ee68d6387b81d71e4f7892fedbfe0f39c94"
        q2_enc_ctr_mode(key="88d1104f7bd5661768ac72f3d5a453b7", message="u+V[nN#m0YLwOuKp%u!:@5|e4v]22'ukkx};(_,cdm5>5VZsmqE7)W(O-&/!Y?lhhF", nonce="5633e2712a3684784cf1a6c5", cipher=Sample_Cipher()) == "e062cfa6c48addd26eb976819998f56eb03cb8c7eaf182da6a9667c4e4cacb92fe31e4c6829bd2dc3a8d0fc8e3bbe411f838dcca8393d6f073c615d78fd2d252fd0f"
        q2_enc_ctr_mode(key="2e7d7d855f802fcf06166adc10650c79", message="I6IC$d|Tb|5H~^7.U9:<N!Y}y6$M_i;)", nonce="4709acbfea6811fb62379f13", cipher=Sample_Cipher()) == "9ed90a46ae7fe1832797b91ea476c5e182d67939c43ac4aa3cdda81b8541c9ec"
    """
    cipherText = ''
    nonce_ = unhexlify(nonce)
    blocksToEncrypt = [message[i:i+cipher.BLOCK_SIZE] for i in range(0,len(message),cipher.BLOCK_SIZE)]
    counter = 0
    for byte in blocksToEncrypt:
        counter_byte = counter.to_bytes(4,'big')
        nonce_counter = nonce_ + counter_byte
        intermediate_val = cipher.encipher(key,nonce_counter.hex())
        encodedMessageBlock = byte.encode('ascii')
        x  = strxor(bytes.fromhex(intermediate_val)[:len(encodedMessageBlock)],encodedMessageBlock)
        cipherText = cipherText + x.hex()
        counter = counter + 1
    return cipherText
    # counter = 0
    # counter_byte = counter.to_bytes(4,'little')
    # nonce_ = unhexlify(nonce)
    # nonce_counter = nonce_ + counter_byte
    # i1 = cipher.encipher(key,nonce_counter.hex())
    # message_block1 = message[:16].encode('ascii')
    # c1 = strxor(bytes.fromhex(i1)[:len(message_block1)],message_block1)
    # print(c1.hex())
    # counter = 1
    # counter_byte = counter.to_bytes(4,'little')
    # nonce_counter = nonce_ + counter_byte
    # i2 = cipher.encipher(key,nonce_counter.hex())
    # message_block2 = message[16:].encode('ascii')
    # c2 = strxor(bytes.fromhex(i2)[:len(message_block2)],message_block2)
    # print(c2.hex())
def q2_dec_ctr_mode(key, ciphertext, nonce, cipher=Sample_Cipher):
    """Question 2 (part 2): Implement Counter (CTR) Mode **decryption** (using the provided block cipher `cipher`)

    Your Task:
        The problem description is similar to the one in the previous problem, just note the different inputs and expected outputs
    Args:
        key         (str):      hex-encoded string (cipher.BLOCK_SIZE-bytes long)
        ciphertext  (str):      hex-encoded ciphertext (arbitrary length)
        nonce       (str):      hex-encoded string of a nonce that should be used for the CTR decryption (cipher.BLOCK_SIZE - 4bytes long)
        cipher      (Cipher):   Cipher class (check `sample_cipher.py`) that provides access to a sample block cipher.
                                    +   cipher.encipher(key, ciphertext)
    Output:
        ret     (str):          ascii output string with an arbitrary length
    Test vectors:
        You can use the same test vectors from `q2_enc_ctr_mode` in the reverse order to double check your solution
    """
    nonce_ = unhexlify(nonce)
    counter = 0
    message = []
    blocksToDecrypt = [ciphertext[i:i+cipher.BLOCK_SIZE*2] for i in range(0,len(ciphertext),cipher.BLOCK_SIZE*2)]
    for byte in blocksToDecrypt:
        counter_byte = counter.to_bytes(4,'big')
        nonce_counter = nonce_ + counter_byte
        intermediate_val = cipher.encipher(key,nonce_counter.hex())
        m = strxor(bytes.fromhex(intermediate_val)[:len(unhexlify(byte))],bytes.fromhex(byte))
        message.append(m.decode())
        counter = counter + 1
    return ''.join(message)
def isPrintable(m):
    for c in m:
        if chr(c) not in string.printable:
            return False
    return True
def message_generator(size):
    return ''.join(random.choice(string.printable) for _ in range(size))

def is_valid_python(code):
    try:
        ast.parse(code)
    except SyntaxError:
        return False
    return True

def q3_break_cbc_mac():
    """Question 3: Break CBC-MAC if used as a hash function

        In this question, You will show that CBC-MAC will fail 
        catastrophically if used as a hash function rather than as a MAC. 
        To explain the underlying issue, I reproduce a quote from the blog of 
        Prof. Matt Green at Johns Hopkins:
            "Cryptographic hash functions are public functions (i.e., no secret key) 
            that have the property of collision-resistance (it's hard to find two messages with the same hash). 
            MACs are keyed functions that (typically) provide message unforgeability -- a very different property. 
            Moreover, they guarantee this only when the key is secret."

        Let's make a (broken) hash function using CBC-MAC with a hardcoded key 'very secret key!'
            K = 'very secret key!'     # key is fixed and public
            def hash_from_cbcmac(M):
                return cbcmac(K, M)    # run CBC-MAC using this key

    Your Task:
            To solve this question, you probably need to revisit your CBC-MAC implementation
            from the previous lab and modify it to use AES (ECB-mode) as the block cipher (instead of `TOY`).

            Then, show that the hash function is broken by finding two colliding messages.
            Hmm, wait, that's too easy, and this is the final question of the lab. 
            So, let me make the question harder in a couple of ways. 

            First, rather than letting you choose the two messages, I'm going to fix one of 
            them for you. Ergo, you'll break the **second preimage resistance** game rather 
            than the **collision resistance** game. 

            Specifically: I'm going to choose the following message: 
                `msg = 'print("CBC-MAC is a very strong hash function!")'`

            Second, I want you to produce a collision that actually has some semantic value. 
            Observe that the original message is a valid Python3 program that can be executed 
            via the command `exec(msg)`. I want your collision to do the same.
    Your output:
            A string `collision` that simultaneously satisfies the following 5 properties.
                1. The `collision` string is exactly 3 blocks (aka 48 bytes) long.
                2. Its hash equals the following: `hash_from_cbcmac(msg) == hash_from_cbcmac(collision)`.
                3. The `collision` string contains only printable ASCII characters (i.e., characters in `string.printable`).
                4. The `collision` string is valid Python3 syntax.
                5. When executed via the command `exec(collision)`, the following text is printed to the terminal: "CBC-MAC not a hash"

            If you cannot find a string that simultaneously satisfies all 5 properties, then simply go as far down the list 
            of properties as you can for partial credit. Because there are multiple valid answers to this question, 
            I cannot provide any test vectors to you.

            Note that you only need to find **one** valid answer.
    """
    key = b'very secret key!'
    message = 'print("CBC-MAC is a very strong hash function!")'
    blocksToEncrypt = [message[i:i+16] for i in range(0,len(message),16)]
    cipherTexts = []
    intermediate_states = []
    cobj = AES.new(key,AES.MODE_ECB)
    x = cobj.encrypt(blocksToEncrypt[0].encode())
    x = x.hex()
    cipherTexts.append(x)
    for byte in blocksToEncrypt[1:]:
        y = strxor(unhexlify(x),byte.encode('ascii')).hex()
        intermediate_states.append(y)
        x = cobj.encrypt(unhexlify(y))
        x = x.hex()
        cipherTexts.append(x)
    X = bytes.fromhex(intermediate_states[1])
    while(True):
        randomMessage = message_generator(4)
        collisionMessage = "print('CBC-MAC not a hash')#"
        collisionMessage += randomMessage
        collision_blocks = [collisionMessage[i:i+16] for i in range(0,len(collisionMessage),16)]
        col_x = cobj.encrypt(collision_blocks[0].encode())
        col_y = strxor(col_x,collision_blocks[1].encode('ascii'))
        col_x = cobj.encrypt(col_y)
        Y = col_x
        message3 = strxor(X,Y)
        if isPrintable(message3):
            #print (randomMessage)
            #print (message3.decode('ascii'))
            message = collisionMessage + message3.decode('ascii')
            if is_valid_python(message):
                return message
f1 = q1_enc_cbc_mode("7369787465656e2062797465206b6579","valid message","00000000000000000000000000000000",Sample_Cipher())
print(f1,len(f1))
#f2 = q1_dec_cbc_mode("74deb9f94977bcfeac492e5b399a5c0c","299a3db5782acbd04cdddcda8f55efc8","cd32ccc8339ec87e7eec2ccc46c31182",Sample_Cipher())
#f3 = q2_enc_ctr_mode("88d1104f7bd5661768ac72f3d5a453b7","u+V[nN#m0YLwOuKp%u!:@5|e4v]22'ukkx};(_,cdm5>5VZsmqE7)W(O-&/!Y?lhhF","5633e2712a3684784cf1a6c5",Sample_Cipher())
#f4 = q2_dec_ctr_mode("7b2937e962319e03aec2d26c8d681e06","1bb8c0d40626a7","a5466611ff4369a8267ebd60",Sample_Cipher())
# f5 = q3_break_cbc_mac()
# print(f5)