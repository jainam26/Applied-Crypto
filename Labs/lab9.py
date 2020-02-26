#!/usr/bin/env python3
# -*- coding: utf-8 -*-

################################################################## LAB 9 ##################################################################

"""
List you collaborators here:
                                party one 
                                party two...


Your task is to fill in the body of the functions below. The specification of each of the functions is commented out.
"""
import lab9_helper
from Cryptodome.Hash import SHA256
from Cryptodome.Hash import HMAC

def q1_break_ecdsa(n, sig1, sig2):
    """Question 1: Breaking (EC)DSA with poor randomness

    The Digital Signature Algorithm (DSA) operates similarly to the Schnorr 
    signature algorithm we discussed in class. 
    
    Like most public key signature algorithms,
    DSA is (1) randomized and (2) incredibly fragile against reuse of the 
    randomness, breaking completely and yielding the key when this occurs. 

    The DRM underlying the Sony Playstation 3 was cracked due to this mistake.

    Your objective:
        Solve the problem listed at https://id0-rsa.pub/problem/17/.
        Note that `n` is the modulus used in the problem, and `z1` and `z2` 
        are the *hashes* of the messages, not just the messages themselves. 

        The ePrint paper linked in the problem statement may be of value to you.

    Your Task:
        Complete the function below to return the secret key used, given two 
        signatures under the same nonce.

        For full credits, your solution should work with any *bad* signatures
        provided to this function.
    
    Args:
        n     (int)                   : the modulus used to generate the 
                                        signatures
        sig1  (lab9_helper.Signature) : First signature (z, s, r)
        sig2  (lab9_helper.Signature) : Second signature (z, s, r)
    
    Output:
        ret         (str)       :   Hex-encoded DSA key used to generate the 
                                    signatures.
    
    How to verify your solution:
        Use the submission box at the bottom of https://id0-rsa.pub/problem/17/ 
        to validate the shared nonce. (Note that the nonce is *different* than 
        the DSA key that I am requiring you to output, although once you have 
        one then you should easily be able to compute the other.)
    """
    


def q2_symmetric_ratchet(init_chain_key, msg_n):
    """Question 2: Symmetric Ratchet System
    
    As discussed in lecture 16, ratching is a technique used to "evolve"
    encryption keys in a cryptographic system. One common approach to key ratching
    is by using Hash functions. More specifically, ratching is done using a Key
    Derivation Function (KDF) that uses hashing internally to evolve the secret
    keys.

    The message keys generated with ratching are then used to perform various
    symmetric cryptographical operations. For that reason, the length of the
    message key is usually the same as the block size of the Block cipher used
    (for example, it will be 16 bytes if AES is used).

    Your Task:
        Simulate a Symmetric Ratchet System using HMAC-SHA2 as your KDF function.
        Your function will take an initial chain key, along with the message 
        number msg_n, and then compute the corresponding message-key (of length
        16 bytes) of the msg_n'th message in the key chain.

    Notes:
        You can assume that msg_n is >= 1, where 1 corresponds to the first
        derived key after one iteration of the KDF.

        Also to bootstrap your derivation logic, you should use 16-bytes of zeros 
        as the msg_key along with the initial chain key to derive the first keys 
        of the chain.

        When handling the output of your KDF function, make sure the last half
        (16-bytes) are used as the msg_key, the rest of the bytes should be used 
        as your new chain_key.

    Args:
        init_chain_key  (str):  Hex-encoded `block_size` bytes key to be used 
                                as the initial chain key.
        msg_n           (int):  The order number of the message for which the
                                key should be generated. 
                                ** Please keep in mind that this value >= 1 
                                            (not 0-indexed) **
    Output:
        ret             (str):  Hex-encoded `block_size` bytes message key that 
                                should be used to with the message number n.
    
    How to verify your solution:
    ```
        assert(q2_symmetric_ratchet("00"*16, 10) == "e0a829e4b153305ba86c42f3d0cca3d5")
        assert(q2_symmetric_ratchet("00"*16, 1)  == "c5f751aefcea28f2c863858e2d29c50b")
        assert(q2_symmetric_ratchet("99"*16, 1) ==  "7aa7cb289cc1f1b6d7d6efe83ba900f2")
    ```
    """
    chainKey = init_chain_key
    message_key = ''
    initial_msg = bytes(16)
    if msg_n == 1 :
        result = lab9_helper.hmacsha2(bytes.fromhex(init_chain_key),initial_msg)
        message_key = result[-32:]
        return message_key
    else :
        for _ in range(msg_n):
            result = lab9_helper.hmacsha2(bytes.fromhex(chainKey),initial_msg)
            chainKey = result[:32]
    message_key = result[-32:]
    return message_key


def q3_public_ratchet(public_component, dh_secret, init_chain_key, msg_n):
    """Question 3: Public Ratchet System

    Your Task:
        In this question, you will extend the ratchet system you built in q2
        to use a public key component in addition to initial chain key to start
        your key chain. 
        
        For the case of simplicity, you only have to use a single public key
        component to initially seed your key chain. In other implementations of
        such a ratchet, the public key component is often renewed, and the key
        chain will be re-seeded for a better forward secrecy.
    Notes:
        Follow the same guidelines as in Question 2, but also note the following:

        - In order to deal with Diffie-Hellman aspect of this question, use the
            public (prime) modulus `lab9_helper.p_val`
        - When encoding/decoding integers, make sure to use "big-endian" encoding
    Args:        
        public_component    (int):  The received D-H value A received from the 
                                    other party.

        dh_secret           (int):  Your own D-H secret exponent b.
        
        init_chain_key      (str):  Hex-encoded `block_size` bytes key to be 
                                    used as the initial chain key.
        
        msg_n               (int):  The order number of the message for which the
                                    key should be generated.
    Output:
        ret                 (str):  Hex-encoded `block_size` bytes message key that 
                                    should be used to with the message number n.
    
    How to verify your solution:
    ```
        assert(q3_public_ratchet(10, 5, "00"*16, 10)  == "73d5eb08393a1cb3ec4ade0dce5d9030")
        assert(q3_public_ratchet(999999, 133333333333333337, "00"*10, 1)   == "fc4f0413c02480b2bb366f50ca9682c9")
        assert(q3_public_ratchet(213214123, 1232, "99"*20, 1)   == "8cb07dc65e85639575191710a66f28d8")
    ```
    """
    chainKey = init_chain_key
    ephemeral_key = lab9_helper.int_to_hex(pow(public_component,dh_secret,lab9_helper.p_val))
    if msg_n == 1:
        result = lab9_helper.hmacsha2(bytes.fromhex(init_chain_key),ephemeral_key)
        message_key = result[-32:]
        return message_key
    else:
        for _ in  range(msg_n):
            result = lab9_helper.hmacsha2(bytes.fromhex(chainKey),bytes.fromhex(ephemeral_key))
            chainKey = result[:32]
    message_key = result[-32:]
    return message_key



# f2 = q2_symmetric_ratchet("00"*16,10)
# print(f2)
# f3 = q3_public_ratchet(10,5,"00"*16,10)
# print(f3)