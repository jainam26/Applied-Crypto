#!/usr/bin/env python3
# -*- coding: utf-8 -*-

################################################################## LAB 5 ##################################################################

"""
List you collaborators here:
                                party one 
                                party two...


Your task is to fill in the body of the functions below. The specification of each of the functions is commented out.
"""

import lab5_helper
import os,random
from binascii import hexlify,unhexlify


def q1_forge_mac(message, leaky_hmac_verify=lab5_helper.leaky_hmac_verify_example):
    """Question 1: Timing attack on HMAC's equality test

    In this problem, you will forge an HMAC-SHA1 tag (without knowing the key) based solely on 
    the amount of time that the verify algorithm takes to validate a prospective tag. 

    The verification algorithm might leak information based on how long it takes to compute, 
    say, if it compares the computed value against the tag one bit at a time.

    The scenario:
        Pretend that Alice is sending authenticated messages to Bob using a key that they 
        know and **you do not**. Bob's code to verify that the messages are properly tagged is 
        given in the 'leaky_hmac_verify' function passed to this function. 
        In summary, his code computes the correct tag and compares it to the one that Alice provided. 

        However, Bob's equality comparison test is imperfect: if Alice's tag is not correct, 
        then Bob's code reveals (or "leaks") the location of the first difference between
        the correct tag and Alice's invalid attempt. 
        (This leaked bit simulates measuring the time it takes for Bob's verification algorithm to run.)

    Your Task:
        Take on the role of Mallory, and find a way to forge an HMAC tag on the following 41-byte message 
        without knowing the key:

        message = "This message was definitely sent by Alice"

        That is: your solution would send several message/tag pairs of your choice to Bob's 'leaky_hmac_verify' 
        routine. By observing Bob's responses, you should be able to forge the appropriate tag.
    Args:
        leaky_hmac_verify  (func)   :   the hmac verify function that Bob would run (check `lab5_helper.py` for an example)
    Output:
        ret     (str):  hex-encoded forged HMAC tag of the "message" given
    How to verify your answer:
        assert(q1_forge_mac(message="This message was definitely sent by Alice") ==
            lab5_helper.hmacsha1(key=lab5_helper.TEST_KEY, message="This message was definitely sent by Alice"))
    Note:
        The key passed to `leaky_hmac_verify` is unknown to you, so don't assume a determinstic output from
        `leaky_hmac_verify` given the same 'message' and 'claimed_tag'. We will test against multiple different
        keys.
    """
    tag = "\x00" * 20
    tag = hexlify(tag.encode('ascii'))
    print(tag)
    result = leaky_hmac_verify(message,tag)
    print(result)



def q2_simple_aes_cache_attack(leaky_encipher=lab5_helper.leaky_encipher_example):
    """Question 2: Simple cache timing attack on AES

    As Mallory, you must determine the last round key at the very end of AES.
    Since you are a legitimate user on the machine, you're welcome to encipher files 
    whenever you'd like, and you can also introspect the state of the cache using techniques 
    like Prime+Probe that we discussed in class.

    Bob's code for file enciphering is provided as the 'leaky_encipher' routine passed to this function
    (Note: you can find an example of the 'leaky_encipher' routine in 'lab5_helper.py'). 

    Bob's routine does both of the above operations for you: it enciphers a file and then helpfully 
    tells you how the 10th round S-box lookups have influenced the state of the cache, so you don't 
    need to inspect it yourself. Hence, 'leaky_encipher' has two outputs: the actual ciphertext plus a 
    Python set stating which cachelines are accessed during the final round's SubBytes operation. 

    Recall that SubBytes works on a byte-by-byte basis: each byte of the state is used to fetch a 
    specific location within the S-box array. The 'leaky_encipher' routine tells you which elements of 
    the S-box array were accessed, which as you recall from Lecture 10 is correlated with the key. 

    I'll state two caveats upfront:
        -   This problem conducts a last-round attack: that is, our attack scenario is explained in lecture 10 slides
            As a result, the cache lines are correlated with the last round key of AES, and not the first round key. 
            This is acceptable to Mallory because there's a known, public permutation that relates all of the round keys.

            In fact in my helper file 'aeskeyexp.py' I have provided a routine 'aes128_lastroundkey' that converts first -> last round keys. 
            I didn't actually give you the converse, but I assure you that it's equally as easy to compute. 
            Let's just declare victory as Mallory if we can find the last round key.

        -   Mallory cannot interrupt the state of execution of AES. She can only observe the contents of the cache after 
            it is finished. As a result: leaky_encipher only tells you the **set** of all table lookups made to the 10th 
            round S-box across all 16 bytes, without telling you which lookup is associated with which byte.

    Your Task:
        Complete this function with a solution that calls 'leaky_encipher' as many times as you wish 
        and uses the results to determine the key.
    Args:
        leaky_encipher  (func)  : performs an AES encipher on the input 16-bytes input `file_bytes`
            Args:
                file_bytes  (bytes)     : 16-bytes input to be passed to AES for enciphering
            Output:
                ret         (str, set)  : tuple with the actual ciphertext and a Python set stating which cachelines 
                                            are accessed during the final round's SubBytes operation.
    Output:
        ret             (str)   : hex-encoded 16-bytes string that represents the lastroundkey of AES in leaky_encipher
    How to verify your answer:
        assert(q2_simple_aes_cache_attack() ==
            aeskeyexp.aes128_lastroundkey(lab5_helper.TEST_KEY).hex())
    Note:
        The file `lab5_helper.py` contains some helper functions that you find useful in solving this question.
    """
    key = ''
    for index in range(0,16):
        byteList = []
        for i in range(0,256):
            byteList.append(i)
        while(len(byteList) != 1):
            randomMessage = os.urandom(16)
            result = leaky_encipher(randomMessage)
            cipherText = result[0]
            hexCipher = cipherText.hex()
            cipher_int = [int(hexCipher[i] + hexCipher[i+1], 16) for i in range(0, len(hexCipher), 2)]
            cache_line = list(result[1])
            test = cipher_int[index]
            candidate = []
            for x in byteList:
                temp = test ^ x
                val = lab5_helper.Sinv(temp)
                if val in cache_line:
                    candidate.append(x)
            byteList = candidate
        temp = hex(byteList[0])
        temp = temp[2:]
        temp = temp.zfill(2)
        key += temp
    return key
def q3_realistic_aes_cache_attack(less_leaky_encipher=lab5_helper.less_leaky_encipher_example):
    """Question 3: Realistic cache timing attack on AES

    In this problem, you're still acting as Mallory and trying to perform a cache timing attack. 
    There's just one new hurdle that you must overcome. (As a consequence: do not attempt to solve 
    this problem until you have already solved Question 2.)

    I made one unrealistic assumption in the 'leaky_encipher' routine:
    I provided you with the set of bytes that were accessed in the final round of AES.
    Real caches unfortunately do not provide byte-level accuracy. I'll spare you the details; 
    the upshot is that it is common 16 values of the SubBytes array to fit within a single cacheline.

    That is: suppose Bob weren't running AES at all, but instead only makes a single table 
    lookup S[x] into the SubBytes array S. By observing which portion of the cache is activated, 
    a cache attack would let Mallory know whether Bob's access x was in the range 0-15, or the range 16-31, 
    or the range 32-47, ... or the range 240-255. However, Mallory couldn't tell anything beyond that. 
    Put another way: Mallory can learn the upper 4 bits of x but not the lower 4 bits.

    The 'lab5_helper.py' file contains Bob's code for this problem. It is the routine less_leaky_encipher_example 
    that only provides (the set of) the upper 4 bits of the location of each table lookup to Mallory; it otherwise 
    runs similarly to the code in Question 2.

    Your Task:
        Perform a cache timing attack even in this restricted setting. Your input-output behavior should 
        be the same as stated in Question 2.
        (The solution to this problem is pretty much exactly what Osvik, Shamir, and Tromer did to break 
        Linux's full disk encryption software, called dmcrypt.)
    """
    key = ''
    for index in range(0,16):
        byteList = []
        for i in range(0,256):
            byteList.append(i)
        while(len(byteList) != 1):
            randomMessage = os.urandom(16)
            result = less_leaky_encipher(randomMessage)
            cipherText = result[0]
            hexCipher = cipherText.hex()
            cipher_int = [int(hexCipher[i] + hexCipher[i+1], 16) for i in range(0, len(hexCipher), 2)]
            cache_line = list(result[1])
            test = cipher_int[index]
            candidate = []    
            for x in byteList:
                temp = test ^ x
                val = lab5_helper.Sinv(temp)
                if val >> 4 in cache_line:
                    candidate.append(x)
            byteList = candidate
        temp = hex(byteList[0])
        temp = temp[2:]
        temp = temp.zfill(2)
        key += temp
    return key
q1_forge_mac("This message was definitely sent by Alice")
