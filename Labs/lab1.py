#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import hashlib
################################################################## LAB 1 ##################################################################
"""
List you collaborators here:
                                Jainam Shah


Your task is to fill in the body of the functions below. The specification of each of the functions is commented out, and an example test case is provided for your convenience.
"""

def str_to_bytes(string):
    """ Convert from a Python string to a list of integers, where each integer represents the value of the corresponding byte of the string. As a result, the length of the output list should equal the length of the input string.

    Example test case:

        "test" -> [116, 101, 115, 116]

    """
    strToIntList = [ord(value) for value in string]
    return strToIntList

def single_byte_to_hex(single_char):
    """ Read a single, decimal byte from the user and return a string of its hexidecimal value. This string should use lowercase and should always be exactly two characters long. Make sure you pad the beginning with a 0 if necessary, and make sure the string does NOT start with '0x'.

    Example test case:

        255 -> "ff"

    """
    hexaRep = (hex(int(single_char)))
    return hexaRep[2:]
    

def multi_byte_to_hex(the_input):
    """ Take in a list of bytes, separated by a space, and return a hex string corresponding to the list of bytes. The easiest way to do this is by using your solution to the previous question.

    Example test case:
 
        [1, 10, 100, 255] -> "010a64ff"

    """
    hexString = ''
    for value in the_input:
        temp = hex(int(value))
        temp = temp[2:]
        temp = temp.zfill(2)
        hexString += temp
    return hexString

def hex_string_to_bytes(the_input):
    """ Take in a hex string and convert it to a list of bytes. (This should effectively "undo" the question 3.)

    Example test case: 

        "70757a7a6c65" -> [112, 117, 122, 122, 108, 101]

    """
    byte_list = []
    pairs_to_convert = [the_input[i:i+2] for i in range(0,len(the_input),2)]
    for value in pairs_to_convert :
        byte_list.append(int(value,16))
    return byte_list    

def bytes_to_string(the_input):
    """ Take in a list of bytes, and return the string they correspond to. Unlike the prior question, here you should return a raw bitstring and not the hex values of the bytes! As a result, the output need not always be printable. (This should effectively "undo" the question 1.)

    Example test case:
 
        [116, 101, 115, 116] -> "test"

    """
    string = ''
    for value in the_input :
       ch = chr(value)
       string += ch
    return string

def string_to_hexstring(the_input):
    """ Take in a string, and return the hex string of the bytes corresponding to it. While the hexlify() command will do this for you, we ask that you instead solve this question by combining the methods you have written so far in this assignment.

    Example test case: "puzzle" -> "70757a7a6c65"
 
    """
    hexString = ''
    int_list = [ord(value) for value in the_input]
    for val in int_list :
        temp = hex(val)
        hexString += temp[2:]
    return hexString
def hexstring_to_string(the_input):
    """  Now take in a hex string and return the string that it corresponds to. (This should effectively "undo" question 6.) Once again, the unhexlify() command will do this for you, but you should instead solve this question using only the code you have written so far in this assignment.

    Example test case: 

        "70757a7a6c65" -> "puzzle"

    """
    result_string = ''
    pairs_to_convert = [int(the_input[i:i+2],16) for i in range(0,len(the_input),2)]
    for val in pairs_to_convert:
        temp = chr(val)
        result_string += temp
    return result_string

def sha256_hexoutput(the_input):
    """ Given input in string format, compute the SHA-256 hash value of the input and return the response as a hex string. (Keep this code handy! In future assignments, we might provide you with the SHA-256 hash of the answer so you can check your solution against it.)

    Example test case:

        "test" -> "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

    You can actually type "sha256 blah" into DuckDuckGo to get the value of sha-256(blah)

    """
    hashObj = hashlib.sha256(the_input.encode()).hexdigest() 
    return hashObj
    
# f1 = str_to_bytes('Jainam')
# f2 = single_byte_to_hex(10)
# f3 = multi_byte_to_hex([1,10,101,254])
# f4 = hex_string_to_bytes("70757a7a6c65")
# f5 = bytes_to_string([116, 101, 115, 116])
# f6 = string_to_hexstring('puzzle')
# f7 = hexstring_to_string('70757a7a6c65')
# f8 = sha256_hexoutput('jainam')
