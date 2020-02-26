#!/usr/bin/env python3
# -*- coding: utf-8 -*-

################################################################## LAB 7 ##################################################################

"""
List you collaborators here: No one

Your task is to fill in the body of the functions below. The specification of each of the functions is commented out.
"""

import lab7_helper
from Cryptodome.PublicKey import RSA
import math
from decimal import Decimal
from json import loads
MMI = lambda A, n,s=1,t=0,N=0: (n < 2 and t%N or MMI(n, A%n, t, s-A//n*t, N or n),-1)[n<1] # taken from https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python it uses the Extended Euclidean Algorithm
def q1_break_poor_rsa(rsa_keys):
    """Question 1 : Breaking RSA keys with poor randomness

    The RSA public key encryption and digital signature schemes (named after 
    its creators Rivest, Shamir, and Adleman) essentially relies upon the 
    hardness of factoring.

    An RSA private key consists of two prime numbers `p` and `q`, and the 
    corresponding public key equals the product of the two primes `N = p * q`.
    
    The RSA scheme relies upon good sources of randomness when generating the 
    private key: if your entropy source isn't strong, and several people on the 
    Internet choose the same `p` **or** the same `q`, then the scheme will break.

    And by this point in the class I think you can see where I'm going with this. 
    Unfortunately, this kind of poor random key generation is exactly what has 
    happened with many computers on the Internet, as shown by https://ia.cr/2012/064 
    and several subsequent papers.

    Your Task:
        
        Given the list of RSA keys in `rsa_keys`, crack as many of the RSA keys 
        as you can. Do **not** try a brute force attack to factor the public 
        keys (that's the next problem), but instead use the fact that factors 
        might be repeated between keys.
    
    Args:
        One of the common ways public/private RSA keys are stored and transmitted
        is by using one of the X509 File Extensions (`.CRT`, `.PEM`, ...). In 
        this lab, we'll use the `.PEM` extension to handle the public keys.

        For example, given the public key file `pub_key.pem`, you can use Python
        as follows to decode the key:
        ```
            from Cryptodome.PublicKey import RSA
            pem1 = open("pub_key.pem", 'r').read()
            k1 = RSA.importKey(pem1)
        ```

        In this problem, your input `rsa_keys` will be a list of strings that
        represents RSA keys in PEM ecoding. For example, to decode the first 
        RSA key in the input list, you can do the following:   
        
        `k1 = RSA.importKey(rsa_keys[0])`

    Output:
        ret (list(Cryptodome.PublicKey.RSA.RsaKey)): A list containing all the
                        private keys of the cracked RSA keys.
    
    Note:
        - The number of bad RSA keys is not always equal to the number of given
            keys, so don't assume any fixed number.
        
        - Given an `n`, `e` and `d` (private exponent), you can create an 
            instance of the `Cryptodome.PublicKey.RSA.RsaKey` object as follows:
            ```
            from Cryptodome.PublicKey import RSA
            n = 133
            e = 5
            d = 65
            priv_key = RSA.construct((n, e, d), False)  # False is passed to 
                                                        # disable parameter checks
            ```    
    How to verify your solution:
        This problem is inspired from the challenge here: 
            http://www.loyalty.org/~schoen/rsa/
        So one way you can verify your solution is to use the keys provided
        in the challenge. I have already imported the keys in `lab7_helper.challenge_keys`

        So you can check your implementation as follows:
        ```
        assert(lab7_helper.verify_keys(
                q1_break_poor_rsa(
                    lab7_helper.challenge_keys
                )
            )
        )
        ```
    """
    private_Keys = []
    public_keys = []
    tuple_indices = []
    gcd_clashes = {}
    for i in range(len(rsa_keys)):
        k1 = RSA.import_key(rsa_keys[i]).n
        public_keys.append(k1)
    e = RSA.import_key(rsa_keys[0]).e
    for j in range(0,len(public_keys)):
        for i in range(0,len(public_keys)):
            if j==i:
                continue
            val = math.gcd(public_keys[j],public_keys[i])
            if val != 1:
                tuple_indices.append((j,i))
                gcd_clashes[val] = list(tuple_indices)
        tuple_indices.clear()
    commonFactors = list(gcd_clashes.keys())
    for values in commonFactors:
        keysToAttack = gcd_clashes[values]
        for keys in keysToAttack:
            temp_key1 = public_keys[keys[0]]
            temp_key2 = public_keys[keys[1]]
            a = temp_key1 // values
            c = temp_key2 // values
            n1 = a * values
            n2 = c * values
            phi_n1 = (values-1)*(a-1)
            phi_n2 = (values-1)*(c-1)
            d1 = MMI(e,phi_n1)
            d2 = MMI(e,phi_n2)
            priv_key1 = RSA.construct((n1,e,int(d1)),False)
            priv_key2 = RSA.construct((n2,e,int(d2)),False)
            private_Keys.append(priv_key1)
            private_Keys.append(priv_key2)
    return private_Keys
    
def q2_break_small_rsa(rsa_key):
    """Question 2: Breaking small RSA keys

    Humans have been trying to figure out how to factor integers for at least 
    2000 years. While we're still not great at it, we are decently good... 
    at least compared to the elliptic curve Diffie-Hellman problem. As a result, 
    RSA keys used in cryptography are quite large: they involve numbers that 
    are 1500-4000 bits long. Sometimes though, adversaries just make your life 
    easier. If you don't believe me, read this stream of Twitter posts about 
    the weak RSA keys used to control medical devices that are implanted in 
    people's hearts: 
            https://twitter.com/matthew_d_green/status/818816372637650948
    
    Your Task:
        Break an RSA public key whose factors are small enough to find rather 
        quickly on a modern computer. For this problem, you can assume that
        the modulus `n` is no longer than (2^{33} - 1), so 33 bits long.
        
        You may **not** use any library provided code to solve this problem,
        I argue that even the simplest approach to solve this problem will
        be sufficient given the small RSA modulus length, so there's no need
        to use a library code for that.

    Args:
        rsa_key     (str):  A byte string with a similar format to the items
                            of the list `rsa_keys` from the previous question
                            (`.PEM` encoding)
    
    Output:
        ret (Cryptodome.PublicKey.RSA.RsaKey): the Private RSA key used to 
                                    generate the input public RSA key. 
    
    How to verify your solution:
        This problem is inspired from the challenge here: 
            https://id0-rsa.pub/problem/09/
        So feel free to use the submission box on the web page to verify your
        solution, or at least test against the provided test vector on the page.        
    """
    
    publicKey = RSA.import_key(rsa_key)
    public_exponent = publicKey.e
    modulo = publicKey.n
    p = int()
    n = math.floor(math.sqrt(modulo))
    for i in range(3,n,2):
        if modulo % i == 0:
            p = i
    q = modulo // p
    phi_n = (p-1)*(q-1)
    d = MMI(public_exponent,phi_n)
    private_key = RSA.construct((modulo,public_exponent,d),False)
    return private_key
