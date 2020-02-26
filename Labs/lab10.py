#!/usr/bin/env python3
# -*- coding: utf-8 -*-

################################################################## LAB 10 ##############################################

"""
List you collaborators here: No one

Your task is to fill in the body of the functions below. The specification of each of the functions is commented out.
"""
import lab10_helper
from Cryptodome.Hash import HMAC
from Cryptodome.Hash import MD5,SHA1,SHA256,SHA512
from Cryptodome.Cipher import AES
from Cryptodome.Util.strxor import strxor
from math import ceil


def q1_fb_onion_hash(password, salt1, salt2):
    """Question 1: Implement Facebook's Onion Hash

    Most online services do not store your password in the clear on their 
    servers. Instead, they store the hash of your password in order to minimize
    the harm caused by a potential data breach. Since hash functions are
    inherently one-way operations, an attacker who compromises the service would
    still need to expend more work to recover the passwords themselves.
    Facebook follows a rather interesting password hashing strategy that I
    describe below.

    As they have grown as a company and become more security-conscious, Facebook
    has upgraded over time the hash functions that they use for password
    hashing. They initially used the MD5 hash function, and at some point they
    upgraded to use the SHA-1 function.

    But Facebook has a problem: they cannot simply upgrade their hash of the
    password from `MD5(password)` to `SHA1(password)` because they don't know
    the user's password and the hash functions are one way (indeed, that was the
    whole point, remember?).
    
    To solve this problem, they could simply wait until the next user login and
    then compute both hashes of the password: one to validate the user login and
    the other to store an upgraded version for next time.

    That solution would work great for users who log in frequently. But there
    are plenty of people who haven't logged into Facebook in years, and it'd be
    great to provide them with stronger security too when newer hash functions
    are built.
    
    Therefore, a better solution is to nest one hash function on top of the
    other:  `SHA1(MD5(password))`. This 'nested' solution enables Facebook to
    upgrade their password hashes without user input.

    Facebook has followed this `onion' approach as they migrated to stronger and
    stronger hash functions, including ones like `scrypt` that are built
    specifically for protecting passwords.

    The pseudocode for "The Onion" approach can be summarized as follows:
    ```
        cur     = 'plaintext'
        cur     = md5(cur)
        salt    = randbytes(20)
        cur     = hmac_sha1(cur, salt)
        cur     = cryptosystem::hmac(cur)
               [= hmac_sha256(cur, secret)]
        cur     = scrypt(cur, salt)
        cur     = hmac_sha256(cur, salt)
    ```
    (pseudocode was retrieved from this talk by Alex Muffet (from Facebook) at
    Passwords14, link:https://youtu.be/7dPRFoKteIU?t=132 relevent slide at 2:12)

    Your Task:
        Implement the first 5 lines of the Facebook onion hash. Ignore the final
        2 lines. That is, write a function that does the following
        transformation to any password: apply MD-5, take that result and apply
        HMAC-SHA1 with a provided salt, and finally take that result and apply
        HMAC-SHA256 with another provided salt. Make sure that you pass along
        the results from one to the other as binary bitstrings. The final result
        must be hex-encoded though so that it is safe to store in a database.

        Use the salt as the secret key portion of the HMAC. You may find the 
        solutions from the previous labs useful when constructing the HMAC.
        
    Notes: 
        The purpose of the 'salts' is to stop an attacker from pre-computing
        the hash of all likely passwords. The salt is generated randomly and
        independently for each user in the system. It is publicly posted next to
        the hashed password so a user can re-derive exactly the same hash on her
        next login. Since the salt is stored within the hashed password file, it
        is also stolen by any adversary who compromises the Facebook login
        servers. Nevertheless, at least the salts prevent simple frequency
        attacks: for instance, everyone who chooses the password 'password'
        doesn't have the same hash anymore. Instead, the attacker must attempt a
        separate brute-force password search for *each* user.

    
    Args:
        password    (str):  ASCII-encoded user input password
        salt1       (str):  ASCII-encoded salt to be used with the HMAC-SHA1
        salt2       (str):  ASCII-encoded salt to be used with the HMAC-SHA256
    
    Output:
        ret         (str):  Hex-encoded hash output after applying the protocol
                            described above. 
    
    How to verify your solution:
    ```
        assert(q1_fb_onion_hash('Password1!', 'salt1', 'salt2') 
            == '06912315b30054d76340a880dbb7b65d366df1f8dee1c348aa1bc4354f42cc38')
    ```
    """
    md5Obj = MD5.new()
    md5Obj.update(password.encode('ascii'))
    result1 = md5Obj.hexdigest()
    result2 = HMAC.new(salt1.encode('ascii'),bytes.fromhex(result1),SHA1).hexdigest()
    finalResult = HMAC.new(salt2.encode('ascii'),bytes.fromhex(result2),SHA256).hexdigest()
    return finalResult


def q2_crack_shadow(shadow_file):
    """Question 2: Crack /etc/shadow file

    The `/etc/shadow` file (on GNU/Linux) stores the hashes of the actual
    passwords for all the user’s accounts (If you're using a Linux OS, you can
    check the file yourself). The `shadow` file also stores additional
    properties related to user password, so basically, it stores secure
    user account information. 
    Within the `shadow` file, each entry (line) represents a password for a
    specific user, so if your system contains three users, you should expect the
    `shadow` file to contain three entries at least.

    According to the `shadow` file specification, here is an example of an entry
    in the `shadow` file:    
    ```
    root:$1$TDQFedzX$.kv51AjM.FInu0lrH1dY30:15045:0:99999:7:::
      ^   ^     ^               ^             ^   ^   ^   ^
      |   |     |               |             |   |   |   |
      1   2     3               4             5   6   7   8
    ```

    All fields (within an entry) are separated by a colon (:) symbol. Password
    related parameters are further separated by a dollar sign ($) symbol.

    For the purposes of this lab, we would only focus on 2, 3 and 4 (from the
    example above):
    2: `id`: the hash algorithm used, on GNU/Linux the mapping is as follows:
                $1$ is MD5
                $2a$ is Blowfish
                $2y$ is Blowfish
                $5$ is SHA-256
                $6$ is SHA-512
    3:  `salt`: salt value is nothing but a random value (ascii-encoded) that's 
                generated to combine with the original password, the same concept 
                is discussed in lecture 18 slides.
    4:  `password_hash`: the hash value (variant of base64 encoded) of salt +
                        user password given the `id` hash algorithm and the salt 
                        provided.
    
    For more information about the file structure, check this Wiki page 
        (here: https://en.wikipedia.org/wiki/Passwd#Shadow_file)

    Your Task:
        Your function should take in as an input the contents of a `shadow`
        file, you would then need to parse each entry (line) in the file,
        extract the relevent data (2, 3 and 4 from above), then you will crack
        each hashed password (more details below), then return a list of
        the cracked passwords *in the same order* they're in the input file.
        
        To simplify your cracking process, you can assume that all hashed
        passwords are chosen from the `lab10_helper.top_rockyou_passwords`
        list of words. Hence, the brute force space should be doable on an
        average CPU. 
        
        What you're doing here is a simplified version of the popular password
        cracking tool "John the Ripper" from Openwall 
            (here: https://www.openwall.com/john/)
        
    Notes:
        - For simplicity, you can assume that only SHA-256, SHA-512 are used to 
          hash the passwords.
        - Keep in mind that the password related values are `$` seperated in
          addition to the general `:` delimiter.

    Args:
        shadow_file         (str):  ASCII-encoded contents of a shadow file,
                                    this value is exactly equivalent to 
                                     `open('/etc/shadow', 'r').read()`
                                (Note: file lines are seperated by `\n`, check 
                                       `lab10_helper.sample_shadow_file` for an 
                                        example)
    Output:
        ret         (list(str)):    List of the ASCII-encoded cracked
                                    passwords extracted from the given shadow
                                    file. The passwords are expected to be in 
                                    the same order as they were in the shadow 
                                    file.
    
    How to verify your solution:
    ```
        assert(lab10_helper.hash_answer(q2_crack_shadow(lab10_helper.sample_shadow_file)) 
            == "136b67895d86122c443c93d23f1c6102e2fcff588be789983bd116ce109ff286")
    ```
    """
    candidatePasswords = lab10_helper.top_rockyou_passwords
    passwordList = []
    shadow_file = shadow_file.split('\n')
    for passwords in shadow_file[:-1]:
        vals = passwords.split('$')
        hashID = int(vals[1])
        saltUsed = vals[2]
        index = vals[3].index(':')
        hashedPwd = vals[3][:index]
        for pwds in candidatePasswords:
            candidate = lab10_helper.hash_password(hashID,saltUsed,pwds)
            candidate = candidate.split('$')
            if candidate[3] == hashedPwd:
                passwordList.append(pwds)
    return passwordList

def q3_sponge_aes_function(inputString, outputLen, r):
    """Question 3: Build a sponge function from AES

    The *sponge function* design is the basis of the SHA-3 hash function (aka
    Keccak). We discussed it in detail in Lecture 18. Let me refresh your memory
    here with a picture depicting its operation (here:
    https://en.wikipedia.org/wiki/Sponge_function#/media/File:SpongeConstruction.svg
    , taken from Wikipedia).

    The sponge construction requires a public, fixed-length, random-looking
    permutation `f`. Since we haven't yet discussed in class how the actual
    Keccak-`f` function works, in this problem let's instead use in its place
    AES-128 with a publicly hardcoded key `K = "AES w/ fixed key"` (but without
    the quotes).
    
    Your Task:
        Your function should 'absorb' an arbitrary-length 'inputString'
        (interpreted as raw bytes) and then 'squeeze' out 'outputLen' bytes of data.
        
        Your sponge function should use AES with key `K` as the permutation `f`.
        You should split its 16-byte state into a rate of `r` bytes followed by 
        a capacity of `16-r` bytes.
    
    Notes:
        Don't worry about padding; that is, you may assume that inputs are
        always a multiple of `r` bytes in length.

        Keep in mind that the `r + c = 16`, so the capacity size is always the 
        remaining of the rate size.
        
    Args:
        inputString     (str):  ASCII-encoded string of an arbitrary-length
                                (multiple of `r` bytes).
        outputLen       (int):  Number of output bytes that you should
                                'squeeze' out of the input.
        r               (int):  Rate size (in bytes) of the the Sponge function
        
    Output:
        ret             (str):  Hex-encoded string of length 'outputLen'-bytes
                                that you 'squeeze-out' of the sponge-function.
    How to verify your solution:
    ```
        assert(q3_sponge_aes_function("this is a test message to be passed to be hashed", 10, 12) == "45045a7eac2202857573")
        assert(q3_sponge_aes_function("the length of this message is a multiple of the 6 byte sponge rate", 10, 3) == "5369b87b739347ed9e47")
        assert(q3_sponge_aes_function("the length of this message is a multiple of the 6 byte sponge rate", 10, 6) == "0d8d8a67d52925badb92")
        assert(q3_sponge_aes_function("the length of this message is a multiple of the 6 byte sponge rate", 30, 6) == '0d8d8a67d52925badb92698527cac836204f78cf6b92bcc90a63a21d4fa5')
    ```

    """
    finalHash = ''
    aesObj = AES.new(b'AES w/ fixed key',AES.MODE_ECB)
    inputBlocks = [inputString[i:i+r].encode('ascii') for i in range(0,len(inputString),r)]
    stateMemory = list(bytes(16).hex())
    for i in range(len(inputBlocks)):
        intermediate_State = strxor(bytes.fromhex((''.join(stateMemory[0:r*2]))),inputBlocks[i]).hex()
        stateMemory[0:r*2] = intermediate_State
        str_State = ''.join(stateMemory)
        stateMemory = list(aesObj.encrypt(bytes.fromhex(str_State)).hex())
    count = ceil((outputLen / r))
    if count == 1:
        finalHash = stateMemory[0:outputLen*2]
        return ''.join(finalHash)
    else : 
        finalHash += ''.join(stateMemory[0:r*2])
        for _ in range(0,count):
            str_State = ''.join(stateMemory)
            stateMemory = list(aesObj.encrypt(bytes.fromhex(str_State)).hex())
            finalHash += ''.join(stateMemory[0:r*2])
    return ''.join(finalHash[0:outputLen*2])