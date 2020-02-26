#!/usr/bin/env python3
# -*- coding: utf-8 -*-

################################################################## LAB 11 ##############################################

"""
List you collaborators here:
                                party one 
                                party two...


Your task is to fill in the body of the functions below. The specification of each of the functions is commented out.
"""

import lab11_helper
from lab11_helper import XOR_GATE,AND_GATE

def q1_difference_propagation(Sbox):
	"""Question 1: Constructing a difference propagation table

	In this problem, you must write the code to produce a difference propagation
	table like the one shown in Lecture 20.

	Your Task:
		Construct this function to return the difference propagation table
		corresponding to a particular `Sbox` (where the input is a 2-dimensional
		list the represents an 8-bit Sbox).

	Notes:
		Remember that the difference propagation table is a 256 x 256 matrix where
		each entry is in the range 0-256. The matrix is constructed as follows:
		the value in the (d_in, d_out) entry (0-indexed) equals the number of
		pairs of inputs and outputs (x, y= S(x)) and (x', y' = S(x')) such that
		x XOR x' = d_in and y XOR y' = d_out (i.e., the difference of inputs is d_in
		and the difference of outputs is d_out).

		Your code must work for any 8-bit S-box that we provide as input.

		Your returned table should be a 2d-array that you can index as follows:
		```
			val = table[r][c]
		```
		rather than a 1d-list
	Args:
		Sbox    (func(int):int):  An S-Box substitution function that takes in a
								  byte input (value from 0-255) and returns a byte
								  output (value from 0-255)
								  (check lab11_helper.test_sbox for an example)
	Output:
		ret     (list(list(int))): The difference propagation table as a 256 x 256
									matrix where each entry is in the range 0-256
	How to verify your solution:
	```
		assert(q1_difference_propagation(lab11_helper.test_Sbox) == lab11_helper.test_diff_prop_table)
	```
	"""
	diff_propoagation_table = []
	diff_in_outputs = dict(zip(range(256),[0]*256))
	l1 = list(range(0,256))
	for count in range(0,256):
		for x in l1:
			y = x ^ count
			sx = Sbox(x)
			sy = Sbox(y)
			result = sx ^ sy
			temp = diff_in_outputs[result]
			diff_in_outputs[result] = temp + 1
		diff_propoagation_table.append(list(diff_in_outputs.values()))
		diff_in_outputs = dict.fromkeys(diff_in_outputs,0)
	return diff_propoagation_table

def q2_simple_garbled_circuit(garbled_circuit, garbler_input, OT):
	"""Question 2: Simple Garbled Circuit

	Garbled circuit is a cryptographic protocol that enables two-party secure
	computation in which two mistrusting parties can jointly evaluate a function
	over their private inputs without the presence of a trusted third party. In
	garbled circuits, there are two main parties: the garbler and the evaluator.

	For a more in-depth explanation on Garbled circuits, please refer to
	Lecture 20.

	Your Task:
		In this question, you'll be simulating the role on an evaluator. For
		simplicity, the circuit we're intrested in computing is the following:

                  a    b                      c      d
                  +    +                      +      +
               +  |    | +                    |      |
              X \ |    | / X                  v      v
              XX -v----v- XX               XXX+XXXXXX+XXX
              X XXXXXXXXXX X               X            X
              X            X               X            X
              X            X               X     AND    X
              X     XOR    X               X            X
              X            X               X            X
              XX          XX               XX          XX
               XX        XX                 XX        XX
                XX      XX                   XX      XX
                  XXX+XXX                      XXX+XXX
                     |                            |
                     |                            |
                     |                            |
                     |                            |
                     |                            |
                     +-----------+     +----------+
                                 |     |
                                 |     |
                             X  |      |  X
                             XX v      v XX
                             X X+XXXXXX+X X
                             X            X
                             X            X
                             X     OR     X
                             X            X
                             XX          XX
                              XX        XX
                               XX      XX
                                 XXX+XXX
                                    |
                                    v
                                  output

	    As an evaluator, you'll be providing the inputs a and c, and the other 
		party (the "garbler") will be proving the other two inputs b and d.

	Notes:
	    - You'll be picking the values of `a` and `c` as part of your
	    	implementation, you can choose any bit pair for those.
		
		- When using the Oblivious Transfer (OT) function, make sure to pass the 
			gate type as the first argument, there are two types that you can use 
			(XOR_GATE and AND_GATE), you can find the types defined in lab11_helper.
			For example, doing the following:
			```
				from lab11_helper import XOR_GATE
				encrypted_xor_input = OT(XOR_GATE, 0) #a=0 in this case
			```
			will return the encryption of the `a` value from the figure above
		
		- You can only call the OT function **once** per gate type.

	    - The encryption algorithm used to encrypt the labels is the `Fernet`,
	    	you can find it in the `cryptography` library as follows:
				`from cryptography.fernet import Fernet`
			Fernet is an Authenticated encryption algorithm, therefore a decryption
			of an invalid ciphertext will throw an `InvalidToken` exception.
	
		- When decrypting a ciphertext, make sure to take into cosideration that
			the encryption order is enc_k1(enc_k2(label)), feel free to use the
			helper function `lab11_helper.doubly_authenticated_decryption` to 
			perform the decryption (highly recommend).
		
		- For simplicity, the output of the last "OR" gate will not be garbled 
			(we wont be using lables to represents the `0` and `1`), instead, 
	        we'll represent 0 as a the hex value `00`, and 1 as the hex value `01`. 
			You should simply return the hex string `00` or `01` as the result.
		
	    
	Args:
	    garbled_circuit (lab11_helper.GarbledCiphertexts):  An object containing
	    	the ciphertexts for the truth table of each gate (note the the
	    	ciphertexts per gate are shuffled, so don't assume a specific order)
	    
		garbler_input   (list(str)): The encrypted lables of the values of `b` 
			and `d` that the garbler choose.
		
	    OT              (func(GATE_TYPE, int)): Oblivious Transfer function, 
	        takes in a gate type a bit input, returns the corresponding label 
			for that input bit.
	Output:
	    ret             (str):  the result of the circuit on the inputs a, b, c
	    	and d. The result should be a hex-encoded string that represents the bit
	    	value `0` or `1`.
	How to verify your solution:
	```
		assert(q2_simple_garbled_circuit(*lab11_helper.test_input) == '01')
	```
		Note that the test case above is the result of the evaluator picking `a=1,
		c=1` and the garbler picking `b=1, d=1`. You can test your own
		implementation with any other bit pairs (for the evaluator side) and check
		the output by manually going over the circut above.
	"""
	xorOutput = ''
	andOutput = ''
	finalOutput = ''
	xorCiphertexts = garbled_circuit.XOR_ciphertexts
	andCiphertexts = garbled_circuit.AND_ciphertexts
	orCiphertexts = garbled_circuit.OR_ciphertexts
	garbler_xor_input = garbler_input[0]
	garbler_and_input = garbler_input[1]
	encrypted_xor_input = OT(XOR_GATE,1)
	encrypted_and_input = OT(AND_GATE,1)
	for vals in xorCiphertexts:
		try:
			temp = lab11_helper.doubly_authenticated_decryption(encrypted_xor_input,garbler_xor_input,vals)
		except:
			continue
	xorOutput = temp
	for vals in andCiphertexts:
		try:
			temp = lab11_helper.doubly_authenticated_decryption(encrypted_and_input,garbler_and_input,vals)
		except:
			continue
	andOutput = temp
	for vals in orCiphertexts:
		try:
			temp = lab11_helper.doubly_authenticated_decryption(xorOutput,andOutput,vals)
		except:
			continue
	finalOutput = temp
	return finalOutput


	

def q3_stack_exchange():
	"""Question 3: Answer a Question on Stack Exchange

	Your Task:
		Spread your new-found knowledge of applied cryptography to others.
		Concretely, find a question on https://crypto.stackexchange.com
		pertaining to material that we've covered in this course, and answer it.

	Requirements:
		- Don't post a question to yourself; that's boring!

		- Questions with the following tags are most likely to be pertinent to
		  the class material: aes, authentication, block cipher,
		  brute-force-attack, cbc, cryptanalysis, encryption, hash,
		  initialization-vector, mac, modes-of-operation, padding, and symmetric.
		  (I'm sure there are others.)

		- Try to find a question that either has 0 prior answers or for which
		  the prior answers seem to be incorrect. In particular, avoid any
		  question with many answers, especially several new answers that are
		  likely to come from your classmates. (But if you wish to answer a
		  question with 1-2 previous answers, that is okay as long as your answer
		  is somehow different than the prior ones.)
	Privacy notice:
		I don't want to force you to post an answer to the Internet. Ergo, you
		will obtain full credit on this assignment simply by finding a question
		on Stack Exchange and answering it locally to me. With that having been
		said: I do encourage you to post your answer publicly if you're
		comfortable doing so.

	Args:
		None
	Output:
		ret (list(str, str, str)): A list (or a tuple) with the following items:
					- The URL of the Stack Exchange question that you wish to consider.
					- The text of the question.
					- Your answer.
	"""
	question = "https://crypto.stackexchange.com/questions/70170/mpc-protocols-for-high-school-kids"
	questionText = "I was explaining MPC to a high school student. He was excited and asked me for some examples. The only ones that I could think of are by using garbled circuits. Are there some simple MPC protocols for operations such as addition, multiplication, exponentiation, max, min that I could easily explain to an high school student?"
	answer = """Here's a simple example for addition which can be extended to other operations as well. 


				Suppose there $X$ number of children in a classroom and everyone has a score ranging from 0 to 100. We want to calculate the average of the scores of all students without the teacher or the other students knowing what their classmates have scored.

				Here's how we can achieve this. 

				Step 1 : 

				Make them each right down the score that they have got on a piece of paper and make sure no one is colluding. This only works if everyone does it honestly. 

				Step 2: 

				Tell each student to select $X$ numbers and write them down preferably on small bits of paper since there are $X$ number of students such that these numbers will add up to the score they want to keep secret. The range can be from $-∞$ to $+∞$.


				Step 3 : 
				Tell each student to distribute $ X-1$ bits to every other student so that each students ends up with $X$ bits in the end.

				Step 4 : Now that each student has $X$ bits of paper , tell them to add up all numbers they have in front of them and write the value they got on the board.

				Step 5: Add all these numbers and you will get average of the scores of each student. 

				You could calculate the average without anyone knowing what their score was.

				You can cross verify by taking the average of the actual scores. """
	return(question,questionText,answer)