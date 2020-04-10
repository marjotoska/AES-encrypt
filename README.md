# AES-Encrypt
A program which encrypts messages by implementing the Advanced Encryption Standard which is virtually impossible to break by brute force.
The message string is tokenized into bytes, converted to hex values and transformed in the encryption process which consists of 10, 12 or 14 rounds total for the 128, 192 and 256-bit keys respectively. A cipherkey is also added in between the rounds, to increase complexity of the algorithm and to finally produce the Ciphertext in junction with the Plaintext.

Trivia: National Security Agency announced AES Algorithm's 192 and 256-bit keys secure enough to be used on Top Secret confidential information. 
