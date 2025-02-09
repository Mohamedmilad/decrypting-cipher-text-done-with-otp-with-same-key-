this script is only for academic purpose don't use it in any other purposes.

We see that the xor result is in {4,5,0,1} but the space occurs if the result is 0 (space^space) or number (space xor letter) but 1 means that it's a letter xor another letter
If it happens more than threshold time than that means that the possibility that this is a space is higher -> flag=True
Means that [i][j] position is a guessed space so we xor it with the cipher (deduce parts of the key)

Here we xor the spaces with the ciphertexts(deduced key) to obtain the text in the positions of the spaces


Derived Key: 94DB46EDEAE86FA840A14F499212FB90798B40A888E90BEBF8029EE11006945FB32EDF47A3388FB502604E5FC7CBF6FE9158D3D31D9F484F1F7A       

completed messages 

Decrypted Message: modern cryptography requires careful and rigorous analysis
Decrypted Message: address randomization could prevent malicious call attacks
Decrypted Message: it is not practical to rely solely on symmetric encryption
Decrypted Message: i shall never reuse the same password on multiple accounts
Decrypted Message: peer review of security mechanisms reduces vulnerabilities
Decrypted Message: learning how to write secure software is a necessary skill
Decrypted Message: secure key exchange is needed for symmetric key encryption
Decrypted Message: security at the expense of usability could damage security
                 
