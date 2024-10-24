import numpy as np


# Ciphertext must be twice the length of the message

filename='Asg2_ciphertexts.txt'
with open(filename, "r") as file:
    ciphertexts= [line.strip() for line in file if line.strip()]

d=0
flag=False
rows, cols = 8, len(ciphertexts[0])
# space_xor_cipher = [['' for _ in range(cols)] for _ in range(rows)]
space_xor_cipher = np.full((len(ciphertexts[0])), "", dtype='U1')
plaintext = np.full((8, len(ciphertexts[0]) // 2), "*", dtype='U1') 

for i in range(8):
    j=0
    while(j<len(ciphertexts[0])):
        thr=6 # max threshold is 7  because it is xored with 7 rows
        c=0
        for x in range(8):
          xor=int(ciphertexts[i][j],16)^int(ciphertexts[x][j],16)
        #   print(xor) # we see that the xor result is in {4,5,0,1} but the space occurs if the result is 0 (space^space) or number (space xor letter) but 1 means that it's a letter xor another letter
          if(xor in [4,5,0]):
              c=c+1
              if(c>thr): #if it happens more than threshold time than that means that the possibility that this is a space is higher
                flag=True
                # print(i,j) #position of spaces
                break
          else:
              flag=False
              break
        if(flag): # flag== True means that [i][j] position is a guessed space so we xor it with the cipher then the result we xor it with the cipher to get the plaintext
            c1 = ciphertexts[i][j:j + 2]  
            xo = int(c1, 16) ^ int('20', 16) #deduce parts of the key
            space_xor_cipher[j] = format(xo, 'X')  
            space_xor_cipher[j + 1] = ciphertexts[i][j + 1]
            d=d+1
        j=j+2

def guess_message(ciphertexts, space_xor_cipher): 

    for i in range(8):
        for j in range(0, len(ciphertexts[0]), 2):
            if space_xor_cipher[j] != '':
                c1 = ciphertexts[i][j]
                c2 = ciphertexts[i][j + 1] 
                # here we xor the spaces with the ciphertexts(deduced key) to obtain the text in the positions of the spaces
                # we did it twice because the space_xor_cipher[j] have the xored done above and space_xor_cipher[j + 1] have ciphertext[i][j + 1]
                p1 = format(int(c1, 16) ^ int(space_xor_cipher[j], 16), 'X')
                p2 = format(int(c2, 16) ^ int(space_xor_cipher[j + 1], 16), 'X') 
                p = str(p1) + str(p2)
                
                try:
                    byte_string = bytes.fromhex(p)
                    ascii_char = byte_string.decode('utf-8')
                    if ascii_char.isalpha() or ascii_char.isspace():
                        plaintext[i][j // 2] = ascii_char
                except UnicodeDecodeError:
                    pass

    return plaintext

plaintext = guess_message(ciphertexts, space_xor_cipher)

# Print the decrypted plaintext
for row in plaintext:
    print(''.join(row))


def get_key_from_cipher_and_message(ciphertext, message):
    key = []

    for i in range(0, len(ciphertext), 2):
        c=ciphertext[i:i + 2]
        m = ord(message[i // 2])  # Message byte (ASCII)
        xor = int(c, 16) ^ m
        key.append(format(xor, '02X'))

    return ''.join(key)

def get_message_from_cipher_and_key(ciphertext, key):
    decrypted_message = []
    for i in range(0, len(ciphertext), 2):
        c=ciphertext[i:i + 2]
        k=key[i:i + 2]
        text = int(c,16) ^ int(k,16)
        decrypted_message.append(format(text, '02X'))
    # Convert decrypted bytes to ASCII
    plaintext = ''.join([chr(int(byte, 16)) for byte in decrypted_message])
    return plaintext



# I guessed one phrase to xor it with it's cipher to get the key and use it to get all the messages
message='modern cryptography requires careful multilingual analysis'
cipher='F9B4228898864FCB32D83F3DFD7589F109E33988FA8C7A9E9170FB923065F52DD648AA2B8359E1D122122738A8B9998BE278B2BD7CF3313C7609'

key = get_key_from_cipher_and_message(cipher, message)
print("Derived Key:", key)
for ciphertext in ciphertexts:
    plaintext = get_message_from_cipher_and_key(ciphertext, key)
    print("Decrypted Message:", plaintext)


# here we see that the guess of the before last word in the cipher text is wrong because using the key the other messages in this place doesn't make sense so we could use another phrase to detect the key which this part is easy
message='secure key exchange is needed for symmetric key encryption'
cipher='E7BE2598988D4FC325D86F2CEA7193F117EC2588E19A2B859D67FA847426F230C10EAC3ECE55EAC170092D7FACAE8FDEF436B0A164EF3C267014'

key = get_key_from_cipher_and_message(cipher, message)
print("Derived Key:", key)
for ciphertext in ciphertexts:
    plaintext = get_message_from_cipher_and_key(ciphertext, key)
    print("Decrypted Message:", plaintext)



# OUTPUTS

# messages not completed

# *od*rn cryptogra*** *e*u**es ****ful *****ig*r*u* a*a*****
# *dd*ess randomiz***o* *o**d p****nt m***C*ou* *a*l *t*****
# *t *s not practi*** *o*r**y s****y onc**M*et*i* *nc*y*****
# * s*all never re*** *h* **me ****wordc****ul*i*l* a*c*****
# *ee* review of s***r*t* **cha****s re***E* v*l*e*ab*l*****
# *ea*ning how to ***t* *e**re ****warec**** n*c*s*ar* *****
# *ec*re key excha*** *s*n**ded**** sym***R*c *e* *nc*y*****
# *ec*rity at the ***e*s* ** us* **ity  **L* d*m*g* s*c*****


# Derived Key: 94DB46EDEAE86FA840A14F499212FB90798B40A888E90BEBF8029EE11006945FB32EDF47A3388FB502604E5FC7CBF6FE9158D3D31D9F484F1F7A       

# completed messages 

# Decrypted Message: modern cryptography requires careful and rigorous analysis
# Decrypted Message: address randomization could prevent malicious call attacks
# Decrypted Message: it is not practical to rely solely on symmetric encryption
# Decrypted Message: i shall never reuse the same password on multiple accounts
# Decrypted Message: peer review of security mechanisms reduces vulnerabilities
# Decrypted Message: learning how to write secure software is a necessary skill
# Decrypted Message: secure key exchange is needed for symmetric key encryption
# Decrypted Message: security at the expense of usability could damage security

