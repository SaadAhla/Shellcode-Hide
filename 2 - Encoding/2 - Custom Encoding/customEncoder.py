# python3 
import sys

def Encode(data):
    cipherText = ""
    for i in range(len(data)):
        if i % 2 == 0:
            cipherText += chr(data[i]+1)
        else:
            cipherText += chr(data[i]+2)
    return cipherText


def printCiphertext(ciphertext):
	print('{ 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };')


try:
    content = open(sys.argv[1], "rb").read()
    
except:
    print("Usage: .\Encoder.py PAYLOAD_FILE")
    sys.exit()


cipherText = Encode(content)
printCiphertext(cipherText)
    
    