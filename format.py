import sys

def printResult(content):
    
    print('unsigned char shellcode[] = { 0x' + ', 0x'.join(hex(x)[2:] for x in content) + ' };')
    
try:
    file = open(sys.argv[1], "rb")
    content = file.read()
except:
    print("Usage: .\format.py PAYLOAD_FILE")
    sys.exit()

printResult(content)


