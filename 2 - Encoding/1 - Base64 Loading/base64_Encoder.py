import sys
import base64


try:
    content = open(sys.argv[1], "rb").read()
except:
    print("Usage: .\base64.py PAYLOAD_FILE")
    sys.exit()
    

b64 = base64.b64encode(content)
print(b64.decode("utf-8"))
    
    