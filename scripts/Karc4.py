#!/usr/bin/python
import sys, struct

# Fucked ARC4 in key prepare
def arc4(key, data):
    btBufDep = ((len(data) & 0xFF) << 1);
    x = 0
    box = range(256)
    for i in range(256):
        x = (x + box[i] + ord(key[i % len(key)]) + btBufDep) % 256 
        box[0], box[x] = box[x], box[0]

    x = y = 0
    out = []
    for char in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out.append(chr(ord(char) ^ box[(box[x] + box[y]) % 256]))
    
    return ''.join(out)    

if len(sys.argv) != 3:
    print "%s <hexkey> <hexdata>" % sys.argv[0]
    sys.exit(1)

PasswordHash = arc4(sys.argv[1].decode("hex"), 
    sys.argv[2].decode("hex"))
print "Result:"
print PasswordHash.encode("hex")

