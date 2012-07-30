#!/usr/bin/python
import sys, re, struct

print 'KeepassX file extract from dump'

if len(sys.argv) != 2:
    print "%s <procdump>" % sys.argv[0]

f = open(sys.argv[1], 'r')
data = f.read()
f.close()

cpt=1

for m in re.finditer(b"\x03\xd9\xa2\x9a\x65\xfb\x4b\xb5", data):
    print '%08x-%08x: %s' % (m.start(), m.end(), m.group(0).encode("hex"))
    filename = "PasswordDb%d.kdb" % cpt
    print " [*] Dump until 2 NULL bytes in %s" % filename

    f = open(filename, 'wb')

    begin = m.start()

    # header size 124
    for i in range(0, 124):
        f.write(data[begin + i])
    i += 1
    while 1:
        if data[begin + i] == chr(0) and data[begin + i + 1] == chr(0):
            break

        f.write(data[begin + i])
        i += 1

    print " [*] Dump on %d bytes" % i
    f.close()
	
    cpt += 1
