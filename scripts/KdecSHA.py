#!/usr/bin/python
import sys, hashlib, struct
from Crypto.Cipher import AES

if len(sys.argv) != 3:
    print "%s <keepassdb> <sha256>" % sys.argv[0]
    sys.exit(1)

PasswordHash = sys.argv[2].decode("hex")
f = open(sys.argv[1], 'rb')

# Flags is a uint32
f.seek(8, 0)
Flags = f.read(4)
Flags = struct.unpack('I', Flags)[0]
#print "Flags %u" % Flags

# FinalRandomSeed
f.seek(16, 0)
FinalRandomSeed = f.read(16)

# Encryption IV
EncryptionIV = f.read(16)

# ContentHash
f.seek(56,0)
ContentsHash = f.read(32)

# TransfRandomSeed
TransfRandomSeed = f.read(32)

# KeyTransfRounds uint32
KeyTransfRounds = f.read(4)
KeyTransfRounds = struct.unpack('I', KeyTransfRounds)[0]
#print "KeyTransfRounds %u" % KeyTransfRounds 

# Data
f.seek(124,0) # To be sure
Data = f.read()


#print "RawMasterKey %s" % PasswordHash.encode("hex")

# Key transform part (PasswordHash, TransfRandomSeed, KeyTransfRounds)
# return a sha256 hash
part1 = PasswordHash[:16]
part2 = PasswordHash[16:]

# Transform part
crypt = AES.new(TransfRandomSeed, AES.MODE_ECB)
for i in range(KeyTransfRounds):
    part1 = crypt.encrypt(part1)
crypt = AES.new(TransfRandomSeed, AES.MODE_ECB)
for i in range(KeyTransfRounds):
    part2 = crypt.encrypt(part2)


# Construct the hash
m = hashlib.sha256()
m.update(part1)
m.update(part2)
TransfPasswordHash = m.digest()

#print "MasterKey %s" % TransfPasswordHash.encode("hex")

# Compute the true password hash
m = hashlib.sha256()
m.update(FinalRandomSeed)
m.update(TransfPasswordHash)
PasswordHash = m.digest()

#print "FinalKey %s" % PasswordHash.encode("hex")
#print "EncryptionIV %s" % EncryptionIV.encode("hex")

# Decrypt data with the found hash
if Flags & 2: # AES
    #print "AES"
    crypt = AES.new(PasswordHash, AES.MODE_CBC, EncryptionIV)
    DecData = crypt.decrypt(Data)
elif Flags & 4: # TWOFISH
    print "TWOFISH"
    sys.exit(1)
else:
    print "Algo not supported"
    sys.exit(1)

OffsetPad = ord(DecData[-1])
#print "OffsetPad: %d" % OffsetPad
DecData = DecData[:-OffsetPad]

# Generate decrypted data hash
m = hashlib.sha256()
m.update(DecData)
DecDataHash = m.digest()

if DecDataHash != ContentsHash:
    print "Failed %s != %s" % (DecDataHash.encode("hex"), ContentsHash.encode("hex"))
    
filename = sys.argv[1]+".dec"
print "Write decrypted content in %s" % filename
f = open(filename, 'w')
f.write(DecData[:-1])
f.close()
