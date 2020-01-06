import hashlib
import binascii
import base58
import hmac


# Below are the public specs for Bitcoin's curve - the secp256k1
Pcurve = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 -1 # The proven prime
N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 # Number of points in the field
Acurve = 0; Bcurve = 7 # This defines the curve. y^2 = x^3 + Acurve * x + Bcurve
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
#Gx, Gy are the x and y coordinates of the generator point

def modinv(a,n=Pcurve): #Extended Euclidean Algorithm/'division' in elliptic curves
    lm, hm = 1,0
    low, high = a%n,n
    while low > 1:
        ratio = int(high/low)
        nm, new = hm-lm*ratio, high-low*ratio
        lm, low, hm, high = nm, new, lm, low
    return lm % n

def ECadd(xp,yp,xq,yq): # Not true addition, invented for EC. It adds Point-P with Point-Q.
    m = ((yq-yp) * modinv(xq-xp,Pcurve)) % Pcurve
    xr = (m*m-xp-xq) % Pcurve
    yr = (m*(xp-xr)-yp) % Pcurve
    return (xr,yr)

def ECdouble(xp,yp): # EC point doubling,  invented for EC. It doubles Point-P.
    LamNumer = 3*xp*xp+Acurve
    LamDenom = 2*yp
    Lam = (LamNumer * modinv(LamDenom,Pcurve)) % Pcurve
    xr = (Lam*Lam-2*xp) % Pcurve
    yr = (Lam*(xp-xr)-yp) % Pcurve
    return (xr,yr)

def ECmultiply(xs,ys,Scalar): # Double & add. EC Multiplication, Not true multiplication
    if Scalar == 0 or Scalar > N: raise Exception("Invalid Scalar/Private Key")
    ScalarBin = str(bin(Scalar))[2:]
    Qx,Qy=xs,ys
    counter = 1
    #most significant bits first
    for i in range (1, len(ScalarBin)):
        Qx,Qy=ECdouble(Qx,Qy);
        counter *= 2
        if ScalarBin[i] == "1":
            Qx,Qy=ECadd(Qx,Qy,xs,ys);
            counter += 1
    #print( counter #this will equal the private key
    return (Qx,Qy)

def ECmultiply2(xs,ys,Scalar):
    if Scalar == 0 or Scalar > N: raise Exception("Invalid Scalar/Private Key")
    ScalarBin = str(bin(Scalar))[2:]
    ScalarBin = ScalarBin[::-1]
    result = None; counter = 0; addend = 1
    #least significant bits first
    for i in range (len(ScalarBin)):
        if ScalarBin[i] == "1":
          counter += addend
          if(result == None):
            result = xs,ys
          else:
            result=ECadd(result[0],result[1],xs,ys)
        xs,ys=ECdouble(xs,ys)
        addend *= 2
    #print( counter #this will equal the private key
    return (result[0], result[1])

def pub_key_gen(x_pub_key, y_pub_key):

    #print( "step 1: generate pubkey:")
    #the uncompressed public key (starts with '04' & is not the public address)
    #[2:]: takes out leading 0x
    uncompressed_pub_key = "04" + hex(x_pub_key)[2:] + hex(y_pub_key)[2:]

    if(int(y_pub_key) % 2 == 0): first_byte = "02"
    else: first_byte = "03"
    compressed_pubkey = first_byte + hex(x_pub_key)[2:]

    #print( "step 2: hash of 1 byte plus x coordinate  "
    sha1 = hashlib.sha256()
    sha1.update(bytes.fromhex(compressed_pubkey))
    hash1 = sha1.digest()

    #print( "step 3: perform ripemd160 on previous result:")
    ripemd = hashlib.new('ripemd160')
    ripemd.update(hash1)
    input_scriptpubkey = ripemd.hexdigest()

    #print( "step 4: Add byte in front of RIPEMD-160 hash (0x00 for Main Network)  "
    #00 for bitcoin. 0x30 for lite. 0x47 for vert
    ripemd_ext = "47" + ripemd.hexdigest()

    #print( "step 5: sha256 previous hash  "
    ripemd_ext = bytes.fromhex(ripemd_ext)
    sha2 = hashlib.sha256()
    sha2.update(ripemd_ext)
    hash2 = sha2.digest()

    #print( "step 6: sha256 previous hash  "
    sha3 = hashlib.sha256()
    sha3.update(hash2)
    hash3 = sha3.digest()

    #print( "step 7: first 4 bytes of previous hash. This is the address checksum  "

    #print( "step 8: add 4 bytes from step 7 to end of step 4 hash  "
    hash4 = ripemd_ext.hex() + hash3.hex()[:8]

    #print( "step 9: base58 encoded address:")
    public_address = base58.b58encode(bytes.fromhex(hash4))
    return public_address, input_scriptpubkey


binary_seed = "01011100010 11101100111 00010100110 10000001010 01110101111 10100001101 11100100000 00110000110 10110000001 10010000101 01001100001 0000100"
binary_seed = binary_seed.replace(" ","")
def hex_seed(bin_seed):
    bin_seed = int(bin_seed, 2)
    bin_seed = hex(bin_seed)
    hex_seed = bin_seed[2:]
    #the random 128 or 256 bits of entropy are hashed to get a checksum
    #The first 4 or 8 bits of the hash are added to the random number to get the right number of bits to convert to wordlist

    sha1 = hashlib.sha256()
    sha1.update(bytes.fromhex(hex_seed))

    if(len(hex_seed) == 32): seed = hex_seed + sha1.hexdigest()[:1]
    if(len(hex_seed) == 64): seed = hex_seed + sha1.hexdigest()[:2]
    print("hex_seed: ")
    print(seed)
    return seed

def mnemonic_from_seed(seed):
    seed = int(seed, 16)
    seed = bin(seed)
    seed = seed[2:]
    while(len(seed) != 132 and len(seed) != 264): seed = "0" + seed
    word_list = open("wordlist.txt")
    lines = word_list.readlines()
    mnemonic = ""
    for x in range(int(len(seed)/11)):
        word_index = int(seed[x*11 : x*11 + 11], 2)
        mnemonic += lines[word_index] + " "
    return mnemonic

def bip39_seed_from_mnemonic(mnemonic):
    mnemonic = mnemonic.replace('\n','')
    #remove the last space
    mnemonic = mnemonic[:-1]
    print("mnemonic: ")
    print(repr(mnemonic))
    mnemonic = bytes(mnemonic, 'utf8')
    salt = "mnemonic".encode('utf8')
    bip39_seed = hashlib.pbkdf2_hmac('sha512', mnemonic, salt, 2048)
    #bip39_seed = bip39_seed.hex()
    print("bip39_seed: ")
    print( bip39_seed.hex())
    return bip39_seed
    #bytes(mnemonic, 'utf-8')
    #mnemonic.encode('utf-8')

def bip32_ext_key_from_bip39_seed(bip39_seed):
    bip32_hash = hmac.new(b"Bitcoin seed", bip39_seed, digestmod=hashlib.sha512).digest()
    #depth = 0, master node
    master_chain_code = bip32_hash[32:]
    master_key = bip32_hash[:32]
    #(serialization format bip32) version, depth, parent's fingerprint, child number, chain code, 00 for private keys
    bip32_ext_key = b"\x04\x88\xad\xe4"  # xprv
    bip32_ext_key += b"\x00" * 9  # Depth, parent fingerprint, and child number
    bip32_ext_key += master_chain_code  # Chain code
    bip32_ext_key += b"\x00" + master_key  # Master key

    # Double hash using SHA256
    checksum = hashlib.sha256(bip32_ext_key).digest()
    checksum = hashlib.sha256(checksum).digest()
    bip32_ext_key += checksum[:4]

    #print(bip32_ext_key.hex())
    print("bip32_ext_key: ") #or bip32 root key
    print( str(base58.b58encode(bip32_ext_key))[2:-1])
    return str(base58.b58encode(bip32_ext_key))[2:-1]

def bip44_ext_key_from_bip32_ext_key(bip32_ext_key):
    bip32_ext_key = base58.b58decode(bip32_ext_key)
    master_key = bytes.fromhex(bip32_ext_key.hex()[92:92+64])
    master_chain_code = bytes.fromhex(bip32_ext_key.hex()[26:26+64])

    #44' = bip44 = \x2c                        \x00 for privkey
    bip44_hash = hmac.new(master_chain_code, b'\x00' + master_key + b'\x80\x00\x00\x2c', digestmod=hashlib.sha512).digest()
    #depth = 01, fingerprint = ripemd(sha256(parentpriv)) or parentpubkey
    bip44_priv_key = bip44_hash[:32] #master key
    #add to master_key and modulus with N
    bip44_priv_key = bytes.fromhex(hex( ( int(bip44_priv_key.hex(), 16) + int(master_key.hex(), 16) ) % N )[2:])
    bip44_chain_code = bip44_hash[32:]

    x_pub_key, y_pub_key = ECmultiply2(Gx,Gy,int(master_key.hex(), 16))
    public_address, input_scriptpubkey = pub_key_gen(x_pub_key, y_pub_key)
    fingerprint = base58.b58decode(public_address).hex()[2:10]

    bip44_ext_key  = b"\x04\x88\xad\xe4"  # xprv
    bip44_ext_key += b"\x01"  # Depth
    bip44_ext_key += bytes.fromhex(fingerprint) #parent fingerprint
    bip44_ext_key += b'\x80\x00\x00\x2c' #child number for bip44
    bip44_ext_key += bip44_chain_code
    bip44_ext_key += b'\x00' + bip44_priv_key

    # Double hash using SHA256
    checksum = hashlib.sha256(bip44_ext_key).digest()
    checksum = hashlib.sha256(checksum).digest()
    bip44_ext_key += checksum[:4]

    bip44_ext_key = str(base58.b58encode(bip44_ext_key))[2:-1]
    print("bip44_ext_key: ")
    print(bip44_ext_key)
    return bip44_ext_key

def bip44_path_level(depth, index, parent_key):
    parent_ext_key = base58.b58decode(parent_key)
    parent_priv_key = bytes.fromhex(parent_ext_key.hex()[92:92+64])
    parent_chain_code = bytes.fromhex(parent_ext_key.hex()[26:26+64])

    if(int(index.hex(), 16) >= int('80000000', 16)):

        sha512 = hmac.new(parent_chain_code, b'\x00' + parent_priv_key + index, digestmod=hashlib.sha512).digest()

        priv_key = sha512[:32]
        priv_key = bytes.fromhex(hex( ( int(priv_key.hex(), 16) + int(parent_priv_key.hex(), 16) ) % N )[2:])
        chain_code = sha512[32:]

        x_pub_key, y_pub_key = ECmultiply2(Gx,Gy,int(parent_priv_key.hex(), 16))
        public_address, input_scriptpubkey = pub_key_gen(x_pub_key, y_pub_key)
        fingerprint = base58.b58decode(public_address).hex()[2:10]

    else:
        x_pub_key, y_pub_key = ECmultiply2(Gx,Gy,int(parent_priv_key.hex(), 16))
        public_address, input_scriptpubkey = pub_key_gen(x_pub_key, y_pub_key)
        fingerprint = base58.b58decode(public_address).hex()[2:10]
        if(int(y_pub_key) % 2 == 0): first_byte = "02"
        else: first_byte = "03"
        compressed_pubkey = first_byte + hex(x_pub_key)[2:]

        sha512 = hmac.new(parent_chain_code, bytes.fromhex(compressed_pubkey) + index, digestmod=hashlib.sha512).digest()

        priv_key = sha512[:32]
        priv_key = bytes.fromhex(hex( ( int(priv_key.hex(), 16) + int(parent_priv_key.hex(), 16) ) % N )[2:])
        chain_code = sha512[32:]

    ext_key  = b"\x04\x88\xad\xe4"  # xprv
    ext_key += depth  # Depth
    ext_key += bytes.fromhex(fingerprint) #parent fingerprint
    ext_key += index
    ext_key += chain_code
    ext_key += b'\x00' + priv_key

    # Double hash using SHA256
    checksum = hashlib.sha256(ext_key).digest()
    checksum = hashlib.sha256(checksum).digest()
    ext_key += checksum[:4]

    ext_key = str(base58.b58encode(ext_key))[2:-1]
    print("ext_key: ")
    print(ext_key)
    return ext_key



if __name__ == '__main__':
    seed = hex_seed(binary_seed)
    mnemonic = mnemonic_from_seed(seed)
    bip39_seed = bip39_seed_from_mnemonic(mnemonic)
    bip32_ext_key = bip32_ext_key_from_bip39_seed(bip39_seed)
    bip44_ext_key = bip44_ext_key_from_bip32_ext_key(bip32_ext_key)
    vert = bip44_path_level(b'\x02', b'\x80\x00\x00\x1c', bip44_ext_key)
    vert_account = bip44_path_level(b'\x03', b'\x80\x00\x00\x00', vert)
    vert_change = bip44_path_level(b'\x04', b'\x00\x00\x00\x00', vert_account)
    vert_address = bip44_path_level(b'\x05', b'\x00\x00\x00\x00', vert_change)
