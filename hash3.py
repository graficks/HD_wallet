import hashlib
import binascii
import base58
import hmac

N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

#Perform SHA on binary
binary_seed = "01011100010 11101100111 00010100110 10000001010 01110101111 10100001101 11100100000 00110000110 10110000001 10010000101 01001100001 0000100"

binary_seed = binary_seed.replace(" ","")
binary_seed = int(binary_seed, 2)
binary_seed = hex(binary_seed)
hex_seed = binary_seed[2:]
print("hex_seed: ")
print(hex_seed)
#the random 128 or 256 bits of entropy are hashed to get a checksum
#The first 4 or 8 bits of the hash are added to the random number to get the right number of bits to convert to wordlist

sha1 = hashlib.sha256()
sha1.update(bytes.fromhex(hex_seed))
print("sha hexdigest: ")
print(sha1.hexdigest())

if(len(hex_seed) == 32): seed = hex_seed + sha1.hexdigest()[:1]
if(len(hex_seed) == 64): seed = hex_seed + sha1.hexdigest()[:2]
print("seed plus checksum: ")
print(seed)

seed = int(seed, 16)
seed = bin(seed)
seed = seed[2:]
while(len(seed) != 132 and len(seed) != 264): seed = "0" + seed
print("binary seed: ")
print(seed)
word_list = open("wordlist.txt")
lines = word_list.readlines()
mnemonic = ""
for x in range(int(len(seed)/11)):
    word_index = int(seed[x*11 : x*11 + 11], 2)
    mnemonic += lines[word_index] + " "

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
print(bip39_seed.hex())
#bytes(mnemonic, 'utf-8')
#mnemonic.encode('utf-8')

#bip32
bip32_hash = hmac.new(b"Bitcoin seed", bip39_seed, digestmod=hashlib.sha512).digest()
#depth = 0, master node
master_chain_code = bip32_hash[32:]
master_key = bip32_hash[:32]
print("master_chain_code: ")
print(master_chain_code.hex())
print("master_key: ")
print(master_key.hex())
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
print(str(base58.b58encode(bip32_ext_key))[2:-1])


#44' = bip44 = \x2c                        \x00 for privkey
bip44_hash = hmac.new(master_chain_code, b'\x00' + master_key + b'\x80\x00\x00\x2c', digestmod=hashlib.sha512).digest()
#depth = 01, fingerprint = ripemd(sha256(parentpriv)) or parentpubkey
print(base58.b58decode("VnPvBVZi7cmfCdSH2GPKUhm14mpdXyq5bH").hex()[2:10])

print("parent fingerprint: ")
rip = hashlib.new('ripemd160')
rip.update(hashlib.sha256(master_key).digest())
print(rip.hexdigest())

bip44_chain_code = bip44_hash[32:]
bip44_key = bip44_hash[:32]
bip44_key = bytes.fromhex(hex( ( int(bip44_key.hex(), 16) + int(master_key.hex(), 16) ) % N )[2:])
print("bip44_key: ")
print(bip44_key.hex())
print("bip44_chain_code: ")
print(bip44_chain_code.hex())

vertcoin_seed = hmac.new(master_chain_code, b'\x00' + master_key + b'\x80\x00\x00\x1c', digestmod=hashlib.sha512).digest()
vertcoin_chain_code = vertcoin_seed[32:]
vertcoin_key = vertcoin_seed[:32]
#vertcoin_key = ( vertcoin_key.hex() + master_key.hex() ) % N
