import hashlib
import binascii
import base58
import hmac
#Perform SHA on binary

binary_seed = "01011100010 11101100111 00010100110 10000001010 01110101111 10100001101 11100100000 00110000110 10110000001 10010000101 01001100001 0000100"

binary_seed = binary_seed.replace(" ","")
binary_seed = int(binary_seed, 2)
binary_seed = hex(binary_seed)
hex_seed = binary_seed[2:-1]
print("hex_seed: ")
print(hex_seed)
#the random 128 or 256 bits of entropy are hashed to get a checksum
#The first 4 or 8 bits of the hash are added to the random number to get the right number of bits to convert to wordlist

sha1 = hashlib.sha256()
sha1.update(hex_seed.decode('hex'))
print("sha hexdigest: ")
print(sha1.hexdigest())

if(len(hex_seed) == 32): seed = hex_seed + sha1.hexdigest()[:1]
if(len(hex_seed) == 64): seed = hex_seed + sha1.hexdigest()[:2]
print("seed plus checksum: ")
print(seed)
#there is really no reason to convert to binary again except it sort of follows the protocol
seed = int(seed, 16)
seed = bin(seed)
seed = seed[2:]
while(len(seed) != 132 and len(seed) != 264): seed = "0" + seed
print("binary seed: ")
print(seed)
word_list = open("wordlist.txt")
lines = word_list.readlines()
mnemonic = ""
for x in range(len(seed)/11):
    word_index = int(seed[x*11 : x*11 + 11], 2)
    #including the space you fucking moron
    mnemonic += lines[word_index] + " "

#for loops adds new lines, I don't know why
mnemonic = mnemonic.replace('\n','')
#remove the last space
mnemonic = mnemonic[:-1]
#Doesn't even have to be encoded
print("mnemonic: ")
print(repr(mnemonic))
salt = "mnemonic"+""
bip39_seed = hashlib.pbkdf2_hmac('sha512', mnemonic, salt, 2048)
#bip39_seed = bip39_seed.encode('hex')
print("bip39_seed: ")
print(bip39_seed.encode('hex'))

print("bip32_ext_key: ") #or bip32 root key
bip32_hash = hmac.new(b"Bitcoin seed", bip39_seed, digestmod=hashlib.sha512).digest()
#(serialization format bip32) version, depth, parent's fingerprint, child number, chain code, 00 for private keys
bip32_ext_key = b"\x04\x88\xad\xe4"  # Version for private mainnet
bip32_ext_key += b"\x00" * 9  # Depth, parent fingerprint, and child number
bip32_ext_key += bip32_hash[32:]  # Chain code
bip32_ext_key += b"\x00" + bip32_hash[:32]  # Master key

# Double hash using SHA256
checksum = hashlib.sha256(bip32_ext_key).digest()
checksum = hashlib.sha256(checksum).digest()
bip32_ext_key += checksum[:4]

#print(bip32_ext_key.encode('hex'))
print(base58.b58encode(bip32_ext_key))
