import hashlib
import binascii
#Perform SHA on binary

binary_seed = "11011010101 00001011000 11000110011 00101110011 01011100100 10011010111 00111011101 01100001000 11001000110 10110001111 11000111000 0010001"

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
print(repr(mnemonic))
salt = "mnemonic"+""
bip39_seed = hashlib.pbkdf2_hmac('sha512', mnemonic, salt, 2048)
print("bip39_seed: ")
print(bip39_seed.encode('hex'))
