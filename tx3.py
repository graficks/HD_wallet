#Python 2.7
import hashlib
import base58
# Below are the public specs for Bitcoin's curve - the secp256k1
Pcurve = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 -1 # The proven prime
N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 # Number of points in the field
Acurve = 0; Bcurve = 7 # This defines the curve. y^2 = x^3 + Acurve * x + Bcurve
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
#Gx, Gy are the x and y coordinates of the generator point

address_to_send_to = "Vrz9oQy69zyMXWZZJ47BkWUhCXnJ4bjCXu"
prev_tx_raw_input = "01000000012188b8352e369611f962609894f6dcdc9751c433b3d450cfbaf4cc5fb4725425000000006a47304402207de658b859b9f692f0e1a748cec128b7738b6106ce9581dba1d2fbaa4e75ac19022045c39ff84bdcef80fa7214276ef648d05dece567d535561632ad4f3e0e0aeb80012103ab57676352c071d268d1bc7c8c23e385e06277d57cf1f7108ff93d007cc6e36dffffffff01b03fba00000000001976a9143c40cb63968ad9f4781c1dc861b2a67834ad03ea88ac00000000"
value = "008cb90000000000" #8 bytes, reversed, little endian

#wallet import format to privkey
#priv key ( L158yYYjRJRU4V1pt3whD55vtr6hGEV5uqAmKdUy127MBcZdQSJz )
#to address( VfVR5DjRdVpVD6QkR5mKihJ7wA6GNtc14c )
#priv key ( L2jdhtsLtvK7RvUcG16F55NGmCRDSHn56SApj3WJhXGAQ5vpoB2c )
#to address( Vrz9oQy69zyMXWZZJ47BkWUhCXnJ4bjCXu )
wif_key = "L158yYYjRJRU4V1pt3whD55vtr6hGEV5uqAmKdUy127MBcZdQSJz"
wif_key_base58de = base58.b58decode(wif_key)
imported_priv_key = wif_key_base58de.hex()
#starts with 80(supposed to be removed), drop the last 4 bytes
imported_priv_key = imported_priv_key[2:-8]
#if WIF starts with K or L the last byte will be 01. remove it
if(wif_key[0] == "K" or wif_key[0] == "L" and imported_priv_key[-2:] == "01"):
    imported_priv_key = imported_priv_key[:-2]
print( "imported priv key: ")
print( imported_priv_key)

privKey = int("0x" + imported_priv_key, 0)
privKey = int("0x" + "73db8a4cb573fd136ca03c7ceb46660573cd399ff2fd7382198f94f4227b4ee7", 0)
#random number has to be lower than number of points in the field
#privKey = 115792089237316195423570985008687907852837564279074904382605163141518161491337
#N =      115792089237316195423570985008687907852837564279074904382605163141518161494337
RandNum = 115222794527730373379072786348474718560158445381389579684235921886932420000000

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

print(); print( "******* Public Key Generation *********")
xPublicKey, yPublicKey = ECmultiply(Gx,Gy,privKey)

print( "step 0: private key:")
print( "the private key (in base 10 format):"); print( privKey)
print( "the private key (in base 16 format):"); print( hex(privKey)); print()

print( "step 1: generate pubkey:")
#the uncompressed public key (starts with '04' & is not the public address)
#[2:-1]: takes out leading 0x, and trailing L
uncompressed_pub_key = "04" + hex(xPublicKey)[2:] + hex(yPublicKey)[2:]
print( "X coordinate of uncompressed pub key: ")
print( hex(xPublicKey)[2:])
print( "Y coordinate of uncompressed pub key: ")
print( hex(yPublicKey)[2:])
print()

if(int(yPublicKey) % 2 == 0): first_byte = "02"
else: first_byte = "03"
compressed_pubkey = first_byte + hex(xPublicKey)[2:]
scriptsig_pubkey = compressed_pubkey
print( "compressed public key: ")
print( compressed_pubkey ); print()

#print( "step 2: hash of 1 byte plus x coordinate  "
sha1 = hashlib.sha256()
#must decode to hex before hashing
sha1.update(bytes.fromhex(compressed_pubkey))
hash1 = sha1.digest()
#print( hash1.encode('hex') ; print(

print( "step 3: perform ripemd160 on previous result:")
ripemd = hashlib.new('ripemd160')
ripemd.update(hash1)
input_scriptpubkey = ripemd.hexdigest()
print( ripemd.hexdigest() ); print()

#print( "step 4: Add byte in front of RIPEMD-160 hash (0x00 for Main Network)  "
#00 for bitcoin. 0x30 for lite. 0x47 for vert
ripemd_ext = "47" + ripemd.hexdigest()
#print( ripemd_ext ; print(

#print( "step 5: sha256 previous hash  "
ripemd_ext = bytes.fromhex(ripemd_ext)
sha2 = hashlib.sha256()
sha2.update(ripemd_ext)
hash2 = sha2.digest()
#print( hash2.encode('hex') ; print(

#print( "step 6: sha256 previous hash  "
sha3 = hashlib.sha256()
sha3.update(hash2)
hash3 = sha3.digest()
#print( hash3.encode('hex') ; print(

#print( "step 7: first 4 bytes of previous hash. This is the address checksum  "
#print( hash3.encode('hex')[:8] ; print(

#print( "step 8: add 4 bytes from step 7 to end of step 4 hash  "
hash4 = ripemd_ext.hex() + hash3.hex()[:8]
#print( hash4; print(

print( "step 9: base58 encoded address:")
public_address = base58.b58encode(bytes.fromhex(hash4))
print( public_address); print()

#double sha of entire raw transaction is TX ID, we need the TX ID of the transaction we want to redeem
#this is put in our TX so everyone knows which input we are trying to use
double_sha  = hashlib.sha256()
double_sha2 = hashlib.sha256()
prev_tx_raw_input = "01000000012188b8352e369611f962609894f6dcdc9751c433b3d450cfbaf4cc5fb4725425000000006a47304402207de658b859b9f692f0e1a748cec128b7738b6106ce9581dba1d2fbaa4e75ac19022045c39ff84bdcef80fa7214276ef648d05dece567d535561632ad4f3e0e0aeb80012103ab57676352c071d268d1bc7c8c23e385e06277d57cf1f7108ff93d007cc6e36dffffffff01b03fba00000000001976a9143c40cb63968ad9f4781c1dc861b2a67834ad03ea88ac00000000"
double_sha.update( bytes.fromhex(prev_tx_raw_input) )
double_sha2.update( double_sha.digest() )
print( "tx ID of previous transaction:")
#[::-1] reverses the bytes, used to read from block explorer
#In the raw TX we use little endian form
print( double_sha2.digest()[::-1].hex())
prev_tx_hash = double_sha2.digest().hex()
print()

print( "derive scriptpubkey from public address I want to send to:")
#the decoded address is used for scriptpubkey. Remove the first byte and the last 4
#If the reciever put their private key into this code, output_scriptpubkey would be their step 3
address_to_send_to = "Vrz9oQy69zyMXWZZJ47BkWUhCXnJ4bjCXu"
output_scriptpubkey = base58.b58decode(address_to_send_to).hex()
output_scriptpubkey = output_scriptpubkey[2:-8]
#Pay to PubkeyHash = OP_DUP(0x76) OP_HASH160(0xa9) bytes to push(0x14) <PUB-KEY-HASH> OP_EQUALVERIFY(0x88) OP_CHECKSIG(0xac)
#scriptpubkey is all these combined, so it is a misnomer until this line. Pay to PubkeyHash defines what should be in the scriptpubkey and scriptsig
#It is the standard script that must be satified for the TX to be valid
output_scriptpubkey = "76a914" + output_scriptpubkey + "88ac"
print( output_scriptpubkey)
print()

#signing message is what we sign to produce scriptsig
print( "signing_message: ")
version_num = "01000000"
#number of inputs used
input_count = "01"
#calculated above
prev_tx_hash
#index starts at 0, which output from the referenced(prev) tx are you going to redeem, little endian, 4 bytes
previous_output_index = "00000000"
#input_scriptpubkey is one of the output script pub keys from the transaction I want to redeem
#it is also the pub key in step 3 of address generation because this is where they would have sent coins if they knew the public address to this private key
input_scriptpubkey = "76a914" + input_scriptpubkey + "88ac"
#divide by two for byte length
print(input_scriptpubkey)
input_script_len = str(hex(int(len(input_scriptpubkey)/2))[2:])
print(input_script_len)
#this sequence number means this TX will not be changed and is ready to be spent
sequence = "ffffffff"
output_count = "01"
value = "008cb90000000000" #8 bytes, little endian
output_script_len = str(hex(int(len(output_scriptpubkey)/2))[2:])
output_scriptpubkey
#earliest block height this TX can be added to blockchain
lock_time = "00000000"
#01 = SIGHASH_ALL meaning sign the whole transaction except the scriptsig, nothing signed can be changed
sighash_code = "01000000"
signing_message = version_num + input_count + prev_tx_hash + previous_output_index + input_script_len + input_scriptpubkey + sequence + output_count + value + output_script_len + output_scriptpubkey + lock_time + sighash_code
print( signing_message)
#signing_message is double sha'd which is then signed
hashof_signing_message = hashlib.sha256(hashlib.sha256(bytes.fromhex(signing_message)).digest()).hexdigest()
#convert to decimal
hashof_signing_message = int(hashof_signing_message, 16)
print()

#sign with privkey and random number to get R, and S
#Signature will change if random number is different
print( "R and S of signature on the signing message: ")
#print( "******* Signature Generation *********"
xRandSignPoint, yRandSignPoint = ECmultiply(Gx,Gy,RandNum)
r = xRandSignPoint % N; print( "r =", r)
#we only sign the hash of the message
s = ((hashof_signing_message + r*privKey)*(modinv(RandNum,N))) % N; print( "s =", s)
#scriptsig_pushdata_opcode1 goes here
header = "30"
#sig_len goes here, calculated below
r_integer = "02" #02 means R is an integer
r_coor = hex(r)[2:]
#converting to binary will remove leading zeros. If len = 258 first bit is 1 (bin #s start with) 0b
#if the leading bit of R or S is 1, then prepend a 00 byte
if( len(bin(int(r_coor, 16))) == 258 ): r_coor = "00" + r_coor
s_integer = "02"
s_coor = hex(s)[2:]
if( len(bin(int(s_coor, 16))) == 258 ): s_coor = "00" + s_coor
#make sure this equals 64 or 66
print(r_coor)
print(s_coor)
if( len(r_coor) != 64 and len(r_coor) != 66 or len(s_coor) != 64 and len(s_coor) != 66 ): stop
#r and s are big endian. divide by two is for byte length
r_len = hex(int(len(r_coor)/2))[2:]
s_len = hex(int(len(s_coor)/2))[2:]
print( "r length: " + r_len, " s length: " + s_len)
#again divide every length by 2 for byte length. [2:] removes first two chars, 0x
sig_len = hex( len(r_integer)/2 + len(r_len)/2 + len(str(r_coor))/2 + len(s_integer)/2 + len(s_len)/2 + len(str(s_coor))/2 )[2:]
#01 = SIGHASH_ALL meaning sign the whole transaction
scriptsig_sighashcode = "01"
scriptsig_pushdata_opcode1 = hex(len(header)/2 + len(sig_len)/2 + len(r_integer)/2 + len(r_len)/2 + len(str(r_coor))/2 + len(s_integer)/2 + len(s_len)/2 + len(str(s_coor))/2 + len(scriptsig_sighashcode)/2)[2:]
#the length of scriptsig_pubkey
scriptsig_pushdata_opcode2 = hex(len(scriptsig_pubkey)/2)[2:]
#see step 1 of address generation. This is our compressed pubkey of the signing private key
scriptsig_pubkey
#print( "scriptSig components"
"""print( scriptsig_pushdata_opcode1
print( header
print( sig_len
print( r_integer
print( r_len
print( r_coor
print( s_integer
print( s_len
print( s_coor
print( scriptsig_sighashcode
print( scriptsig_pushdata_opcode2
print( scriptsig_pubkey"""
print( " ")
print( "script signature: ")
script_sig = scriptsig_pushdata_opcode1 + header + sig_len + r_integer + r_len + r_coor + s_integer + s_len + s_coor + scriptsig_sighashcode + scriptsig_pushdata_opcode2 + scriptsig_pubkey
print( script_sig)
#the length of the scriptsig is the last piece we need to make the final transaction
script_sig_len = hex(len(script_sig)/2)[2:]
print( " ")
print( "final transaction: ")
"""print( version_num
print( input_count
print( prev_tx_hash
print( previous_output_index
print( script_sig_len
print( script_sig
print( sequence
print( output_count
print( value
print( output_script_len
print( output_scriptpubkey
print( lock_time"""
final_transaction = version_num + input_count + prev_tx_hash + previous_output_index + script_sig_len + script_sig + sequence + output_count + value + output_script_len + output_scriptpubkey + lock_time
print( final_transaction)

#this just verifies the signature was generated by the private key
print(); print( "******* Signature Verification *********")
w = modinv(s,N)
xu1, yu1 = ECmultiply(Gx,Gy,(hashof_signing_message * w)%N)
xu2, yu2 = ECmultiply(xPublicKey,yPublicKey,(r*w)%N)
x,y = ECadd(xu1,yu1,xu2,yu2)
print( r==x); print()
