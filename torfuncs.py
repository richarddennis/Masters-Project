from StringIO import StringIO
#import consensus
import binascii
from collections import namedtuple
import pprint
import os
from OpenSSL import crypto
import time
import ssl,socket,struct
from binascii import hexlify
from Crypto.Hash import SHA
from Crypto.Cipher import *
from Crypto.PublicKey import *
import sys
from Crypto.Util import Counter
import consensus

# cipher = AES CTR (ZERO IV START)
# HASH = SHA1
# RSA 1024bit, e=65537, OAEP
KEY_LEN=16
DH_LEN=128
DH_SEC_LEN=40
PK_ENC_LEN=128
PK_PAD_LEN=42
HASH_LEN=20
DH_G = 2
DH_P = 179769313486231590770839156793787453197860296048756011706444423684197180216158519368947833795864925541502180565485980503646440548199239100050792877003355816639229553136239076508735759914822574862575007425302077447712589550957937778424442426617334727629299387668709205606050270810842907692932019128194467627007L

# adds padding to make payload 509
def padding(payload):
    payload += "\x00" * (509 - len(payload))
    return payload
    
#Tor KDF function
def kdf_tor(K0, length):
    K = ''
    i = 0
    while len(K) < length:
        K += SHA.new(K0 + chr(i)).digest()
        i+=1
    return K
    
#packs a number as big endian into nbytes
#e.g. struct but specify field size
def numpack(n, nbytes):
    n2 = hex(n)[2:-1]
    if(len (n2) % 2 != 0) and nbytes != 0:
        n2 = '0' + n2
    n2 = n2.decode('hex')
    return "\x00" * (nbytes - len(n2)) + n2

#decodes big endian integer into integer
def numunpack(s):
    return int(s.encode("hex"),16)

#according to tor spec, performs hybrid encrypt for create/etc
def hybridEncrypt(rsa, m):
    cipher = PKCS1_OAEP.new(rsa)
    if len(m) < (PK_ENC_LEN - PK_PAD_LEN):
        return cipher.encrypt(m)
    else:
        symkey = os.urandom(KEY_LEN)
        ctr = Counter.new(128, initial_value=0)
        aes = AES.new(symkey, AES.MODE_CTR, counter=ctr)
        m1 = m[0:PK_ENC_LEN-PK_PAD_LEN-KEY_LEN]
        m2 = m[PK_ENC_LEN-PK_PAD_LEN-KEY_LEN:]
        rsapart = cipher.encrypt(symkey+m1)
        sympart = aes.encrypt(m2)
        return rsapart + sympart

def remoteKeyX (on):
    r = consensus.getRouter(on)
    router_descriptor = consensus.getRouterDescriptor(r['identityhash'])
    router_onion_key = consensus.getRouterOnionKey(router_descriptor)
    remoteKey = RSA.importKey(router_onion_key)
    x = numunpack(os.urandom(DH_SEC_LEN))
    X = pow(DH_G,x,DH_P)
    X = numpack(X,DH_LEN)
    remoteKey = RSA.importKey(router_onion_key)
    payload = hybridEncrypt(remoteKey, X)
    return (payload, x)


def decodeCreatedCell(created, x):
    # recieved cell will only contain Y their public key
    Y = numunpack(created[0:DH_LEN])
    #print Y
    DerivativeKeyData = created[DH_LEN: DH_LEN+HASH_LEN]
    #print DerivativeKeyData
    #shared key between us and first hop
    shared_Key = pow(Y,x,DH_P)
    #print "Shared key :",shared_Key
    # Get data from shared key

    KK = StringIO(kdf_tor(numpack(shared_Key, DH_LEN), 3*HASH_LEN + 2*KEY_LEN))
    (KH, Df, Db) = [KK.read(HASH_LEN) for i in range(3)]
    (Kf, Kb) = [KK.read(KEY_LEN) for i in range(2)]
    assert DerivativeKeyData == KH
    return KH, Df, Db, Kf, Kb    




def buildExtendPayload(on):

    r = consensus.getRouter(on)
    ip = map(int,r['ip'].split("."))
    port = int(r['orport'])
    extend = struct.pack("B" * len(ip), *ip)
    extend += struct.pack("H", int(r['orport']))


    pl_To_Next, x = remoteKeyX(on) #made into function much better than repeating code
    #creates the payload to the next hop
    #pl_To_Next = hybridEncrypt(remoteKey, X)
    extend += pl_To_Next
    extend += r['identity']

    return (x, extend)
    #return extend #, x #, ip, port    

def decodeRelayCell(cell):
# #         # Relay command           [1 byte]
# #         # 'Recognized'            [2 bytes]
# #         # StreamID                [2 bytes]
# #         # Digest                  [4 bytes]
# #         # Length                  [2 bytes]
# #         # Data                    [PAYLOAD_LEN-11 bytes]

    celldata = dict(zip(['relayCmd', 'recognised', 'streamId', 'digest', 'length'], struct.unpack(">BHHLH", cell[:11])))
    celldata['pl'] = cell[11:celldata['length']+11]
    return celldata


#     #def buildRelayCell(relayCmd, streamId, payload):
# def buildRelayCell(relayCmd, streamId, payload):
# #         # Relay command           [1 byte]
# #         # 'Recognized'            [2 bytes]
# #         # StreamID                [2 bytes]
# #         # Digest                  [4 bytes]
# #         # Length                  [2 bytes]
# #         # Data                    [PAYLOAD_LEN-11 bytes]

#     # packet = struct.pack(">B", relayCmd)
#     # packet += struct.pack("H", 0)
#     # packet += struct.pack("H", streamId)
#     # packet += struct.pack("L", 0)
#     # packet += struct.pack("H", len(payload))
#     # packet += struct.pack(payload)

#     packet = struct.pack(">BHHLH", relayCmd, 0, streamId, 0, len(payload)) + payload

#     # padding
#     #packet += "\x00" * (509 - len(packet))
#     packet = padding(packet)
#     assert len(packet) == 509

#     fwdSha.update(packet)
#     packet = packet[0:5] + fwdSha.digest()[0:4] + packet[9:]

#     return packet
