from StringIO import StringIO
import binascii
from collections import namedtuple
import pprint
import os
import time
import ssl,socket,struct
from binascii import hexlify
from Crypto.Hash import SHA
from Crypto.Cipher import *
from Crypto.PublicKey import *
import sys
from Crypto.Util import Counter
import consensus
from consensus import *

import re


### Pre set variables with values that do not change
KEY_LEN=16
DH_LEN=128
DH_SEC_LEN=40
PK_ENC_LEN=128
PK_PAD_LEN=42
HASH_LEN=20
DH_G = 2
DH_P = 179769313486231590770839156793787453197860296048756011706444423684197180216158519368947833795864925541502180565485980503646440548199239100050792877003355816639229553136239076508735759914822574862575007425302077447712589550957937778424442426617334727629299387668709205606050270810842907692932019128194467627007L



#Function to add padding to make payload 509, more effiecent that coding this every time
# Input is the payload of the packet so far
# output is the payload correctly padded to len 509
def padding(payload):
    payload += "\x00" * (509 - len(payload))

    ### Test##
    # if len(payload) != 509:
    #     errors.incorrect_padding()
    return payload

# builds a cell
#Function to create the cells, made into a function to reduce code repeation
#Takes the command and payload, and if it is cmd 7 or 128 or greater it is a variable length packet and will be sent as it once correctly packed,however else it will be padded to 509 length
#The cell correctly formatted will be returned read to be sent
def buildCell(circid, command, payload):
        cell = struct.pack(">HB", circid, command)
        if command == 7 or command >= 128:
                cell += struct.pack(">H", len(payload))
        else:
                payload = padding(payload)
               # payload = ''.join(payload)
        cell += payload
        return cell


class TorHop:

    # def __str__(self):
    #     return 'hop #' %  self.hop

    # def __repr__(self):
    #     return 'hop #' %  self.hop

    # def __repr__(self):
    #     return '<TorHop(%d)>' % self.hop

    def __init__(self, KH, Df, Db, Kf, Kb):
        self.KH = KH
        self.Df = Df
        self.Db = Db
        self.Kf = Kf
        self.Kb = Kb

        self.fwdSha = SHA.new()
        self.fwdSha.update(Df)
        self.bwdSha = SHA.new()
        self.bwdSha.update(Db)

        ctr = Counter.new(128,initial_value=0)
        self.fwdCipher = AES.new(Kf, AES.MODE_CTR, counter=ctr)
        ctr = Counter.new(128,initial_value=0)
        self.bwdCipher = AES.new(Kb, AES.MODE_CTR, counter=ctr)
    def encrypt(self, data):
        return self.fwdCipher.encrypt(data)
    def decrypt(self, data):
        return self.bwdCipher.decrypt(data)


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

#Hashes an input with SHA1
def hash_item(i):
    hash_value = SHA.new()
    hash_value.update(i)
    hash_value = hash_value.digest()
    return hash_value

#Gareth Owens code, reused with his permission, saved on time and possible errors that could have been brought in by trying to develop it
#according to tor spec, performs hybrid encrypt for create/etc
def hybridEncrypt(rsa, m):
    # print "RSA type :", type(rsa) #intance
    # print "Message type: ", type(m)  #Str
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

#Takes the onion name of a node, calculates its public and private keys to be used
def remoteKeyX (on):
    r = consensus.getRouter(on)
    x = numunpack(os.urandom(DH_SEC_LEN))
    X = pow(DH_G,x,DH_P)
    X = numpack(X,DH_LEN)
    router_descriptor = consensus.getRouterDescriptor(r['identityhash'])
    router_onion_key = consensus.getRouterOnionKey(router_descriptor)
    remoteKey = RSA.importKey(router_onion_key)
    payload = hybridEncrypt(remoteKey, X)
    return (x, payload)

#Failed attempt of calulating the keys with out an onion nickname, this was developed for a node with just ip addresses, however the consensus was edited to search for the nickname thus rendering this un needed
def remoteKeyX_with_no_on (on):
    x = numunpack(os.urandom(DH_SEC_LEN))
    X = pow(DH_G,x,DH_P)
    X = numpack(X,DH_LEN)
    router_descriptor = consensus.getRouterDescriptor(identityHash)
    router_onion_key = consensus.getRouterOnionKey(router_descriptor)

    remoteKey = RSA.importKey(router_onion_key)
    #remoteKey = RSA.importKey(router_onion_key)

    payload = hybridEncrypt(remoteKey, X)
    return (x, payload)

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
    #return KH, Df, Db, Kf, Kb
    return TorHop(KH, Df, Db, Kf, Kb)

def buildExtendPayload(on):
    match = re.search(r'(\d{1,3}\.){3}\d{1,3}(:\d{1,5})?', on)
    # if on =="Goblin500":
    #     print "Goblin500"
    #     ip = [82,26,108,68]
    #     port = 9001
    #     extend = struct.pack("B" * len(ip), *ip)
    #     extend += struct.pack("H", port)

    #     x, pl_To_Next = remoteKeyX(on) 
    #     extend += pl_To_Next
    #     r = consensus.getRouter(on)

    #     print r['identity'].encode('hex')
    #     extend += r['identity']

    if match:
        ip, port,identity = on.split(":")
        print ip
        # print type(ip)
        d = consensus.get_data_by_ip(ip)

        ip = map(int,ip.split("."))
        port = int(port)

        extend = struct.pack("B" * len(ip), *ip)
        extend += struct.pack("H", port)
        d = consensus.get_data_by_ip(ip)

        x, pl_To_Next = remoteKeyX(d['identityhash'])

        extend += pl_To_Next
        extend += d['identity']

    else :
        r = consensus.getRouter(on)
        ip = map(int,r['ip'].split("."))
        port = int(r['orport'])
        extend = struct.pack("B" * len(ip), *ip)
        extend += struct.pack("H", port)

        x, pl_To_Next = remoteKeyX(on) #made into function much better than repeating code
           #creates the payload to the next hop
            #pl_To_Next = hybridEncrypt(remoteKey, X)
        extend += pl_To_Next
        extend += r['identity']

    return (x, extend)
    #return extend #, x #, ip, port


def buildRelayCell(torhop, relayCmd, streamId, payload):
#         # Relay command           [1 byte]
#         # 'Recognized'            [2 bytes]
#         # StreamID                [2 bytes]
#         # Digest                  [4 bytes]
#         # Length                  [2 bytes]
#         # Data                    [PAYLOAD_LEN-11 bytes]

    packet = struct.pack(">B", relayCmd)
    packet += struct.pack(">H", 0)
    packet += struct.pack(">H", streamId)
    packet += struct.pack(">L", 0)
    packet += struct.pack(">H", len(payload))
    packet += payload

    # padding
    #packet += "\x00" * (509 - len(packet))
    packet = padding(packet)
    assert len(packet) == 509

    torhop.fwdSha.update(packet)
    packet = packet[0:5] + torhop.fwdSha.digest()[0:4] + packet[9:]

    return packet


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


#This function is a simple function that removes the .onion address from the end of the hidden service address if it has it
def remove_of_onion(onion_Add):
    if '.' in onion_Add:
        return onion_Add.split('.')[0]
    else:
        return onion_Add

def ip_port_for_on(on):
    test = consensus.getRouter(on)
    print test
