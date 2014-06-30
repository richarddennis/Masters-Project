from StringIO import StringIO
import cStringIO
import binascii
from collections import namedtuple
import pprint
import os
#from OpenSSL import crypto
import time
import ssl,socket,struct
from binascii import hexlify
#from Crypto.Hash import SHA
#from Crypto.Cipher import *
#from Crypto.PublicKey import *
import sys
import itertools

#from Crypto.Util import Counter
import consensus


from torfuncs import *

#         0 -- PADDING     (Padding)
#         1 -- CREATE      (Create a circuit)
#         2 -- CREATED     (Acknowledge create)
#         3 -- RELAY       (End-to-end data)
#         4 -- DESTROY     (Stop using a circuit)
#         5 -- CREATE_FAST (Create a circuit, no PK)
#         6 -- CREATED_FAST (Circuit created, no PK)
#         8 -- NETINFO     (Time and address info)
#         9 -- RELAY_EARLY (End-to-end data; limited)
#         10 -- CREATE2    (Extended CREATE cell)
#         11 -- CREATED2   (Extended CREATED cell)
#
#    Variable-length command values are:
#         7 -- VERSIONS    (Negotiate proto version)
#         128 -- VPADDING  (Variable-length padding)
#         129 -- CERTS     (Certificates)
#         130 -- AUTH_CHALLENGE (Challenge value)
#         131 -- AUTHENTICATE (Client authentication)
#         132 -- AUTHORIZE (Client authorization)    (Not yet used)


# relay
#          1 -- RELAY_BEGIN     [forward]
#          2 -- RELAY_DATA      [forward or backward]
#          3 -- RELAY_END       [forward or backward]
#          4 -- RELAY_CONNECTED [backward]
#          5 -- RELAY_SENDME    [forward or backward] [sometimes control]
#          6 -- RELAY_EXTEND    [forward]             [control]
#          7 -- RELAY_EXTENDED  [backward]            [control]
#          8 -- RELAY_TRUNCATE  [forward]             [control]
#          9 -- RELAY_TRUNCATED [backward]            [control]
#         10 -- RELAY_DROP      [forward or backward] [control]
#         11 -- RELAY_RESOLVE   [forward]
#         12 -- RELAY_RESOLVED  [backward]
#         13 -- RELAY_BEGIN_DIR [forward]
#         14 -- RELAY_EXTEND2   [forward]             [control]
#         15 -- RELAY_EXTENDED2 [backward]            [control]



KEY_LEN=16
DH_LEN=128
DH_SEC_LEN=40
PK_ENC_LEN=128
PK_PAD_LEN=42
HASH_LEN=20
DH_G = 2
DH_P = 179769313486231590770839156793787453197860296048756011706444423684197180216158519368947833795864925541502180565485980503646440548199239100050792877003355816639229553136239076508735759914822574862575007425302077447712589550957937778424442426617334727629299387668709205606050270810842907692932019128194467627007L


s = socket.socket()
ssl_sock = ssl.wrap_socket(s)
ssl_sock.connect(("94.242.246.24", 8080))

peerAddress = map(int,ssl_sock.getpeername()[0].split("."))
ownAddress = map(int,ssl_sock.getsockname()[0].split("."))
#print ownAddress
#sys.exit(0)

# 512 - COMMAND_LEN - PAYLOAD_LEN = 512 - 1 - 509 = 2
CIRCID_LEN = 2

# sock is TCP socket/SSL socket
# specify waitFor as cmd ID if should wait for that packet (ignores all others)
def recvCell(sock, waitFor = 0):
        while True:
                hdr = sock.recv(3)
                circid, cmd = struct.unpack(">HB", hdr[0:3])
                ln = 509
                if cmd == 7 or cmd >= 128:
                        ln = struct.unpack(">H", sock.recv(2))[0]
                pl = sock.recv(ln)

                if cmd == waitFor or waitFor == 0:
                        return { 'circId': circid, 'cmd': cmd, 'len': ln, 'pl': pl}



# builds a cell
def buildCell(circid, command, payload):
        cell = struct.pack(">HB", circid, command)
        if command == 7 or command >= 128:
                cell += struct.pack(">H", len(payload))
        else:
                payload = padding(payload)
               # payload = ''.join(payload)
        cell += payload
        return cell


# builds the version cell's payload
def buildVersions(acceptVersions):
        pkt = ''
        for v in acceptVersions:
                pkt += struct.pack(">H", v)
        return pkt

verPl = buildVersions([ 3 ])
verCell = buildCell(0, 7, verPl)

print "Packet to send is : ", verCell
ssl_sock.send(verCell)

def decodeNetInfo(pl):
    payload = pl
    tm = struct.unpack(">I", payload[0:4])[0]
    our_or_ip_version = struct.unpack(">B", payload[4])[0]
    our_or_addr_len = struct.unpack(">B", payload[5])[0]
    if our_or_addr_len == 4:
        our_op_ip = struct.unpack(">BBBB", payload[6:10])
        num_their_ips = struct.unpack(">B", payload[10])[0]
        len_their_ips = struct.unpack(">B", payload[12])[0]
        # Much better way to unpack the packet, does unpacking dynamically rather than set values
        byte_string = '>{}'.format('B'*len_their_ips)
        their_ips = []
        for count in range(num_their_ips):
            start = 13 + (count*len_their_ips)
            end = start + len_their_ips
            ip = struct.unpack(byte_string, payload[start:end])
            their_ips.append(ip)

    elif our_or_addr_len == 16:
        our_op_ip = struct.unpack(">BBBBBBBBBBBBBBBB", payload[6:22])
        num_their_ips = struct.unpack(">B", payload[22])[0]
        len_their_ips = struct.unpack(">B", payload[23])[0]

        byte_string = '>{}'.format('B'*len_their_ips)
        their_ips = []
        for count in range(num_their_ips):
            start = 24 + (count*len_their_ips)
            end = start + len_their_ips
            ip = struct.unpack(byte_string, payload[start:end])
            their_ips.append(ip)

    #Setting their Ip version
    if len_their_ips == 16:
        version_their_ips = 6
    elif len_their_ips == 4:
        version_their_ips = 4

    our_op_ip = [int(i) for i in our_op_ip]
    their_ips = [map(int, x) for x in their_ips]
    their_ips = list(itertools.chain.from_iterable(their_ips))
    return { 'tm': tm, 'our_or_ip_version': our_or_ip_version, 'our_or_addr_len': our_or_addr_len, 'our_op_ip': our_op_ip, 'version_their_ips': version_their_ips, 'num_their_ips': num_their_ips, 'len_their_ips': len_their_ips, 'their_ips': their_ips }

def NetInfoToSend(tm, our_or_ip_version, our_or_addr_len, our_op_ip, version_their_ips, num_their_ips, len_their_ips, their_ips):
    CellNetInfopkt = struct.pack(">I", time.time())

    #         Number of addresses    [1 byte]
    # CellNetInfopkt += struct.pack("B", num_their_ips)
    #         Their OR's addresses    [variable]
    CellNetInfopkt += struct.pack(">B", 4)
    CellNetInfopkt += struct.pack(">B", 4)
    CellNetInfopkt += struct.pack("B" * len(peerAddress), *peerAddress)

    CellNetInfopkt += struct.pack(">B", 1)

    # adress format is a type/length/value
    #         This OR's address     [variable]
    CellNetInfopkt += struct.pack(">B", our_or_ip_version) # IPV4
    CellNetInfopkt += struct.pack(">B", our_or_addr_len) #
    CellNetInfopkt += struct.pack("B" * len(ownAddress), *ownAddress)

    return  CellNetInfopkt


srv_netinfocell = recvCell(ssl_sock, 8)
print "netinfoCell recieved ",srv_netinfocell 
srv_decodeNetInfo = decodeNetInfo(srv_netinfocell['pl']) # proccess the payload from the netinfo cell
srv_NetInfoToSend = NetInfoToSend(**srv_decodeNetInfo)
netinfoCell = buildCell(0, 8, srv_NetInfoToSend)
print "netinfo to send ", netinfoCell.encode('hex')

ssl_sock.send(netinfoCell)

# retrieve the consensus
consensus.fetchConsensus()
#print "Retrieved the consensus successfully"

#retrieves the consensus data for the first node to connect ti
# r = consensus.getRouter("orion")
# #print "r (orion router): ", r

# x = numunpack(os.urandom(DH_SEC_LEN))

# #calculates Big X (our public key)
# X = pow(DH_G,x,DH_P)
# X = numpack(X,DH_LEN)
# print X

# router_descriptor = consensus.getRouterDescriptor(r['identityhash'])
# router_onion_key = consensus.getRouterOnionKey(router_descriptor)
# print router_onion_key

# remoteKey = RSA.importKey(router_onion_key)
#creates the payload to the first hop


firstHop = "orion"
payload, x = remoteKeyX(firstHop)
createcell = buildCell(1, 1, payload)
print "Create cell to send", createcell.encode('hex')
ssl_sock.send(createcell)

srv_createdCell = recvCell(ssl_sock, 2)  #2 is created cell
print "Recieved a created cell back : ", srv_createdCell

#print "Df", Df.encode('hex')
#srv_createdCell = srv_createdCell['pl']
KH, Df, Db, Kf, Kb = decodeCreatedCell(srv_createdCell['pl'], x)
print "KH", KH.encode('hex'), "Df", Df.encode('hex'), "Db", Db.encode('hex'), "Kf", Kf.encode('hex'), "Kb", Kb.encode('hex')

t1 = KH, Df, Db, Kf, Kb


hops = []
packetSendCount = 0

fwdSha = SHA.new()
fwdSha.update(Df)
bwdSha = SHA.new()
bwdSha.update(Db)

ctr = Counter.new(128,initial_value=0)
fwdCipher = AES.new(Kf, AES.MODE_CTR, counter=ctr)
ctr = Counter.new(128,initial_value=0)
bwdCipher = AES.new(Kb, AES.MODE_CTR, counter=ctr)

def encrypt(data):
    return fwdCipher.encrypt(data)

def decrypt(data):
    return bwdCipher.decrypt(data)

hops.append(t1)

def buildExtendPayload(on):

    r = consensus.getRouter(on)
    ip = map(int,r['ip'].split("."))
    port = int(r['orport'])
    extend = struct.pack("B" * len(ip), *ip)
    extend += struct.pack(">H", int(r['orport']))

    pl_To_Next, x = remoteKeyX(on) #made into function much better than repeating code
    #creates the payload to the next hop
    extend += pl_To_Next
    extend += r['identity']
    #extend = encrypt(extend)

    return (x, extend)
    #return extend #, x #, ip, port

# (x, extend) = buildExtendPayload("TheVillage")
# print "extend ",extend.encode('hex')


# #constructs relay cell payload and encrypts to torhop
# def buildRelayCell( relCmd, streamId, data):
#     print relCmd
# #construct pkt
#     pkt = struct.pack(">BHHLH", relCmd, 0, streamId, 0, len(data)) + data
#     pkt += "\x00" * (509 - len(pkt))
# #update rolling sha1 hash (with digest set to all zeroes)
#     fwdSha.update(pkt)
# #splice in hash
#     pkt = pkt[0:5] + fwdSha.digest()[0:4] + pkt[9:]
# #encrypt
#     return pkt

    #def buildRelayCell(relayCmd, streamId, payload):
def buildRelayCell(relayCmd, streamId, payload):
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

    fwdSha.update(packet)
    packet = packet[0:5] + fwdSha.digest()[0:4] + packet[9:]

    return packet

def extend(on):
    (x, extend) = buildExtendPayload(on)
    extendr = buildRelayCell(6, 0, extend)
    send(extendr)

def send(packet):
        packetencrpyt = encrypt(packet)
        ssl_sock.send(buildCell(1, 9, packetencrpyt)) # will need to monitor this, if packets sent >8 need to change relay type


# print "extend encrypted ", extend.encode('hex')
# extendr = buildRelayCell(hops[-1], 6, 0, extend)
# print "extendr: ", extendr.encode('hex')
# print "len extendr: ", len(extendr)
# #extendr = encrypt(extendr)

# ssl_sock.send(buildCell(1, 9, extendr))   # 9 = RELAY_EARLY
# packetSendCount += 1
#hopsToVisit = ["TheVillage"]

def extendedRecieved(packet):
    extended = decrypt(packet)
    relayDecoded = decodeRelayCell(extended)
    assert relayDecoded['relayCmd'] == 7 # checks to make sure the cell recieved is a RELAY_EXTENDED
    relayDecoded = relayDecoded['pl']

    # Y = numunpack(relayDecoded[0:128])
    #print Y
    # DerivativeKeyData = relayDecoded[128: 128+20]
    ##DerivativeKeyData = 64a4f00a0687872000a5d54a256508931d955d13

    # shared_Key = pow(Y,x,DH_P)


    # KK = StringIO(kdf_tor(numpack(shared_Key, DH_LEN), 3*HASH_LEN + 2*KEY_LEN))
    # (KH, Df, Db) = [KK.read(HASH_LEN) for i in range(3)]
    # (Kf, Kb) = [KK.read(KEY_LEN) for i in range(2)]
    ## kh = 23631b77a5da974f753b8b7e8d658288b8291a58
    #return KH

    t2 = decodeCreatedCell(relayDecoded, x) #currently getting an assertion error
    return t2

send = extend("TheVillage")
packetSendCount += 1
srv_RelayedCell = recvCell(ssl_sock)
print "Recieved a cell back : ", srv_RelayedCell
print type(srv_RelayedCell) #dict
# srv_RelayedCell = ', '.join(format(key,val) for (key,val) in srv_RelayedCell.items())
# print type(srv_RelayedCell)
# srv_RelayedCell = decrypt(srv_RelayedCell)
# print type(srv_RelayedCell)

for k, v in srv_RelayedCell.iteritems():
    print k
# circId
# cmd 
# pl
# len
print "payload", srv_RelayedCell['pl'].encode('hex')
RelayedCellPayload = srv_RelayedCell['pl'] #only require the payload
#print "x", x
extended = extendedRecieved(RelayedCellPayload)
print "extended decrypted ", extended.encode('hex')
#print type(extended)
hops.append(t2)

