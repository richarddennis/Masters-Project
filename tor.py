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
from rendFuncs import *

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

   # Relay cell types
   #     32 -- RELAY_COMMAND_ESTABLISH_INTRO
   #     33 -- RELAY_COMMAND_ESTABLISH_RENDEZVOUS
   #     34 -- RELAY_COMMAND_INTRODUCE1
   #     35 -- RELAY_COMMAND_INTRODUCE2
   #     36 -- RELAY_COMMAND_RENDEZVOUS1
   #     37 -- RELAY_COMMAND_RENDEZVOUS2
   #     38 -- RELAY_COMMAND_INTRO_ESTABLISHED
   #     39 -- RELAY_COMMAND_RENDEZVOUS_ESTABLISHED
   #     40 -- RELAY_COMMAND_INTRODUCE_ACK


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

# builds the version cell's payload
def buildVersions(acceptVersions):
        pkt = ''
        for v in acceptVersions:
                pkt += struct.pack(">H", v)
        return pkt

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



class TorCircuit():
    def __init__(self, sock, circid):
        self.hops = []
        self.circId = circid
        self.socket = sock
        self.tempX = 0
        self.packetSendCount = 0

#parse relaycell as str
    def encrypt(self, relayCell):
        for hop in self.hops[::-1]:
            relayCell = hop.fwdCipher.encrypt(relayCell)
        return relayCell

#parse relaycell as str
    def decrypt(self, relayCell):
        for hop in self.hops:
            relayCell = hop.decrypt(relayCell)
        return relayCell

    def toFirst(self, on):
        (self.tempX, create) = remoteKeyX(firstHop)
        createcell = buildCell(self.circId, 1, create)
        self.socket.send(createcell)

    def handleCreated(self, cell):
        created = cell['pl']
        t1 = decodeCreatedCell(created, self.tempX)
        self.hops.append(t1)

    def extend(self, on):
        (self.tempX, extend) = buildExtendPayload(on)
        extendr = buildRelayCell(self.hops[-1], 6, 0, extend)
        self.send(extendr)

    def send(self, packet):
        packetencrpyt = self.encrypt(packet)
        relayId = (9 if self.packetSendCount <8 else 3)
        self.socket.send(buildCell(self.circId, relayId, packetencrpyt)) # will need to monitor this, if packets sent >8 need to change relay type
        self.packetSendCount += 1

    def extendedRecieved(self, packet):
        extended = self.decrypt(packet)
        relayDecoded = decodeRelayCell(extended)
        assert relayDecoded['relayCmd'] == 7 # checks to make sure the cell recieved is a RELAY_EXTENDED  #sometimes get an assertion error
        payload = relayDecoded['pl']
        t2 = decodeCreatedCell(payload, self.tempX)
        self.hops.append(t2)
        # return extended
        #return t2

    def createStream(self,strId, host, port):
        payload = host + ":" + str(port) + "\x00" + struct.pack(">L", 0)
        relay = buildRelayCell(self.hops[-1], 1, strId, payload)
        self.send(relay)

    def streamRecieved(self, packet):
        connected = self.decrypt(packet)
        relayDecoded = decodeRelayCell(connected)        
        assert relayDecoded['relayCmd'] == 4 # Otherwise the relay_connect have not been recieved (Usually down to a time out)

    def streamData(self,strId, data):
        relay = buildRelayCell(self.hops[-1], 2, strId, data)
        #relay = self.encrypt(relay)
        self.send(relay)

    def recievedStreamData(self, packet):
        data = self.decrypt(packet)
        relayDecoded = decodeRelayCell(data)        
        return relayDecoded

# first_hop = raw_input("Enter the first hop to connect to (Case and space sensitive): ")
# print first_hop

s = socket.socket()
ssl_sock = ssl.wrap_socket(s)
ssl_sock.connect(("94.242.246.24", 8080))

peerAddress = map(int,ssl_sock.getpeername()[0].split("."))
ownAddress = map(int,ssl_sock.getsockname()[0].split("."))

consensus.fetchConsensus()
print "consensus Retrieved"

verPl = buildVersions([ 3 ])
verCell = buildCell(0, 7, verPl)
print "Packet to send is : ", verCell
ssl_sock.send(verCell)

srv_netinfocell = recvCell(ssl_sock, 8)
print "netinfoCell recieved ",srv_netinfocell 
srv_decodeNetInfo = decodeNetInfo(srv_netinfocell['pl']) # proccess the payload from the netinfo cell

srv_NetInfoToSend = NetInfoToSend(**srv_decodeNetInfo)
netinfoCell = buildCell(0, 8, srv_NetInfoToSend)
print "netinfo to send ", netinfoCell.encode('hex')
ssl_sock.send(netinfoCell)
print "netinfo sent"
firstHop = "orion"

circ = TorCircuit(ssl_sock, 1)
circ.toFirst(firstHop)
created = recvCell(ssl_sock)
circ.handleCreated(created)

#hop = "WorldWithPrivacyNY1"
count=0
for hop in ["WorldWithPrivacyNY1","TorLand1", "TheVillage"]: #"TorLand1"
    print "hop :", hop
    circ.extend(hop)
    extended = recvCell(ssl_sock)
    print "extended recieved", extended
    circ.extendedRecieved(extended['pl'])
    count = count + 1
    print "success, hop ",count

circ.createStream(1, "ghowen.me", 80)
connected = recvCell(ssl_sock)
circ.streamRecieved(connected['pl'])
print "Stream successfully established"

data = "GET /ip HTTP/1.1\r\nHost: ghowen.me\r\n\r\n"
print "data", data
# dataAscii = [ord(c) for c in data] #converts to ascii
# dataAscii = ", ".join(map(str, dataAscii))
# dataSend = binascii.hexlify(dataAscii)

# print "data in to send to stream", dataSend

## Currently not working keeping getting back a relay end 

circ.streamData(1, data)

# while True:
#      relayData = recvCell(ssl_sock)
#      print "Stream data recieved: ",relayData
#      print "Data decrypted", circ.recievedStreamData(relayData['pl'])#.encode('hex')

# HSDir_List = consensus.get_HSDir_Flag()  # Allows us to only get the data containing the HSDir flags
# print HSDir_List
# for k, v in HSDir_List:
#     if k == 'identity':
#         print k

# idnxcnkne4qt76tg.onion It is the homepage of the Tor project

print "Retriving hidden service descriptor"
onionAdd = "idnxcnkne4qt76tg.onion"
service_id, tld = onionAdd.split(".")

REPLICAS = 2

print "service_id",service_id
for replica in range(0, REPLICAS):
    descriptor_id = get_descriptor_Id(service_id, replica)    
    print "descriptorid", descriptor_id
    responsible_HSDir = find_responsible_HSDir(descriptor_id)
    print responsible_HSDir



















# retrieve the consensus

#print "KH", KH.encode('hex'), "Df", Df.encode('hex'), "Db", Db.encode('hex'), "Kf", Kf.encode('hex'), "Kb", Kb.encode('hex')

#t1 = KH, Df, Db, Kf, Kb

# class TorCircuit():
#     def __init__(self, sock, circid):
#         self.hops = []
#         self.circId = circid
#         self.socket = sock
#         self.tempX = 0
#         self.packetSendCount = 0

# def handleCreated(cell):
#     created = cell['pl']
#     t1 = decodeCreatedCell(created, x)
#     hops.append(t1)

# created = handleCreated(srv_createdCell)

#packetSendCount = 0

#hops.append(t1)


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

# print "extend encrypted ", extend.encode('hex')
# extendr = buildRelayCell(hops[-1], 6, 0, extend)
# print "extendr: ", extendr.encode('hex')
# print "len extendr: ", len(extendr)
# #extendr = encrypt(extendr)

# ssl_sock.send(buildCell(1, 9, extendr))   # 9 = RELAY_EARLY
# packetSendCount += 1
#hopsToVisit = ["TheVillage"]


#print "Retrieved the consensus successfully"

#retrieves the consensus data for the first node to connect ti


# verPl = buildVersions([ 3 ])
# verCell = buildCell(0, 7, verPl)
# print "Packet to send is : ", verCell
# ssl_sock.send(verCell)

# srv_netinfocell = recvCell(ssl_sock, 8)
# print "netinfoCell recieved ",srv_netinfocell 
# srv_decodeNetInfo = decodeNetInfo(srv_netinfocell['pl']) # proccess the payload from the netinfo cell

# srv_NetInfoToSend = NetInfoToSend(**srv_decodeNetInfo)
# netinfoCell = buildCell(0, 8, srv_NetInfoToSend)
# print "netinfo to send ", netinfoCell.encode('hex')
# ssl_sock.send(netinfoCell)

# firstHop = "orion"
# payload, x = remoteKeyX(firstHop)
# createcell = buildCell(1, 1, payload)
# print "Create cell to send", createcell.encode('hex')
# ssl_sock.send(createcell)

# srv_createdCell = recvCell(ssl_sock, 2)  #2 is created cell
# print "Recieved a created cell back : ", srv_createdCell

# #print "Df", Df.encode('hex')
# #srv_createdCell = srv_createdCell['pl']
# t1 = decodeCreatedCell(srv_createdCell['pl'], x)    

# send = extend("TheVillage")
# packetSendCount += 1
# srv_RelayedCell = recvCell(ssl_sock)
# print "Recieved a cell back : ", srv_RelayedCell
# print type(srv_RelayedCell) #dict
# # srv_RelayedCell = ', '.join(format(key,val) for (key,val) in srv_RelayedCell.items())
# # print type(srv_RelayedCell)
# # srv_RelayedCell = decrypt(srv_RelayedCell)
# # print type(srv_RelayedCell)

# for k, v in srv_RelayedCell.iteritems():
#     print k
# # circId
# # cmd 
# # pl
# # len
# print "payload", srv_RelayedCell['pl'].encode('hex')
# RelayedCellPayload = srv_RelayedCell['pl'] #only require the payload
# #print "x", x
# extended = extendedRecieved(RelayedCellPayload)
# print "extended decrypted ", extended.encode('hex')
# #print type(extended)
# hops.append(t2)

