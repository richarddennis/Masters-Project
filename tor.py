from StringIO import StringIO
import cStringIO
import binascii
from collections import namedtuple
import pprint
import os
import time
import ssl,socket,struct
from binascii import hexlify
import sys
import itertools
import consensus
import sys
import base64
import urllib2
import zlib
from Crypto.Hash import SHA

from torfuncs import *
from rendFuncs import *

   #      0 -- PADDING     (Padding)
   #      1 -- CREATE      (Create a circuit)
   #      2 -- CREATED     (Acknowledge create)
   #      3 -- RELAY       (End-to-end data)
   #      4 -- DESTROY     (Stop using a circuit)
   #      5 -- CREATE_FAST (Create a circuit, no PK)
   #      6 -- CREATED_FAST (Circuit created, no PK)
   #      8 -- NETINFO     (Time and address info)
   #      9 -- RELAY_EARLY (End-to-end data; limited)
   #      10 -- CREATE2    (Extended CREATE cell)
   #      11 -- CREATED2   (Extended CREATED cell)

   # Variable-length command values are:
   #      7 -- VERSIONS    (Negotiate proto version)
   #      128 -- VPADDING  (Variable-length padding)
   #      129 -- CERTS     (Certificates)
   #      130 -- AUTH_CHALLENGE (Challenge value)
   #      131 -- AUTHENTICATE (Client authentication)
   #      132 -- AUTHORIZE (Client authorization)    (Not yet used)


# relay
        #  1 -- RELAY_BEGIN     [forward]
        #  2 -- RELAY_DATA      [forward or backward]
        #  3 -- RELAY_END       [forward or backward]
        #  4 -- RELAY_CONNECTED [backward]
        #  5 -- RELAY_SENDME    [forward or backward] [sometimes control]
        #  6 -- RELAY_EXTEND    [forward]             [control]
        #  7 -- RELAY_EXTENDED  [backward]            [control]
        #  8 -- RELAY_TRUNCATE  [forward]             [control]
        #  9 -- RELAY_TRUNCATED [backward]            [control]
        # 10 -- RELAY_DROP      [forward or backward] [control]
        # 11 -- RELAY_RESOLVE   [forward]
        # 12 -- RELAY_RESOLVED  [backward]
        # 13 -- RELAY_BEGIN_DIR [forward]
        # 14 -- RELAY_EXTEND2   [forward]             [control]
        # 15 -- RELAY_EXTENDED2 [backward]            [control]
        # 32 -- RELAY_COMMAND_ESTABLISH_INTRO
        # 33 -- RELAY_COMMAND_ESTABLISH_RENDEZVOUS
        # 34 -- RELAY_COMMAND_INTRODUCE1
        # 35 -- RELAY_COMMAND_INTRODUCE2
        # 36 -- RELAY_COMMAND_RENDEZVOUS1
        # 37 -- RELAY_COMMAND_RENDEZVOUS2
        # 38 -- RELAY_COMMAND_INTRO_ESTABLISHED
        # 39 -- RELAY_COMMAND_RENDEZVOUS_ESTABLISHED
        # 40 -- RELAY_COMMAND_INTRODUCE_ACK



   # The error codes are:
   #   0 -- NONE            (No reason given.)
   #   1 -- PROTOCOL        (Tor protocol violation.)
   #   2 -- INTERNAL        (Internal error.)
   #   3 -- REQUESTED       (A client sent a TRUNCATE command.)
   #   4 -- HIBERNATING     (Not currently operating; trying to save bandwidth.)
   #   5 -- RESOURCELIMIT   (Out of memory, sockets, or circuit IDs.)
   #   6 -- CONNECTFAILED   (Unable to reach relay.)
   #   7 -- OR_IDENTITY     (Connected to relay, but its OR identity was not
   #                         as expected.)
   #   8 -- OR_CONN_CLOSED  (The OR connection that was carrying this circuit
   #                         died.)
   #   9 -- FINISHED        (The circuit has expired for being dirty or old.)
   #  10 -- TIMEOUT         (Circuit construction took too long)
   #  11 -- DESTROYED       (The circuit was destroyed w/o client TRUNCATE)
   #  12 -- NOSUCHSERVICE   (Request for unknown hidden service)



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

                print "got pkt circ ",circid, " cmd", cmd
                if cmd == waitFor or waitFor == 0:
                        print "Return pkt circ ",circid, " cmd", cmd
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
    print "peerAddress",peerAddress
    print "peerAddress type", type(peerAddress)

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



TOR_CIRCID_COUNTER = 1
class TorCircuit():
    def __init__(self, sock):
        global TOR_CIRCID_COUNTER
        self.hops = []
        self.circId = TOR_CIRCID_COUNTER
        TOR_CIRCID_COUNTER+=1
        self.socket = sock
        self.tempX = 0
        self.packetSendCount = 0
        self.cookie = []

#parse relaycell as str
    def encrypt(self, relayCell):
        for hop in self.hops[::-1]:
            relayCell = hop.fwdCipher.encrypt(relayCell)
        return relayCell

    def encrypt_last_only(self, relayCell):
        for hop in self.hops[-1:]:
            relayCell = hop.fwdCipher.encrypt(relayCell)
        return relayCell

#parse relaycell as str
    def decrypt(self, relayCell):
        i = 0
        for hop in self.hops:
            relayCell = hop.decrypt(relayCell)
            if relayCell[1]==0 and relayCell[2]==0:
                print "decrypt: hop #{} of {} {}".format(i, len(self.hops), hop)
                return relayCell
            i+=1
        return relayCell


# #parse relaycell as str
#     def decrypt(self, relayCell):
#         for hop in self.hops:
#             relayCell = hop.decrypt(relayCell)
#         return relayCell


    def toFirst(self, on):
        # ERROR FOUND HERE - USING GLOBAL!! FIXED - GARETH
        (self.tempX, create) = remoteKeyX(on)
        createcell = buildCell(self.circId, 1, create)
        self.socket.send(createcell)

    def handleCreated(self, cell):
        created = cell['pl']
        t1 = decodeCreatedCell(created, self.tempX)
        self.hops.append(t1)

    def extend(self, stream_id, on):
        (self.tempX, extend) = buildExtendPayload(on)
        extendr = buildRelayCell(self.hops[-1], 6, stream_id, extend)
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

    def create_stream_hsdir(self,strId, host):
        payload = host + "\x00" + struct.pack(">L", 0)
        relay = buildRelayCell(self.hops[-1], 13, strId, payload)  #13 -- RELAY_BEGIN_DIR
        self.send(relay)

    def streamRecieved(self, packet):
        connected = self.decrypt(packet)
        print connected.encode('hex')
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

    def rendezvous_point_payload(self, rendezvous_cookie):
        if self.cookie != []:
            self.cookie.pop
        self.cookie.append(rendezvous_cookie)  #keeps it for use later on
        payload = struct.pack ('!20s',rendezvous_cookie)
        return payload

    def establish_rendezvous_point(self, strId, payload):
        relay = buildRelayCell(self.hops[-1], 33, strId, payload)
        self.send(relay)

    def a_op_to_induction_point(self, strId, pk,rp_address, rp_or_port, rp_id, rp_ok, rc):
        # PK_ID  Identifier for Bob's PK      [20 octets]
        PK_ID = hash_item(pk)
        assert len(PK_ID) == 20

        x, data = a_op_to_induction_point_v2( pk, rp_address, rp_or_port, rp_id, rp_ok, rc)
        
        payload = PK_ID + data

        cell = buildRelayCell(self.hops[-1], 34, strId, payload)
        self.send(cell)
        # self.hops.append(self.tempX)

        # return self.tempX
        return x

    def a_op_to_induction_point_v3_spec(self, strId, pk,rp_address, rp_or_port, rp_id, rp_ok, rc):
        PK_ID = hash_item(pk)
        assert len(PK_ID) == 20
        x, data = a_op_to_induction_point_v2( pk, rp_address, rp_or_port, rp_id, rp_ok, rc)      
        payload = PK_ID + data
        cell = buildRelayCell(self.hops[-1], 34, strId, payload)
        self.send(cell)
        return x

    def handle_hs(self, pl, x):
        t3 = decodeCreatedCell(redv_payload, x) 
        self.hops.append(t3)   

    def create_stream_hs(self,strId, port):
        payload = "" + ":" + str(port) + "\x00" + struct.pack(">L", 0)
        relay = buildRelayCell(self.hops[-1], 1, strId, payload)
        self.send(relay)

def create_circuits(circ_name, hops):
    circ_name.toFirst(hops[0])
    created = recvCell(ssl_sock)
    assert created['circId'] == circ_name.circId and created['cmd'] == 2
    circ_name.handleCreated(created)
    count=0
    for hop in hops[1:]:
        print "hop :", hop
        circ_name.extend(0, hop)
        extended = recvCell(ssl_sock)
        assert extended['circId'] == circ_name.circId and extended['cmd'] == 3
        circ_name.extendedRecieved(extended['pl'])
        count = count + 1
        print "success, hop ",count

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
print "netinfoCell recieved "
srv_decodeNetInfo = decodeNetInfo(srv_netinfocell['pl']) # proccess the payload from the netinfo cell

srv_NetInfoToSend = NetInfoToSend(**srv_decodeNetInfo)
netinfoCell = buildCell(0, 8, srv_NetInfoToSend)
#print "netinfo to send ", netinfoCell.encode('hex')
ssl_sock.send(netinfoCell)
print "netinfo sent"

hops_in_circ =  ["orion", "TheVillage"]

circ_to_rend = TorCircuit(ssl_sock)
create_circuits(circ_to_rend,hops_in_circ)

#Testing to ensure that a stream can be sent through the tor network and out to a server
circ_to_rend.createStream(1, "ghowen.me", 80)
connected = recvCell(ssl_sock)
print connected
circ_to_rend.streamRecieved(connected['pl'])
print "Stream successfully established"
data = "GET /ip HTTP/1.1\r\nHost: ghowen.me\r\n\r\n"

circ_to_rend.streamData(1, data)

#Retrieves the data recieved from the request, looking for a 200 back
stream_data = []
while True:
   relayData = recvCell(ssl_sock)
   data = circ_to_rend.recievedStreamData(relayData['pl'])
   if (data['relayCmd']) == 3:
       break
   print data['pl']
   stream_data.append(data['pl'])
print stream_data


# idnxcnkne4qt76tg.onion It is the homepage of the Tor project

print "Retriving hidden service descriptor"
onion_Add = "3g2upl4pq6kufc4m"          #"kpvz7ki2v5agwt35"#Hidden Wiki   #"3g2upl4pq6kufc4m"#duck duck go     #"idnxcnkne4qt76tg" #homepage of the Tor project

responsible_HSDir_list = []
descriptor_id_list = []

for i in range(0, 2):
    descriptor_id = get_descriptor_Id(onion_Add, i)
    descriptor_id_list.append(descriptor_id)
    responsible_HSDir = find_responsible_HSDir(descriptor_id)
    responsible_HSDir_list.append(responsible_HSDir) # Saves all responsible HSDir information in a list to use later

print "responsible_HSDir_list", responsible_HSDir_list

ip_addresses, dirport, port, nickname, identity = extract_HSDir_data(responsible_HSDir_list)

web_addresses = connect_to_web_lookup(ip_addresses, dirport, descriptor_id_list)

print "web addr", web_addresses


n = 1 # Change this value to select a different router to connect to
i = 0 # change between 0 - 1   releated to descriptor list
service_descriptor_data = "GET /tor/rendezvous2/"+ descriptor_id_list[i] +" HTTP/1.1\r\nHost: "+web_addresses[n]+"\r\n\r\n"

#"GET HTTP/1.1\r\nHost:"+web_addresses[0]+"\r\n\r\n" #need to change so it loops through all web addresses if first fails etc
print "service_descriptor_data to send", service_descriptor_data

rendezvous_point = hops_in_circ[(len(hops_in_circ)-1)]
print "hops_in_circ : "  ,hops_in_circ #circuit we will be using
print  "No of hops in circ : ", len(hops_in_circ)
print "rendezvous_point", rendezvous_point
rendezvous_cookie = create_rendezvous_cookie()
rendezvous_cookie_payload = circ_to_rend.rendezvous_point_payload(rendezvous_cookie)

circ_to_rend.establish_rendezvous_point(1, rendezvous_cookie_payload)
relayData = recvCell(ssl_sock)
data = circ_to_rend.recievedStreamData(relayData['pl'])
print data
assert (data['relayCmd']) == 39 #Make sure only a RELAY_COMMAND_RENDEZVOUS2EZVOUS_ESTABLISHED is recieved


hops_in_circ =  ["orion", "TorLand1", "TheVillage"] #"WorldWithPrivacyNY1"
hops_in_circ.append(nickname[n]) #first IP
print "hops_in_circ : "  ,hops_in_circ #circuit we will be using
print  "No of hops in circ : ", len(hops_in_circ)

#Creates new circuit to the HSDir server
circ_to_HSDir = TorCircuit(ssl_sock)
create_circuits(circ_to_HSDir, hops_in_circ)

print web_addresses[n]

#creates a stream to the HSDir server to send data down
circ_to_HSDir.create_stream_hsdir(2, web_addresses[n])
connected = recvCell(ssl_sock)


# If the  address cannot be resolved, or a connection can't be established, the  exit node replies with a RELAY_END cell
# Had an issue with the creation stream, beccause it is a directory a RELAY_BEGIN_DIR cell needed to be sent instead
print connected
print circ_to_HSDir.streamRecieved(connected['pl'])

print "Stream successfully established to HSDir"

# sends the get request to a directory server
circ_to_HSDir.streamData(2, service_descriptor_data)

file_to_save = descriptor_id_list[0]+".txt"

text_file = open(file_to_save, "w") # creates a file to write the data recieved from the stream, done ths so always got a copy, saves format etc

while True:
    relayData = recvCell(ssl_sock)
    assert relayData['circId'] == circ_to_HSDir.circId
    data = circ_to_HSDir.recievedStreamData(relayData['pl'])
    if (data['relayCmd']) == 3: #End of stream data
        break
    print data['pl']
    text_file.write(data['pl'])
text_file.close()

#Retrieves data from the document recieved
rend_service_descriptor, RSA_pub_key, secret_id_part, message_decrypted,  signature = decode_recieved_document(file_to_save)

print "message_decrypted\n\n", message_decrypted

#saves  decrypted to a text file
file_decrypted_to_save = descriptor_id_list[0]+"_decrypted.txt"
message_decrypted_file = open(file_decrypted_to_save, "w")
message_decrypted_file.write(message_decrypted)
message_decrypted_file.close()

#Retrieves data from the decrypted version of the document recieved
introduction_point_decrypted, ip_addresses, onion_port, onion_key_decrypted, service_key_decrypted, service_key_encrypted = extract_data_from_file(file_decrypted_to_save)



print introduction_point_decrypted[0] #One of the chosen Introduction points

# Put a loop in here, if un named try another
introduction_point_nick = consensus.get_data_by_ip(ip_addresses[0])['nick'] #Retrieves the nickname based on ip address

hops_in_circ = ["orion", "TorLand1"]
hops_in_circ.append(introduction_point_nick) #first IP  added onto the end of the circ
print "hops_in_circ : "  ,hops_in_circ #circuit we will be using
print  "No of hops in circ : ", len(hops_in_circ)

#Create new circuit to send data to the chosen I.P
circ_to_ip= TorCircuit(ssl_sock)
create_circuits(circ_to_ip, hops_in_circ)

print "Circ to introduction point created successfully"

rp_id, rp_ip, rp_or_port, rp_onion_key = calc_rendezvous_point_data(rendezvous_point)

redv_x = circ_to_ip.a_op_to_induction_point(3, service_key_decrypted[0], rp_ip, rp_or_port, rp_id, rp_onion_key, rendezvous_cookie)

print "Connecting to the ip"
while True :
    data = recvCell(ssl_sock)
    # assert circ_to_ip.circId == data['circId']
    # print "data recived", data
    if circ_to_rend.circId == data['circId']:
        data = circ_to_rend.recievedStreamData(data['pl'])
        if data['relayCmd'] == 37 : 
            print "RELAY_COMMAND_RENDEZVOUS2"
            print "Rend point"
            print data
            print "relayCmd:",data['relayCmd']
            redv_payload = data['pl']
            # print     "Rendv point data payload",redv_payload.encode('hex')
            break
    elif circ_to_ip.circId == data['circId']:
        data = circ_to_ip.recievedStreamData(data['pl'])
        print data
        if data['relayCmd'] == 40 : 
            print "RELAY_COMMAND_INTRODUCE_ACK"
    else: 
        print "Unkown packet"
        print "data of unknown packet : ", data

print "Out of loop"
decoded_rendv2 = circ_to_rend.handle_hs (redv_payload, redv_x) 

#creates a stream to the hidden service to send data down
print "Creating stream to hs"
circ_to_rend.create_stream_hs(1, rp_or_port)
data = recvCell(ssl_sock)
recieved_stream = circ_to_rend.recievedStreamData(data['pl'])
if recieved_stream['relayCmd'] == 4: #RELAY_CONNECTED
    print  recieved_stream
    print "Stream created successfully"
else : 
    print "error creating stream"
    print "relayCmd : ", recieved_stream['relayCmd']  
    print recieved_stream 









## Tidying up at end, remove the downloaded docs, frees up memory space etc - needed ?
try:
        os.remove(file_to_save)
        print "deleted file :", file_to_save

except OSError, e:  ## if failed, report it back to the user ##
        print ("Error: %s - %s." % (e.filename,e.strerror))
try:
        os.remove(file_decrypted_to_save)
        print "deleted file :", file_decrypted_to_save

except OSError, e:  
        print ("Error: %s - %s." % (e.filename,e.strerror))





















































# print "No. of elements in HSDir_list", len(responsible_HSDir_list) #Currently 2
# print "type of responsible_HSDir_list", type(responsible_HSDir_list) #list


# first_responsible_HSDir_dict = {}
# for dic in responsible_HSDir_list[0]:
#     first_responsible_HSDir_dict.update(dic)

# flattened= ([x for y in  first_responsible_HSDir_dict for x in y])
# print [x.get('identityhash') for x in flattened]

# identityhash = [i.get('identityhash') for j in responsible_HSDir_list for i in j]
# print(identityhash)

# print first_responsible_HSDir_dict

# first_responsible_HSDir_dict = responsible_HSDir_list[1][1]  #using list access
# ip_address = first_responsible_HSDir_dict['ip']

# ip_addresses = []
# ports =[]
# for j in range(0, 2):
#     ip_addresses.append( [i.get('ip') for i in responsible_HSDir_list[j]])
#     ports.append( [i.get('ip') for i in responsible_HSDir_list[j]])


# ip_addresses = [i.get('ip') for j in data for i in j]

# print ip_addresses
#print ports


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
