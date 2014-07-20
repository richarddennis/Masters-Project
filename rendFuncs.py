from StringIO import StringIO
import binascii
from collections import namedtuple
import pprint
import os
#from OpenSSL import crypto
import time
import ssl,socket,struct
from binascii import hexlify
from Crypto.Hash import SHA
from Crypto.Cipher import *
from Crypto.PublicKey import *
import sys
from Crypto.Util import Counter
import consensus
import base64
import re
from urlparse import urlparse,urljoin,urlunsplit
import urllib
import urllib2
from urllib2 import Request, urlopen, URLError, HTTPError
import csv
import pprint
import sha
import struct
import itertools
import re
from Crypto.PublicKey import RSA
from Crypto.Util import asn1

from hashlib import sha1
from base64 import b32encode, b32decode, b64decode
from random import randint
from bisect import bisect_left

from torfuncs import *


def get_descriptor_Id(onion_Add, replica):
  service_id = b32decode(onion_Add, 1)
  time_period = int((((time.time()) + ((struct.unpack('B', service_id[0])[0] * 86400) ) / 256) ) / 86400 + 0)
  s = sha1()
  s.update(struct.pack('>I', time_period)[:4]);
  s.update('{0:02X}'.format(replica).decode('hex'))
  s = s.digest()
  d = sha1()
  d.update(service_id)
  d.update(s)
  d = d.digest()
  return b32encode(d).lower()

def find_responsible_HSDir(descriptor_id):
   responsible_HSDirs = []
   HSDir_List = consensus.get_HSDir_Flag()  # Allows us to only get the data containing the HSDir flags
   orHashList = sorted(map(lambda x: x['identity'], HSDir_List))
   descriptor_position = bisect_left(orHashList, b32decode(descriptor_id,1)) #should be identiy list not HSDir_List #TODO - Add the other part of the list to it so it makes a circle
   for i in range(0,3):
      responsible_HSDirs.append(orHashList[descriptor_position+i])
   return (map(lambda x: consensus.get_router_by_hash(x) ,responsible_HSDirs))

def create_rendezvous_cookie():
   rendezvous_cookie = os.urandom(20) #Random 20 byte value
   return rendezvous_cookie

def connect_to_web_lookup(ip_addresses, dirport, descriptor_id_list):
  web_addresses =[]
# creates a list of all possible web addresses to connect to using the data retrieved from above
  for i in range(0,len(descriptor_id_list)):
    for j in range(0,3):
      a_elem = i*3 + j
      web_addresses.append(ip_addresses[a_elem]+':'+str(dirport[a_elem]))
  return web_addresses

def calc_rendezvous_point_data(rendezvous_point):
  rp_ip = consensus.getRouter(rendezvous_point)['ip']
  rp_or_port = consensus.getRouter(rendezvous_point)['orport']
  rp_id = consensus.getRouter(rendezvous_point)['identity']
  router_descriptor = consensus.getRouterDescriptor((consensus.getRouter(rendezvous_point))['identityhash'])
  onion_key = consensus.getRouterOnionKey(router_descriptor)
  return rp_id, rp_ip, rp_or_port, onion_key

def getIndex(str,arr):
     for i in range(len(arr)):
             if str in arr[i]:
                     return i
     return -1

def extract_HSDir_data(responsible_HSDir_list):
  # Extracts the data here from the list generated above to connect to the web url to get the rendezvous2 data
  ip_addresses = [i.get('ip') for j in responsible_HSDir_list for i in j]
  dirport =  [i.get('dirport') for j in responsible_HSDir_list for i in j]
  port =  [i.get('port') for j in responsible_HSDir_list for i in j]
  nickname = [i.get('nick') for j in responsible_HSDir_list for i in j]
  identity = [i.get('identity') for j in responsible_HSDir_list for i in j]
  return ip_addresses, dirport, port, nickname, identity


def decode_recieved_document(file_to_open):
  rend_service_descriptor, RSA_pub_key, secret_id_part, message,  signature = [], [], [], [], []

  lines = open(file_to_open, "rt").readlines()

  # Gets the lines dynamically, although the doc should be of a standard size this protects againt any differences
  rs_line = getIndex("rendezvous-service-descriptor", lines)
  rs_line_end = getIndex("version", lines)

  rsa_line = getIndex("-----BEGIN RSA PUBLIC KEY-----", lines)+1
  rsa_line_end = getIndex("-----END RSA PUBLIC KEY-----", lines)

  s_id_line = getIndex("secret-id-part", lines)
  s_id_line_end = getIndex("publication-time", lines)

  msg_line = getIndex("-----BEGIN MESSAGE-----", lines)+1
  msg_line_end = getIndex("-----END MESSAGE-----", lines)

  sig_line = getIndex("-----BEGIN SIGNATURE-----", lines)+1
  sig_line_end = getIndex("-----END SIGNATURE-----", lines)

  #rend service descriptor
  with open(file_to_open, "r") as text_file:
      for line in itertools.islice(text_file, rs_line, rs_line_end):
          rend_service_descriptor.append(line)
  text_file.close()

  #RSA pub key
  with open(file_to_open, "r") as text_file:
      for line in itertools.islice(text_file, rsa_line, rsa_line_end):
          RSA_pub_key.append(line)
  text_file.close()

  #Secret id
  with open(file_to_open, "r") as text_file:
      for line in itertools.islice(text_file, s_id_line, s_id_line_end):
          secret_id_part.append(line)
  text_file.close()

  #Message
  with open(file_to_open, "r") as text_file:
      for line in itertools.islice(text_file, msg_line, msg_line_end):
          message.append(line)
  text_file.close()

  #Sig
  with open(file_to_open, "r") as text_file:
      for line in itertools.islice(text_file, sig_line, sig_line_end):
          signature.append(line)
  text_file.close()

  #Strips out to ensure only the data is saved
  rend_service_descriptor = str.split(''.join(rend_service_descriptor))[1]
  RSA_pub_key =  base64.b64decode(''.join(RSA_pub_key))
  secret_id_part = str.split(''.join(secret_id_part))[1]
  message =  base64.b64decode(''.join(message))
  signature = ''.join(signature)

  return rend_service_descriptor, RSA_pub_key, secret_id_part, message, signature

def convert_msg_to_dict(message):
  for l in message.splitlines():
            q = l.strip().split(" ")
            if q[0] == 'introduction-point': #router descriptor
                format = ['introduction-point']
                data = dict(zip(format, q[1:]))
                idt= data['introduction-point']
                print idt
            if q[0] == 'ip-address':
                format = ['ip-address']
                data = dict(zip(format, q[1:]))
                idt= data['ip-address']
                print idt
            if q[0] == 'onion-port':
                format = ['onion-port']
                data = dict(zip(format, q[1:]))
                idt= data['onion-port']
                print idt

def convert_msg_to_dict_regex(message):
  pat=re.compile(r"onion-key\s?-----BEGIN RSA PUBLIC KEY-----\s?(.*?)\s?-----END RSA PUBLIC KEY-----", re.DOTALL)
  result = {'onion-key': key for key in pat.findall(message)}
  pat = re.compile(r"([\w-]+)\s-----BEGIN RSA PUBLIC KEY-----\s(.*?)\s-----END RSA PUBLIC KEY-----", re.DOTALL)
  result = dict(pat.findall(message))
  results = [dict(pair) for pair in zip(*[iter(pat.findall(message))]*2)]
  return results

def extract_data_from_file(decrypted_file):
  introduction_point, ip_addresses, onion_port, ok, sk, onion_key_decrypted, service_key_decrypted, introduction_point_decrypted = [], [], [], [], [], [], [], []

  lines = open(decrypted_file, "rt").readlines()

  ip_line = getIndex("introduction-point", lines)
  print ip_line
  ip_add_line = getIndex("ip-address", lines)
  port_line = getIndex("onion-port", lines)


  rsa_line = getIndex("-----BEGIN RSA PUBLIC KEY-----", lines)+1
  rsa_line_end = getIndex("-----END RSA PUBLIC KEY-----", lines)

  sk_line = getIndex("service-key", lines)+2

  word_list=re.split('\s+',file(decrypted_file).read().lower())

  # Gets the number of times each is in the doc, have seen examples where anywhere between 1 and 4 are in each doc
  no_of_ip = word_list.count('introduction-point')
  # print no_of_ip
  no_of_ip_add = word_list.count('ip-address')
  print no_of_ip_add
  no_of_ports = word_list.count('onion-port')


  j = ip_line
  while len(introduction_point) < no_of_ip:
      # for line in itertools.islice(text_file, 0, 15, 30):#i, i+1):# i+2):
      #      introduction_point.append(str.split(''.join(line))[1])
    for i,line in enumerate(open(decrypted_file, "r")):
        if i >= j and i < j+1:
           introduction_point.append(str.split(''.join(line))[1])
    j = j + 15
  print introduction_point


  j = ip_add_line
  while len(ip_addresses) < no_of_ip_add:
      # for line in itertools.islice(text_file, 0, 15, 30):#i, i+1):# i+2):
      #      introduction_point.append(str.split(''.join(line))[1])
    for i,line in enumerate(open(decrypted_file, "r")):
        if i >= j and i < j+1:
           ip_addresses.append(str.split(''.join(line))[1])
    j = j + 15

  print ip_addresses


  j = port_line                                                                                       
  while len(onion_port) < no_of_ports:
    for i,line in enumerate(open(decrypted_file, "r")):
        if i >= j and i < j+1:
           onion_port.append(str.split(''.join(line))[1])
    j = j + 15
  print onion_port

  #Get all data contained within the RSA section
  j = rsa_line
  while len(ok) < (no_of_ip*3):
    for i,line in enumerate(open(decrypted_file, "r")):
        if i >= j and i < j+3 :
            ok.append(str.split(''.join(line))[0])
    j = j + 15

  #Get all data contained within the Service key section
  l = sk_line
  while len(sk) < (no_of_ip*3):
    for i,line in enumerate(open(decrypted_file, "r")):
        if i >= l and i < l+3 :
            sk.append(str.split(''.join(line))[0])
    l = l + 15

  if no_of_ip == 2:
    onion_key = ([i+j for i,j in zip(ok[::2], ok[1::2])])                                 
    service_key = ([i+j for i,j in zip(sk[::2], sk[1::2])])
  elif no_of_ip == 3:
    onion_key = ([i+j+k for i,j,k in zip(ok[::3], ok[1::3], ok[2::3])])
    service_key = ([i+j+k for i,j,k in zip(sk[::3], sk[1::3], sk[2::3])])
  elif no_of_ip == 4:
    onion_key = ([i+j+k+l for i,j,k,l in zip(ok[::4], ok[1::4], ok[2::4],  ok[3::4])])
    service_key = ([i+j+k+l for i,j,k,l in zip(sk[::4], sk[1::4], sk[2::4], sk[3::4])])

  #Decrypts the data
  for i in onion_key:
    onion_key_decrypted.append(base64.b64decode(i))

  for i in service_key:
    service_key_decrypted.append(base64.b64decode(i))

  print introduction_point
  
  for i in introduction_point:
    introduction_point_decrypted.append(base64.b64decode(i))

  print "no. of onion_key_decrypted", len(onion_key_decrypted)
  print "no. of service_key_decrypted", len(service_key_decrypted)
  print "no. of introduction_point_decrypted", len(introduction_point_decrypted)
  print "ip_addresses", ip_addresses
  print "onion_port", onion_port
  print "no. of service keys", (service_key)


  return  introduction_point_decrypted, ip_addresses, onion_port, onion_key_decrypted, service_key_decrypted, service_key

def a_op_to_induction_point_v2(pk, rp_address, rp_or_port, rp_id, rp_ok, rc):
#  629           VER    Version byte: set to 2.        [1 octets]
#  630           IP     Rendezvous point's address    [4 octets]
#  631           PORT   Rendezvous point's OR port    [2 octets]
#  632           ID     Rendezvous point identity ID [20 octets]
#  633           KLEN   Length of onion key           [2 octets]
#  634           KEY    Rendezvous point onion key [KLEN octets]
#  635           RC     Rendezvous cookie            [20 octets]
#  636           g^x    Diffie-Hellman data, part 1 [128 octets]

  # print "rp_address",rp_address
  # print "type rp_address", type(rp_address)

  rp_address_split = rp_address.split('.')
  rp_address_split = map(int, rp_address_split) #Changes from Str to int for all ip addresses

  data = struct.pack (">B", 2)
  print rp_address_split
  data += struct.pack("B" * len(rp_address_split), *rp_address_split)#* len(rp_address_split)
  data += struct.pack (">H", int(rp_or_port))
  print rp_or_port
  # rp_id_decoded = base64.standard_b64decode(rp_id)

  data += struct.pack (">20s", rp_id)
  data += struct.pack (">H", len(rp_ok))
  data += struct.pack("c" * len(rp_ok), *rp_ok)
  # data += (struct.pack ('!i', len(rp_ok)) + rp_ok)

  data += struct.pack ('!20s', rc)
  x = numunpack(os.urandom(DH_SEC_LEN))
  X = pow(DH_G,x,DH_P)
  X = numpack(X,DH_LEN)

  data += struct.pack ('128c', *X)

  assert len(data) == 177+len(rp_ok) #Check the packing have been done correct, currently is not
  
  keyPub = RSA.importKey(pk)
  data = hybridEncrypt(keyPub, data)

  return x, data


def a_op_to_induction_point_v3(pk, rp_address, rp_or_port, rp_id, rp_ok, rc):
 # 638           VER    Version byte: set to 3.        [1 octet]
 # 639           AUTHT  The auth type that is used     [1 octet]
 # 640           If AUTHT != [00]:
 # 641               AUTHL  Length of auth data           [2 octets]
 # 642               AUTHD  Auth data                     [variable]
 # 643           TS     A timestamp                   [4 octets]
 # 644           IP     Rendezvous point's address    [4 octets]
 # 645           PORT   Rendezvous point's OR port    [2 octets]
 # 646           ID     Rendezvous point identity ID [20 octets]
 # 647           KLEN   Length of onion key           [2 octets]
 # 648           KEY    Rendezvous point onion key [KLEN octets]
 # 649           RC     Rendezvous cookie            [20 octets]
 # 650           g^x    Diffie-Hellman data, part 1 [128 octets]


  # print "rp_address",rp_address
  # print "type rp_address", type(rp_address)

  rp_address_split = rp_address.split('.')
  # print "rp_address_split type", type(rp_address_split)
  # print "rp_address split", rp_address_split
  rp_address_split = map(int, rp_address_split) #Changes from Str to int for all ip addresses

  data = struct.pack (">B", 3)
  data += struct.pack (">B", 00)
  data += struct.pack (">I", time.time())
  print rp_address_split
  data += struct.pack("B" * len(rp_address_split), *rp_address_split)#* len(rp_address_split)

  data += struct.pack (">H", int(rp_or_port))
  # rp_id_decoded = base64.standard_b64decode(rp_id)

  data += struct.pack (">20s", rp_id)
  data += struct.pack (">H", len(rp_ok))
  data += struct.pack("c" * len(rp_ok), *rp_ok)
  # data += (struct.pack ('!i', len(rp_ok)) + rp_ok)

  data += struct.pack ('!20s', rc)
  x = numunpack(os.urandom(DH_SEC_LEN))
  X = pow(DH_G,x,DH_P)
  X = numpack(X,DH_LEN)

  data += struct.pack ('128c', *X)
  assert len(data) == 177+len(rp_ok) 
  
  keyPub = RSA.importKey(pk)
  data = hybridEncrypt(keyPub, data)

  return x, data
