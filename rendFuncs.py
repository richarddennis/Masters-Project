from StringIO import StringIO
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

from hashlib import sha1
from base64 import b32encode, b32decode
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
  rp_id = consensus.getRouter(rendezvous_point)['identityhash']
  router_descriptor = consensus.getRouterDescriptor((consensus.getRouter(rendezvous_point))['identityhash'])
  onion_key = consensus.getRouterOnionKey(router_descriptor)
  return rp_id, rp_ip, rp_or_port, onion_key



def a_op_to_induction_point_v2(rp_address, rp_or_port, rp_id, rp_ok, rc):
#  629           VER    Version byte: set to 2.        [1 octet]
#  630           IP     Rendezvous point's address    [4 octets]
#  631           PORT   Rendezvous point's OR port    [2 octets]
#  632           ID     Rendezvous point identity ID [20 octets]
#  633           KLEN   Length of onion key           [2 octets]
#  634           KEY    Rendezvous point onion key [KLEN octets]
#  635           RC     Rendezvous cookie            [20 octets]
#  636           g^x    Diffie-Hellman data, part 1 [128 octets]

  data = struct.pack ('!1s', str(2))
  data += struct.pack ('!4s', rp_address)#.split('.'))  
  data += struct.pack ('!2s', rp_or_port)
  data += struct.pack ('!20s', rp_id)
  data += struct.pack ('!2s', str(len(rp_ok)))
  data += (struct.pack ('!i', len(rp_ok)) + rp_ok)
  data += struct.pack ('!20s', rc)

  x = numunpack(os.urandom(DH_SEC_LEN))
  X = pow(DH_G,x,DH_P)
  data += struct.pack ('!128s', str(X))

  return data

def decode_recieved_document(file_to_open): 
  rend_service_descriptor, RSA_pub_key, secret_id_part, message,  signature = [], [], [], [], []

  #rend service descriptor
  with open(file_to_open, "r") as text_file:
      for line in itertools.islice(text_file, 8, 9):
          rend_service_descriptor.append(line)
  text_file.close() 

  #RSA pub key
  with open(file_to_open, "r") as text_file:
      for line in itertools.islice(text_file, 12, 15):
          RSA_pub_key.append(line)
  text_file.close() 

  #Secret id
  with open(file_to_open, "r") as text_file:
      for line in itertools.islice(text_file, 16, 17):
          secret_id_part.append(line)
  text_file.close()  

  #Message
  with open(file_to_open, "r") as text_file:
      for line in itertools.islice(text_file, 21, 60):
          message.append(line)
  text_file.close()

  #Sig
  with open(file_to_open, "r") as text_file:
      for line in itertools.islice(text_file, 63, 66):
          signature.append(line)
  text_file.close()        
                                                                  
  rend_service_descriptor = str.split(''.join(rend_service_descriptor))[1]
  RSA_pub_key = ''.join(RSA_pub_key)
  secret_id_part = str.split(''.join(secret_id_part))[1]
  message = ''.join(message)
  signature = ''.join(signature)

  return rend_service_descriptor, RSA_pub_key, secret_id_part, message,  signature

