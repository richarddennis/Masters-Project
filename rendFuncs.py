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
import urllib2
import csv
import pprint
import sha
import struct

from hashlib import sha1
from base64 import b32encode, b32decode

def get_descriptor_Id(service_id_base32, replica, descriptor_cookie = ""):
  service_id = b32decode(service_id_base32, 1)
  epoch_time = int(time.time())   #epoch time  seconds since 1970
  time_period = get_time_period(epoch_time, 0, service_id)
  si = sha1()
  si.update(struct.pack('>I', time_period)[:4]);
  if descriptor_cookie:
    si.update(descriptor_cookie)
  si.update('{0:02X}'.format(replica).decode('hex'))
  si = si.digest()
  di = sha1()
  di.update(service_id)
  di.update(si)
  di = di.digest()
  return b32encode(di).lower()


# Calculates time period - time-period = (current-time + permanent-id-byte * 86400 / 256) / 86400
def get_time_period(time, deviation, service_id):
  REND_TIME_PERIOD_V2_DESC_VALIDITY = 24 * 60 * 60
  return int(((time + ((struct.unpack('B', service_id[0])[0] * REND_TIME_PERIOD_V2_DESC_VALIDITY) ) / 256) ) / REND_TIME_PERIOD_V2_DESC_VALIDITY + deviation)




#    #descriptor-id = H(permanent-id | H(time-period | descriptor-cookie | replica))
#    #permanent-id = H(public-key)[:10]

# #  onion = base64.b32decode(onionb64.upper())
# #   curtime = int(parse(timestr).strftime("%s"))
# #   replica = 0
#    epoch_time = int(time.time())   #epoch time  seconds since 1970
#    timePeriod = struct.pack(">IB", int((epoch_time + ord(onion[0]) * 86400 // 256) // 86400),replica)
#    ht = sha.new()
#    ht.update(timePeriod)
#    hashT = ht.digest()
#    h = sha.new()
#    h.update(onion + hashT)
#    return base64.b32encode(h.digest()).lower()


# #f = urllib.urlopen('http://'+router['address']+':'+str(router['dir_port'])+'/tor/rendezvous2/'+router['descriptor_id'])


# def rendezvous2d_compute_v2_desc_id(service_id_base32, replica, time = int(time()), descriptor_cookie = ""):
#   service_id = b32decode(service_id_base32, 1)
#   return service_id
