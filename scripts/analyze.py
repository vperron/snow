#!/usr/bin/env python

"""
Another version of deployd forwarder.
That one reduces the time overhead of another
proxy, thus improves latency issues.
"""

from __future__ import print_function
import zmq
import struct
import json

import sys
import re

zmq_endpoint = sys.argv[1]

struct_format = 'I4s3sb'

def debugLog(obj):
    if __debug__:
        print(obj)

def listify(string):
    return [hex(ord(c)) for c in string]

def byte_to_hex( bytestr ):
    return ''.join( [ "%02x" % ord( x ) for x in bytestr ] ).strip()

context = zmq.Context()
in_socket = context.socket(zmq.PULL)
in_socket.bind(zmq_endpoint)

print("Listening for wlan data on zmq endpoint : " + zmq_endpoint)

dbm_av = {}
f = open(sys.argv[2],'w')
count = 500

while count!=0:
    ident, msg = in_socket.recv_multipart()
    s = struct.unpack(struct_format, msg)
    ts = s[0]
    prefix = byte_to_hex(s[2])
    dbm = s[3]
    mac = byte_to_hex( s[1] )
    print(str(ts)+','+str(mac)+','+str(prefix)+','+str(dbm))
    print(str(ts)+','+str(mac)+','+str(prefix)+','+str(dbm),file=f)
    if mac in dbm_av:
        i = dbm_av[mac]
        i['n'] += 1
        i['sum'] += dbm
        i['av'] = i['sum'] / i['n']
    else:
        i = dict()
        i['n'] = 1
        i['sum'] = dbm
        i['av'] = dbm
        dbm_av[mac] = i
    count -= 1

for k,v in dbm_av.iteritems():
    print(v)
