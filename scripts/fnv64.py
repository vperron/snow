#!/usr/bin/env python

import os
import sys
import struct
import pyhash
import random

from binascii import hexlify, unhexlify

hasher = pyhash.fnv1a_64()
str_seed = os.environ.get('SNOW_HASH_SEED', None)

seed = int(str_seed, 16)

print "seed is : %016x" % seed

mode = sys.argv[1]
txt = sys.argv[2]
if mode == 'mac':
    no_colons = txt.split(':')
    no_colons = ''.join(no_colons)
    data = unhexlify(no_colons)
    h = hasher(data, seed=seed)
    print "hash for '%s' is : %016x" % (txt, int(h))

if mode == 'raw':
    data = txt
    h = hasher(data, seed=seed)
    h = hexlify(struct.pack('>Q', h))
    print "hash for '%s' is : %s" % (txt, h)



