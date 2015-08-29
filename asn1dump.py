#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""Parse and dump DER.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import pprint
import json
import binascii
import sys
import datetime
import logging
import errno
import os.path
import gzip

from struct import Struct

from oids import OIDS, PREFIXES

show_oids = 0

def parse_primitive_int(buf):
    return int(buf.get_all().encode('hex'), 16)

def parse_primitive_bitstr(buf):
    init = buf.get_byte()
    if init > 7:
        raise Exception('invalid bitstr initial value')
    if init == 0:
        v = buf.get_all()
        return b'bitstr:len=%d' % len(v)
    v = parse_primitive_int(buf)
    return v >> init

def parse_primitive_octstr(buf):
    data = buf.get_all()
    try:
        r = RBuf(data)
        return r.parse_asn1_seq('OCT')
    except:
        #logging.exception("oct parse")
        return b'oct:'+data.encode('hex')

def parse_primitive_utf8(buf):
    return buf.get_all().decode('utf8')

_new_oids = {}

def parse_oid(buf):
    oid = buf.parse_oid()
    name = OIDS.get(oid)
    if name:
        return name.encode('utf8')
    for k in PREFIXES:
        if oid.startswith(k):
            oid = PREFIXES[k]
            return oid.encode('utf8')
    _new_oids[oid] = _new_oids.get(oid, 0) + 1
    return oid.encode('utf8')

def string_decoder(name, encoding):
    def decoder(buf):
        v = buf.get_all()
        try:
            s = v.decode(encoding)
        except UnicodeDecodeError:
            s = repr(v)
        res = name + ':' + s
        #res = s
        return res.encode('utf8')
    return decoder

def _splitby2(s):
    if len(s) % 2 != 0:
        raise Exception('invalid length for time: %s' % s)
    res = []
    pos = 0
    while pos < len(s):
        res.append(int(s[pos : pos+2], 10))
        pos += 2
    return res

def convert_time(s, yearchars):
    if s[-1] != b'Z':
        raise Exception('invalid GeneralizedTime: no Z')
    s, subsec = s[:-1], ''
    if s.find('.') > 0:
        s, subsec = s.split('.')
    year = int(s[:yearchars], 10)
    if yearchars == 2:
        if year >= 50:
            year += 1900
        else:
            year += 2000
    parts = _splitby2(s[yearchars:])
    usec = sec = 0
    mon, day, h, m = parts[:4]
    if len(parts) > 4:
        sec = parts[4]
    if subsec:
        usec = int(float('0.' + subsec) * 1000000)
    return datetime.datetime(year, mon, day, h, m, sec, usec)

def time_decoder(name, yearchars):
    def decoder(buf):
        s = buf.get_all()
        try:
            return convert_time(s, yearchars)
        except:
            return b'badtime: '+s
    return decoder

def parse_real(buf):
    if not buf.avail():
        return 0.0
    t = buf.get_byte()
    if t & 0x80:
        # binary float
        sign = (t & 0x40) and 1 or -1
        base = (2, 8, 16, -1)[(t >> 4) & 3]
        fac = 1 << ((t >> 2) & 3)
        explen = (t & 3) + 1        # orig bits: 00:1b, 01:2b, 10:3b, 11:has-len-byte
        if explen == 4:
            explen = buf.get_byte() # number of bytes
        exp = buf.get_beint(explen)
        num = buf.get_beint(buf.avail_bytes())
    elif t & 0x40:
        # SpecialRealValue
        pass
    else:
        pass
        # decimal float

    raise Exception("REAL value not supported")

primitive_tags = {
    1: ('bool', lambda buf: buf.get_byte() != 0 ),
    2: ('int', parse_primitive_int ),
    3: ('BITSTR', parse_primitive_bitstr ),
    4: ('octstr', parse_primitive_octstr ),
    5: ('null', lambda buf: None ),
    6: ('OID', parse_oid),
    #7: ('odesc', None),
    9: ('real', parse_real),
    10: ('enum', parse_primitive_int),                  # ?
    12: ('utf8',  string_decoder('utf8', 'utf8')),
    13: ('reloid',  lambda buf: buf.parse_rel_oid()),
    18: ('numstr', string_decoder('numstr', 'ascii')),
    19: ('pstr', string_decoder('pstr', 'ascii')),
    20: ('t61', string_decoder('t61', 'latin1')),
    21: ('vxstr', string_decoder('vxstr', 'ascii')),
    22: ('ia5', string_decoder('ia5', 'ascii')),
    23: ('utctime', time_decoder('utctime', 2)),
    24: ('gentime', time_decoder('gentime', 4)),
    25: ('gfxstr', string_decoder('gfxstr', 'ascii')),
    26: ('vistr', string_decoder('vistr', 'ascii')),
    27: ('genstr', string_decoder('genstr', 'ascii')),
    28: ('unistr', string_decoder('unistr', 'ascii')),
    29: ('chastr', string_decoder('chastr', 'ascii')),
    30: ('bmp', string_decoder('bmp', 'utf-16be')),
}

class RBuf(object):
    r"""Binary data reader.
    
    >>> rb = RBuf("\x11\x22\x33\x44\x55\x66\x77\x88\x99\xffXZ")
    >>> '%x' % rb.get_be32()
    '11223344'
    >>> '%x' % rb.get_be24()
    '556677'
    >>> '%x' % rb.get_be16()
    '8899'
    >>> '%x' % rb.get_byte()
    'ff'
    >>> rb.get_char()
    'X'
    >>> rb.get_str(1)
    'Z'
    """
    __slots__ = ('pos', 'end', 'blob', '_brun')

    def __init__(self, blob, start=0, end=None):
        if end is None:
            end = len(blob)
        if start > end or end > len(blob):
            raise ValueError("invalid size")
        self.pos = start
        self.end = end
        self.blob = blob
        self._brun = 0

    def check_bounds(self, cnt):
        if self.pos + cnt > self.end:
            raise ValueError("Out of bounds: [%d - %d] req=%d avail=%d" % (
                self.pos, self.end, cnt, self.end - self.pos))

    def avail(self):
        return self.pos < self.end

    def avail_bytes(self):
        return self.end - self.pos

    def copy_remaining(self):
        return RBuf(self.blob, self.pos, self.end)

    def skip(self, cnt):
        self.check_bounds(cnt)
        self.pos += cnt

    _be32 = Struct(b">L")
    def get_be32(self):
        self.check_bounds(4)
        res = self._be32.unpack_from(self.blob, self.pos)
        self.pos += 4
        return res[0]

    _be24 = Struct(b">BBB")
    def get_be24(self):
        self.check_bounds(3)
        res = self._be24.unpack_from(self.blob, self.pos)
        self.pos += 3
        return (res[0] << 16) | (res[1] << 8) | res[2]

    _be16 = Struct(b">H")
    def get_be16(self):
        self.check_bounds(2)
        res = self._be16.unpack_from(self.blob, self.pos)
        self.pos += 2
        return res[0]

    _byte = Struct(b">B")
    def get_byte(self):
        self.check_bounds(1)
        res = self._byte.unpack_from(self.blob, self.pos)
        self.pos += 1
        return res[0]

    def get_beint(self, nbytes):
        if nbytes == 1:
            return self.get_byte()
        if nbytes == 2:
            return self.get_be16()
        if nbytes == 3:
            return self.get_be24()
        if nbytes == 4:
            return self.get_be32()
        v = self.get_str(nbytes)
        return int(v.encode('hex'), 16)

    def get_char(self):
        self.check_bounds(1)
        res = self.blob[self.pos]
        self.pos += 1
        return res

    def get_str(self, slen):
        self.check_bounds(slen)
        res = self.blob[ self.pos : self.pos + slen ]
        self.pos += slen
        return res

    def get_all(self):
        return self.get_str(self.avail_bytes())

    def get_buf(self, blen):
        self.check_bounds(blen)
        res = RBuf(self.blob, self.pos, self.pos + blen)
        self.pos += blen
        return res

    def get_asn1_value(self):
        # parse identifier byte
        tid = self.get_byte()
        cls = tid & 0xC0                    # 00-native, 01-app, 10-context, 11-private
        is_primitive = (tid & 0x20) == 0    # is constructed or primitive
        tag = tid & 0x1F

        if tag == 0x1F:
            raise Exception("Long tag not supported")

        if cls == 0:
            xname = None
        elif cls == 0x80:
            xname = 'CTX-%d' % tag
        elif cls == 0x40:
            xname = 'APP-%d' % tag
        elif cls == 0xC0:
            xname = 'PRIV-%d' % tag

        dlen = self.get_byte()
        if dlen & 0x80:
            dlen = self.get_beint(dlen & 0x7F)
        buf = self.get_buf(dlen)
        if is_primitive:
            if xname:
                val = buf.get_all()
                try:
                    val = val.decode('utf8')
                except UnicodeDecodeError:
                    val = val.encode('hex')
                return ('%s: %s' % (xname, val)).encode('utf8')
                #raise Exception("Primitive + non-standard: %s %s" % (xname, buf.get_all()))
            desc, conv = primitive_tags[tag]
            res = conv(buf)
            if buf.avail():
                raise Exception("Not fully parsed value: %s" % desc)
            return res
        elif cls == 0:
            if tag == 16: # SEQ
                return buf.parse_asn1_seq()
            if tag == 17: # SET
                res = {}
                for k, v in buf.parse_asn1_seq():
                    res[k] = v
                return res
            raise Exception("Invalid complex tag: %d" % tag)
        else:
            res = buf.parse_asn1_seq(xname)
            return res

    def parse_asn1_seq(self,name=None):
        res = []
        if name:
            if isinstance(name, unicode):
                name = name.encode('utf8')
            res.append(name)
        while self.avail():
            res.append(self.get_asn1_value())
        if name:
            return tuple(res)
        return res

    def parse_oid(self):
        v = self.parse_oid_elem()
        if v < 40:
            oid = [0, v]
        elif v < 80:
            oid = [1, v - 40]
        else:
            oid = [2, v - 80]
        while self.avail():
            oid.append(self.parse_oid_elem())
        return '.'.join([str(v) for v in oid])

    def parse_oid_elem(self):
        v = self.get_byte()
        if v == 0x80:
            raise Exception('Invalid OID init: 0x80')
        val = v & 0x7f
        while v & 0x80:
            v = self.get_byte()
            val = (val << 7) | (v & 0x7F)
        return val

    def parse_rel_oid(self):
        oid = []
        while self.avail():
            oid.append(self.parse_oid_elem())
        return '.'.join([str(v) for v in oid])

def parse_pem(data):
    import binascii
    blines = []
    start = False
    gotend = False
    for ln in data.splitlines():
        if not start:
            if ln.startswith('-----BEGIN'):
                start = True
            continue
        if ln.startswith('-----END'):
            gotend = True
            break
        blines.append(ln)
    if not gotend:
        raise Exception('did not find end')
    src = ''.join(blines).encode('utf8')
    blob = binascii.a2b_base64(src)
    buf = RBuf(blob)
    return buf.parse_asn1_seq()

def parse_pem_file(fn):
    with open(fn, 'r') as f:
        data = f.read()
        return parse_pem(data)

def print_result(res):
    if not show_oids:
        pprint.pprint(res, width=160)


def show_pem_file(fn):
    res = parse_pem_file(fn)
    print_result(res)

def show_gz_file(fn):
    f = gzip.open(fn, 'r')
    for ln in f:
        h, data = ln.split(',')
        raw = data.decode('base64')
        res = RBuf(raw).parse_asn1_seq()
        print_result(res)

def print_new_oids():
    tmp = []
    for oid, num in _new_oids.items():
        tmp.append( (num, oid) )
    tmp.sort()
    for num, oid in tmp:
        print("%4d - %s" % (num, oid))

def main():
    global show_oids

    args = sys.argv[1:]
    if args and args[0] == '-o':
        show_oids = 1
        args = args[1:]

    for fn in args:
        print(b"## %s ##" % fn)
        ext = os.path.splitext(fn)[1]
        if ext == '.gz':
            show_gz_file(fn)
        elif ext in ('.crt', '.pem'):
            show_pem_file(fn)

    if show_oids:
        print_new_oids()

if __name__ == '__main__':
    try:
        main()
    except IOError as ex:
        if ex.errno != errno.EPIPE:
            print(str(ex))
    except KeyboardInterrupt:
        pass

