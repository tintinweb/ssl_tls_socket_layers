'''
Created on Apr 13, 2014

@author: martin
'''
from utils import *
from layer.ssl.tls import *
from layer.base import Raw,TCP,UDP

import sys

'''
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

def main(opts):
    ip = opts['ip']
    port = opts['port']
    print ip,port

    tcp = TCP(ip=ip, port=443, buffer=16*1024)
    
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
            'port':80}
    main(opts)
    exit()