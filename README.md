ssl_tls_socket_layers
=====================

ssl tls tcp udp layers for python sockets intended for messing with tls ssl protocol fields (fuzzing, exploitation, ...)


a general purpose TLS protocol layer implementation on top of python sockets.
no dependencies


work in progress...


TODO    
-----
* proto description with class only.. no serialize/unserialize
* get rid of utils.serialize
* move hexdump to layer
* allow cross proto manipulations
    * upper layer accesses lower layer to set own fields
* only serialize once
    * dirty bits? serialize on update or only on read op
* match protocol based on layer descriptions
    
    
 - tintin
 
 
 	# example: layered TLS messages on top of ordinary sockets
 	#
	tcp = TCP(ip="172.16.0.55", port=443, buffer=16*1024)	# response buffer
	
	# build extension list
	ext = TLSExtensionList(extensions=TLSExtension()/TLSServerNameList()+
	                                    TLSExtension()/TLSSessionTicket(data='N'*15+"I"*15+'\x00\x20'+'T'*0x20))
	
	# build valid TLS 1.0 Record with TLS 1.1 Handshake
	#  + append extensions defined above
	#  + autocalculates all other fields
	p = TLSRecord(version=0x0301, content_type=0x16)/TLSHandshake(version=0x0302, extensions=ext)
	print tcp/Raw(data=p.serialize())