ssl_tls_socket_layers
=====================

ssl tls tcp udp layers for python sockets intended for messing with tls ssl protocol fields (fuzzing, exploitation, ...)


a general purpose TLS protocol layer implementation on top of python sockets.
no dependencies


work in progress...


TODO:    
    * proto description with class only.. no serialize/unserialize
    * get rid of utils.serialize
    * move hexdump to layer
    * allow cross proto manipulations
        * upper layer accesses lower layer to set own fields
    * only serialize once
        * dirty bits? serialize on update or only on read op
    * match protocol based on layer descriptions
    
    
 - tintin