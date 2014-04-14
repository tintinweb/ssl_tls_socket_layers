

from src.utils import *
from src.layer import *


class TLSRecord(Layer):    
    def _definition(self):
        # fields and their wire-definition
        # in order!
        self.add_field(name='content_type', struct='!B', default=0x18)
        self.add_field(name='version', struct='!H', default=0x0302)
        self.add_field(name='length', struct='!H', default=self.next_len)
        
class TLSHandshake(Layer):
    TLSRECORD_CONTENT_TYPE = 0x22
    TYPE_CLIENT_HANDSHAKE = 0x01
    TYPE_SERVER_HANDSHAKE = 0x02
     
    def _definition(self):
        
        self.add_field(name='type', struct='!B', default=self.TYPE_CLIENT_HANDSHAKE)          #client hello
        self.add_field(name='dummy_len_remove_me_fixme', struct='!B', default=0x00)
        self.add_field(name='length', struct='!H', default=142-4)
        self.add_field(name='version', struct='!H', default=0x0302)
        #
        self.add_field(name='random', default=TLSPropRandom().serialize)
        #
        self.add_field(name='session_id', struct='!B', default=0)
        #
        self.add_field(name='cipher_suites', default=TLSPropCipherSuites().serialize)
        #
        self.add_field(name='compression_methods', default=TLSPropCompressionMethod().serialize)
        #
        self.add_field(name='extensions', default=TLSExtensionList().serialize)

class TLSPropRandom(Layer):
    def _definition(self):
        self.add_field(name="gmt_unix_time",  default=h2bin('53 43 5b 90')) #struct="!BBBB",
        self.add_field(name="random_bytes", default="A"*28)
        
class TLSPropCipherSuites(Layer):
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA  = 0xc014
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xc00a
    TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA = 0xc022
    TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA = 0xc021
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x0039
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA = 0x0038
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0088
    TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA = 0x0087
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA = 0xc00f
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA =0xc005
    TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0084
    
    def _definition(self):
        self.add_field(name="length", struct='!H', default=self.cipher_list_length)
        self.add_field(name="cipher_suites",  default=self.ciphers_all)
        
    def ciphers_all(self):
        return "".join( [struct.pack('!H',getattr(self,c)) for c in dir(self) if c.startswith("TLS_")])

    
    def cipher_list_length(self):
        return len(self.fields['cipher_suites'])
    
class TLSPropCompressionMethod(Layer):
    TLS_COMPRESS_NULL = 0x00
    
    def _definition(self):
        self.add_field(name="length", struct='!B', default=self.compress_list_length)
        self.add_field(name="compression_methods", default=self.compress_all)
        
    def compress_all(self):
        return "".join( [struct.pack('!B',getattr(self,c)) for c in dir(self) if c.startswith("TLS_")])
    
    def compress_list_length(self):
        return len(self.fields['compression_methods'])


class TLSExtensionList(Layer):
    def _definition(self):
        self.add_field(name="length", struct='!H', default=self.get_extensions_length)
        self.add_field(name="extensions",  default=self.get_extensions)
        
    def get_extensions(self):
        exts = [
                
                h2bin(" 00 0b 00 04 03 00 01 02"),  # ec_points_format
                h2bin("""00 0a 00 34 00 32 00 0e 00 0d 00 19 00 0b 00 0c 
   00 18 00 09 00 0a 00 16 00 17 00 08 00 06 00 07  
   00 14 00 15 00 04 00 05 00 12 00 13 00 01 00 02
   00 03 00 0f 00 10 00 11  """),                   # elliptic_curves
                
                h2bin("00 23 00 00 "),              #session ticket
                h2bin("00 0f 00 01 01"),            # heartbeat
                ]
        return "".join(exts)
    
    def get_extensions_length(self):
        print "len extensions",len(self.get_extensions())
        return len(self.get_extensions())
          
class TLSHeartBeat(Layer):    
    def _definition(self):
        # fields and their wire-definition
        # in order!
        self.add_field(name='HeartbeatMessageType', struct='!B', default=0x01)
        self.add_field(name='payload_length', struct='!H', default=self.payload_length)
        self.add_field(name='payload', default='')
        self.add_field(name='padding', default=self.padding)
        
    def payload_length(self):
        return len(self.fields['payload'])

    def padding(self):
        return 'P' * (0 if self.payload_length() >= 16 else 16)





def serialize(layer):
    # layer = leaf layer .. we need to serialize this bottom up
    # last layer
    data = ''
    while (layer):
        layer_data = layer.serialize()  # bottom layer serialized data
        layer_len = len(layer_data)     # bottom layer serialized len
        print "*  serializing %s size=%s"%(repr(layer.__class__.__name__),layer_len)
        data = layer_data + data        # <previ.data> <next.data>
        layer.curr_layer_len = layer_len
        hexdump_squashed(layer_data)
        layer=layer.prev                # switch to previous layer
        # update size?
        if not layer:
            #no need to do this if this was root
            break
        layer.next_layer_len= layer_len       # update sizeof (next layer)
        print "set",layer_len
        # update data

    return data
    
    
    
    
if __name__=="__main__":
    
    x=TLSRecord()
    x.unserialize("\x01\x00\x02\x04\x05")   
    print repr(x)
    exit()

    serialize(TLSHandshake())
    exit()

    x = TLSRecord(version=0xffff)
    y = TLSRecord(version=1)
    z = TLSRecord(version=2)
    h = TLSHeartBeat(payload="a", padding='X')
    
    a = x/y/z/h
    print "next",repr(a.next)
    print "prev",repr(a.prev)

    hexdump_squashed( serialize(a) )
    exit()

    hexdump_squashed(h.serialize())
    #hexdump_squashed(str(x))
    exit()
    print x/y
    print x.prev,"--",x.next