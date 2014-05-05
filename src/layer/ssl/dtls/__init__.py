from utils import *
from layer import *
import time, os
import layer.ssl.tls 


class DTLSRecord(Layer):
    CONTENT_TYPE_CHANGE_CIPHER_SPEC = 20
    CONTENT_TYPE_ALERT = 21
    CONTENT_TYPE_HANDSHAKE = 22
    CONTENT_TYPE_APPLICATION_DATA = 23
    CONTENT_TYPE_HEARTBEAT = 24
    CONTENT_TYPE_UNKNOWN_255 = 255
    
    PROTOCOL_DTLS_1_0_OPENSSL_PRE_0_9_8f = 0x0100
    PROTOCOL_DTLS_1_0 = 0xfeff
    PROTOCOL_DTLS_1_1 = 0xfefd

    
    def _definition(self):
        # fields and their wire-definition
        # in order!
        self.add_field(name='content_type', struct='!B', default=self.next_magic)
        self.add_field(name='version', struct='!H', default=self.PROTOCOL_DTLS_1_0)
        self.add_field(name='epoch', struct='!H', default=0x00)
        self.add_field(name='sequence', struct='!Q{6}', default=0x00)            # 6bytes of long.long
        self.add_field(name='length', struct='!H', default=self.next_size)
        
class DTLSHandshake(layer.ssl.tls.TLSHandshake): 
    TYPE_HELLO_VERIFY = 0x03
 
    def _definition(self):
        
        self.add_field(name='type', struct='!B', default=self.next_magic)          #client hello
        #self.add_field(name='length_hi', struct='!B', default=0x00)  #fix!
        self.add_field(name='length', struct='!I{3}', default=self.get_handshake_length) #+2
        
        self.add_field(name='sequence', struct='!H',default=0x00)
        self.add_field(name='fragment_offset', struct='!I{3}', default=0x00)
        self.add_field(name='fragment_length', struct='!I{3}', default=self.get_handshake_length)
     
        self.add_field(name='data', default=DTLSClientHello())
        
        
class DTLSClientHello(Layer):
     
    
    def _definition(self):
        self.MAGIC = DTLSHandshake.TYPE_CLIENT_HELLO
        self.add_field(name='version', struct='!H', default=DTLSRecord.PROTOCOL_DTLS_1_0)
        #
        self.add_field(name='random', default=layer.ssl.tls.TLSPropRandom())
        #
        self.add_field(name='session_id', struct='!B', default=0)
        #
        self.add_field(name='cookie', default=DTLSPropCookie())
        #
        self.add_field(name='cipher_suites', default=layer.ssl.tls.TLSPropCipherSuites())
        #
        self.add_field(name='compression_methods', default=layer.ssl.tls.TLSPropCompressionMethod())
        #
        self.add_field(name='extensions', default=layer.ssl.tls.TLSExtensionList())

class DTLSHelloVerify(Layer):
    
    
    def _definition(self):
        self.MAGIC = DTLSHandshake.TYPE_HELLO_VERIFY
        self.add_field(name='version', struct='!H', default=DTLSRecord.PROTOCOL_DTLS_1_0)    
        self.add_field(name='cookie', default=DTLSPropCookie())
        
class DTLSPropCookie(Layer):
    def _definition(self):
        self.add_field(name='length', struct='!B', default=self.get_cookie_length)
        self.add_field(name='cookie', default='')
        
    def get_cookie_length(self):
        return len(self.fields['cookie'])