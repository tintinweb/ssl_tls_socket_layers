'''
@author: tintinweb

'''
from utils import *
from layer import *
import time, os


class TLSRecord(Layer):
    CONTENT_TYPE_CHANGE_CIPHER_SPEC = 20
    CONTENT_TYPE_ALERT = 21
    CONTENT_TYPE_HANDSHAKE = 22
    CONTENT_TYPE_APPLICATION_DATA = 23
    CONTENT_TYPE_HEARTBEAT = 24
    CONTENT_TYPE_UNKNOWN_255 = 255
    
    PROTOCOL_TLS_1_0 = 0x0301
    PROTOCOL_TLS_1_1 = 0x0302
    PROTOCOL_TLS_1_2 = 0x0303
    
    def _definition(self):
        # fields and their wire-definition
        # in order!
        self.add_field(name='content_type', struct='!B', default=self.next_magic)
        self.add_field(name='version', struct='!H', default=self.PROTOCOL_TLS_1_0)
        self.add_field(name='length', struct='!H', default=self.next_size)
        
class TLSHandshake(Layer):
    TYPE_HELLO_REQUEST = 0x00
    TYPE_CLIENT_HELLO = 0x01
    TYPE_SERVER_HELLO =0x02
    TYPE_CERTIFICATE =0x0b
    TYPE_SERVER_KEY_EXCHANGE = 0x0c
    TYPE_CERTIFICATE_REQUEST = 0x0d
    TYPE_SERVER_HELLO_DONE = 0x0e
    TYPE_CERTIFICATE_VERIFY = 0x0f
    TYPE_CLIENT_KEY_EXCHANGE = 0x10
    TYPE_FINISHED = 20
    TYPE_CERTIFICATE_URL = 21
    TYPE_CERTIFICATE_STATS = 22
    TYPE_UNKNOWN_255 = 0xff
     
     
    MAGIC = TLSRecord.CONTENT_TYPE_HANDSHAKE
    def _definition(self):
        
        self.add_field(name='type', struct='!B', default=self.next_magic)          #client hello
        #self.add_field(name='length_hi', struct='!B', default=0x00)  #fix!
        self.add_field(name='length', struct='!I{3}', default=self.get_handshake_length) #+2
        
        self.add_field(name='data', default=TLSClientHello())
        
    def next_magic(self):
        return self.fields['data'].getValue().MAGIC

    def get_handshake_length(self):
        print "data",len(self.fields['data']),"<---"
        return len(self.fields['data'])
        #
        #self.add_field(name='data', default=TLSClientHello())
        '''
        self.add_field(name='version', struct='!H', default=TLSRecord.PROTOCOL_TLS_1_1)
        #

        self.add_field(name='random', default=TLSPropRandom())
        #
        self.add_field(name='session_id', struct='!B', default=0)
        #
        self.add_field(name='cipher_suites', default=TLSPropCipherSuites())
        #
        self.add_field(name='compression_methods', default=TLSPropCompressionMethod())
        #
        self.add_field(name='extensions', default=TLSExtensionList())
        '''
    def get_handshake_size(self):
        skip =('type','length_hi','length')
        return sum( len(value) for f_name,value in self.fields.iteritems() if f_name not in skip )

class TLSClientHello(Layer):
     
    MAGIC = TLSHandshake.TYPE_CLIENT_HELLO
    def _definition(self):
        self.add_field(name='version', struct='!H', default=TLSRecord.PROTOCOL_TLS_1_1)
        #
        self.add_field(name='random', default=TLSPropRandom())
        #
        self.add_field(name='session_id', struct='!B', default=0)
        #
        self.add_field(name='cipher_suites', default=TLSPropCipherSuites())
        #
        self.add_field(name='compression_methods', default=TLSPropCompressionMethod())
        #
        self.add_field(name='extensions', default=TLSExtensionList())


class TLSPropRandom(Layer):
    def _definition(self):
        self.add_field(name="gmt_unix_time", struct='!I', default=int(time.time()))
        self.add_field(name="random_bytes", default=os.urandom(28))
        
class TLSPropCipherSuites(Layer):
    
    TLS_NULL_WITH_NULL_NULL = 0x0000
    
    TLS_RSA_WITH_NULL_MD5 = 0x0001
    
    TLS_RSA_WITH_NULL_SHA1 = 0x0002
    TLS_RSA_WITH_NULL_SHA256 = 0x003b
    
    TLS_RSA_WITH_3DES_EDE_CBC_SHA =  0x000a
    
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA  = 0x0016    
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA  = 0x0013
    TLS_RSA_WITH_3DES_EDE_CBC_SHA =  0x000a
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA  =  0x0033
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA  = 0x0032
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x002f
    TLS_RSA_WITH_IDEA_CBC_SHA  = 0x0007
    TLS_DHE_DSS_WITH_RC4_128_SHA  = 0x0066
    TLS_RSA_WITH_RC4_128_SHA  = 0x0005
    TLS_RSA_WITH_RC4_128_MD5  = 0x0004
    TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA  = 0x0063
    TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA  = 0x0062
    TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5  = 0x0061
    TLS_DHE_RSA_WITH_DES_CBC_SHA  = 0x0015
    TLS_DHE_DSS_WITH_DES_CBC_SHA  = 0x0012
    TLS_RSA_WITH_DES_CBC_SHA  = 0x0009
    TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA  = 0x0065
    TLS_RSA_EXPORT1024_WITH_RC4_56_SHA  = 0x0064
    TLS_RSA_EXPORT1024_WITH_RC4_56_MD5  = 0x0060
    TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA  = 0x0014
    TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA  = 0x0011
    TLS_RSA_EXPORT_WITH_DES40_CBC_SHA  = 0x0008
    TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5  = 0x0006
    TLS_RSA_EXPORT_WITH_RC4_40_MD5  = 0x0003

    TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA = 0x0038    
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x0039
    
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xc00a
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA = 0xc00f    
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA  = 0xc014
    TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA = 0xc021
    TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA = 0xc022
    


    TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA = 0x0087
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA = 0x0088


    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA =0xc005

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
    TLS_COMPRESS_DEFLATE = 0x01
    
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
        print "len extensions",len(self.fields['extensions']),"<---"
        return len(self.fields['extensions'])

class TLSExtension(Layer):
    TYPE_SERVER_NAME = 0x0000
    TYPE_SESSION_TICKET_TLS =0x0023
    TYPE_HEARTBEAT = 0x000f
    TYPE_STATUS_REQUEST = 0x0005
    TYPE_RENEGOTIATION_INFO = 0xff01
    TYPE_SIGNATURE_ALGORITHMS = 0x000d
    
    def _definition(self):
        # fields and their wire-definition
        # in order!
        self.add_field(name='type', struct='!H', default=self.next_magic)
        self.add_field(name='length', struct='!H', default=self.next_size)        # next layer length
    
class TLSSessionTicket(Layer):
    
    MAGIC = TLSExtension.TYPE_SESSION_TICKET_TLS
    def _definition(self):
        #type + length from TLSExtension
        self.add_field(name='data', default='')          
       
class TLSServerNameList(Layer):
    '''
    chain with ( TLSExtension/TLSServerNameList )
    
          struct {
              NameType name_type;
              select (name_type) {
                  case host_name: HostName;
              } name;
          } ServerName;
    
          enum {
              host_name(0), (255)
          } NameType;
    
          opaque HostName<1..2^16-1>;
    
          struct {
              ServerName server_name_list<1..2^16-1>
          } ServerNameList;
    '''
    MAGIC = TLSExtension.TYPE_SERVER_NAME    # previous.next.magic()
    
    def _definition(self):
        # fields and their wire-definition
        # in order!
        self.add_field(name='length', struct='!H', default=self.get_name_list_len)
        self.add_field(name='name_list', default=self.get_name_list)
        
    def get_name_list(self):
        return TLSServerName(type=TLSServerName.TYPE_HOST, data="a.yimg.com")  
        
    def get_name_list_len(self):
        return len(self.fields['name_list'])
        return self.get_name_list().size()

    
class TLSServerName(Layer):
    '''
    part of TLSServerNameList
    '''
    TYPE_HOST = 0x00
    
    def _definition(self):
        # fields and their wire-definition
        # in order!
        self.add_field(name='type', struct='!B', default=self.TYPE_HOST)
        self.add_field(name='length', struct='!H', default=self.get_name_len)
        self.add_field(name='data', default='')
        
    def get_name_len(self):
        return len(self.fields['data'])
 

class TLSHeartBeat(Layer): 
    MAGIC = TLSRecord.CONTENT_TYPE_HEARTBEAT
      
    class Handshake(Layer):
        
        MAGIC = TLSExtension.TYPE_HEARTBEAT
        def _definition(self):
            self.add_field(name='mode', struct="!B", default=0x01)       
         
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


class TLSAlert(Layer):  
    LEVEL_WARNING = 0x01
    LEVEL_FATAL = 0x02
    LEVEL_UNKNOWN_255 = 0xff
    
    DESCRIPTION_CLOSE_NOTIFY = 0
    DESCRIPTION_UNEXPECTE_MESSAGE = 10
    DESCRIPTION_BAD_RECORD_MAC = 20
    DESCRIPTION_DESCRIPTION_FAILED_RESERVED = 21
    DESCRIPTION_RECORD_OVERFLOW = 22
    DESCRIPTION_DECOMPRESSION_FAILUR = 30
    DESCRIPTION_HANDSHAKE_FAILUR = 40
    DESCRIPTION_NO_CERTIFICATE_RESERVED = 41
    DESCRIPTION_BAD_CERTIFICATE = 43
    DESCRIPTION_UNSUPPORTED_CERTIFICATE = 43
    DESCRIPTION_CERTIFICATE_REVOKED = 44
    DESCRIPTION_CERTIFICATE_EXPIRED = 45
    DESCRIPTION_CERTIFICATE_UNKNOWN = 46
    DESCRIPTION_ILLEGAL_PARAMETER = 47
    DESCRIPTION_UNKNOWN_CA = 48
    DESCRIPTION_ACCESS_DENIED = 49
    DESCRIPTION_DECODE_ERROR = 50
    DESCRIPTION_DECRYPT_ERROR = 51
    DESCRIPTION_EXPORT_RESTRICTION_RESERVED = 60
    DESCRIPTION_PROTOCOL_VERSION = 70
    DESCRIPTION_INSUFFICIENT_SECURITY = 71
    DESCRIPTION_INTERNAL_ERROR = 80
    DESCRIPTION_USER_CANCELED = 90
    DESCRIPTION_NO_RENEGOTIATION = 100
    DESCRIPTION_UNSUPPORTED_EXTENSION = 110
    DESCRIPTION_UNKNOWN_255 = 255
    
    
    MAGIC = TLSRecord.CONTENT_TYPE_ALERT
    
    def _definition(self):
        # fields and their wire-definition
        # in order!
        self.add_field(name='level', struct='!B', default=self.length)
        self.add_field(name='description', struct='!B', default=self.DESCRIPTION_CLOSE_NOTIFY)
    
    
if __name__=="__main__":
    #hexdump_squashed(TLSExtension()/TLSServerNameList())
    print "------tin"
    
    hexdump_squashed(TLSHandshake(data=TLSClientHello()))
    exit()

    ext = TLSExtensionList(extensions=TLSExtension()/TLSServerNameList())
    p = TLSRecord()/TLSHandshake(extensions=ext)
    print "--"
    hexdump_squashed(p)
    exit()
