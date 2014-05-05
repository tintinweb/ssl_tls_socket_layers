'''
Created on May 2, 2014

@author: martin
'''
import random
import sys, string
from layer import CompoundLayer
from layer.ssl.tls import TLSClientHello, TLSHandshake, TLSRecord
import struct

class UnsupportedFormatException(Exception):pass
class DataGen:
    @staticmethod
    def generate_for_struct(format):
        '''
        x    pad byte    no value          
        c    char    string of length 1    1     
        b    signed char    integer    1    (3)
        B    unsigned char    integer    1    (3)
        ?    _Bool    bool    1    (1)
        h    short    integer    2    (3)
        H    unsigned short    integer    2    (3)
        i    int    integer    4    (3)
        I    unsigned int    integer    4    (3)
        l    long    integer    4    (3)
        L    unsigned long    integer    4    (3)
        q    long long    integer    8    (2), (3)
        Q    unsigned long long    integer    8    (2), (3)
        f    float    float    4    (4)
        d    double    float    8    (4)
        s    char[]    string          
        p    char[]    string          
        P    void *    integer         (5), (3)
        '''
        data = []
        for fd in format:
            try:
                # it is actually a value we can work with
                data.append(DataGen._generate_data_for_type(fd))
            except UnsupportedFormatException, uf:
                # skip x,!@<>
                pass
        return data
    
    @staticmethod
    def _generate_data_for_type(datatype):
        if datatype in ('f','d'):           # !f is not working..
            return  random.uniform(sys.float_info.min,sys.float_info.max) 
        elif datatype in ('b','?'):
            val =  random.randint(-128,127)
            return val
        elif datatype in ('c','B'):
            val = random.randint(0,255)
            if datatype=='c':
                val = chr(val)
            return val
        elif datatype in ('h','i','l','q'):
            if datatype=='h':
                vmin = -65535/2
                vmax = 65535/2
            else:
                vmin =-(sys.maxsize+1)
                vmax = sys.maxsize               
            return random.randint(vmin,vmax) # long min/max .. rough
        elif datatype in ('H','I','L','Q','P'):
            if datatype=='H':
                vmax = 65535
            else:
                vmax = 2*sys.maxsize-1
            return random.randint(0,vmax) # long min/max .. rough
        elif datatype in ('s','p'):
            size=random.randint(1,random.randint(1,300))            # max size= 1 <= x <= 300
            charset = string.printable
            return ''.join(random.choice(charset) for _ in range(size))
        raise UnsupportedFormatException

class Fuzzer(object):
    '''
    we set fuzz default values for fields in order
    '''
    def __init__(self, seed=None):
        self.seed(seed)

    def seed(self, seed=None):
        if not seed:
            seed = random.random()
        self.seed = seed
     
    def fuzz(self, layer, mode='incremental'):
        if isinstance(layer,CompoundLayer):
            for l in p.next():
                print repr(l)
                for f in l.fields.iteritems():
                    print f
                    # fuzz yield copy opject here
                    #order: last: type, length
        else:
            print "fuzz this layer"

    def _fuzz_random(self, layer):
        '''
        fuzz based on mutation probabilities
        '''
        pass

    def _fuzz_incremental(self, layer):
        '''
        fuzz one field at a time.
        '''
        for field in layer.fields.values():
            pass
        pass
    
    def mutate_layer(self,start):
        '''
        generate all possible *valid* combinations for a layer
        '''
        #TODO: only return deep copy of initial layer
        if isinstance(start,CompoundLayer):
            start=start.list
        else:
            start=[start]
            
        for s in start:
            fields = s.fields.items()
            # move "length","type" to end of list
            sfields =[]
            for fname,field in fields:
                if fname in ('type','length'):
                    sfields.append((fname,field))
                else:
                    sfields.insert(0,(fname,field))
            import types
            # build new layer
            for fname,field in sfields:
                if field.allowed:
                    # got description
                    # wow this is so dirty..
                    
                    #new_value = random.choice(field.allowed)
                    for new_value in field.allowed:
                        if type(new_value) in (types.ClassType,types.TypeType):
                            field.value=new_value()
                        else:
                            field.value=new_value
                        # iterate all allowed fields:
                        print "!!fuzz: %s"%fname
                        yield start
                else:
                    # can be string or int
                    # if struct is defined use datagen based on struct, else generate random string
                    if field.struct:
                        new_value = DataGen.generate_for_struct(field.struct)[0]
                    else:
                        # generate string with random width
                        ff = "%ds"%random.randint(1,50)
                        new_value = struct.pack(ff,*DataGen.generate_for_struct(ff))
                    field.value = new_value
                print "!!fuzz: %s"%fname
                yield start
        


if __name__=="__main__":
    ff = "!dBBBbbHH"
    data =  DataGen.generate_for_struct(ff)
    print data
    import struct
    print repr(struct.pack(ff,*data))
    ################
    # fuzzer
    
    p = TLSRecord(version=TLSRecord.PROTOCOL_TLS_1_0)/TLSHandshake(data=TLSClientHello(version=TLSRecord.PROTOCOL_TLS_1_1))
    p = TLSRecord()+TLSHandshake()
    #p = TLSRecord()
    print "--"

    print "--"
    print repr(p)
    f = Fuzzer()
    f.fuzz(p)
    
    for l in f.mutate_layer(TLSRecord()):
        print repr(l)