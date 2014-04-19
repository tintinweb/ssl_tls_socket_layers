'''
@author: tintinweb

'''
from collections import OrderedDict
import struct
import re

class Packer:
    REX_DEF_SLICE = re.compile("(?P<type>.*?)\{(?P<start>-?\d)(?P<end>\,-?\d?)?\}?")
    @staticmethod
    def pack(definition, value):
        '''
        definition: + based on struct help
                    + extended with slicing functionality
        
        extended example:   I{3}    ... 3 byte unsigned int
                            I{3,4}  ... 1 byte unsigned int value[3,4] once packed
        '''
        if "}" in definition:
            # extended syntax
            # TODO: right now we only support one struct definition 
            definition,start,end = Packer.REX_DEF_SLICE.match(definition).groups()
            start = int(start)
            if end:
                end = end.strip(",")
                if not len(end):
                    end = None
                else:
                    end = int(end)
            # pack
            data = struct.pack(definition,value)
            if "<" in definition:
                raise "cannot handle little-endianess atm!"
            if end:
                raise "We do not handle this case atm!"
                data = data[start:end]      #I{1,2} .. char 1-2
            else:
                data = data[len(data)-start:]         #I{1}   .. up to 1 char .. 0x00 00 00 aa
            # only first struct def handled
        else:
            data = struct.pack(definition,value)
            
        
        return data

class FieldDict(OrderedDict):
    'Store items in the order the keys were last added'
    def __setitem__(self, key, value):
        if key in self:
            del self[key]
        OrderedDict.__setitem__(self, key, value)

class Field(object):
    def __init__(self, name, struct=None, default=None, value=None, valid=None):
        self.name = name
        self.struct = struct
        self.default = default
        self.set(value)
        
    def set(self, value):
        self.value = value
        
    def get(self, value=None):
        #print "[F] ->"+self.name
        ret=''
        value = value if value!=None else (self.value or self.default)
        if isinstance(value, Layer) or isinstance(value,CompoundLayer):  # serialize this layer
            #print "[F] isinstance"
            ret = value.serialize()
        elif hasattr(value,"__call__"):   # is function?
            #print "[F] val"
            ret = self.get(value())
        elif isinstance(value, list):   # list? serialize and join
            #print "[F] list"
            for e in value:
                ret+=self.get(e)        # deref/serialize list items
        else:
            #print "[F] raw"
            ret = value
                
        return ret
    

    
    def serialize(self):
        value = self.get()

        print repr(self)
        
        if self.struct:
            return Packer.pack(self.struct, value)
            return struct.pack(self.struct, value) 
        return value 
    
    def unserialize(self, data):
        size = struct.calcsize(self.struct)
        self.value = struct.unpack(self.struct,data[:size])[0]
        return size
        
    def __repr__(self):
        return "[F]   %-20s : %-5s %-10s"%(self.name,self.struct,self.get())
    
    def __len__(self):
        return len(self.serialize())


class Layer(object):
    class NoneLayer(object):
        '''
        dummy termination layer
        '''
        def __init__(self):
            self.length=0
        def size(self):
            print "DUMMY"
            #raise
            return self.length
        def magic(self):
            print "DUMMY_TYPE"
            raise
            return 0xcc
        def next_size(self):
            raise
        def next_magic(self):
            raise
        
    def __init__(self, **kwargs):
        self.next = Layer.NoneLayer()           # previous -- linked by / operator
        self.next_layer_len=0
        self.length=0
        self.prev = None                        # next layer
        self.data_serialized = False            # dirty bit - data last serialized
        self.fields=OrderedDict()
        self._definition()
        # load params
        for k,v in kwargs.iteritems():
            # skip __ args (special functionality)
            if k.startswith("__"): continue
            try:
                self.fields[k].set(v)
            except KeyError, ke:
                print "invalid argument (%s): %s=%s  (%s)"%(self.__class__.__name__,k,v,repr(self.fields.keys()))
                raise
                
        if '__raw' in kwargs.keys():
            # load from __raw.. skip all other fields
            self.unserialize(kwargs['__raw'])

    def __div__(self, other):
        self.next = other
        other.prev = self
        print "%s/%s"%(repr(self),repr(other))
        print "--div--"
        print "self => ",repr(self)
        print "next => ",repr(self.next)
        return CompoundLayerDiv(self,other)

    def __add__(self, other):
        # list of elements that do not modify each other
        return CompoundLayerAdd(self,other)
        
    def next_len(self):
        return self.next_layer_len
    
    def curr_len(self):
        return self.length
    
    def size(self):
        return self.length
    
    def magic(self):
        return self.MAGIC
    
    def next_magic(self):
        print "next_size:",self.next.__class__.__name__,repr(self.next.magic)
        return self.next.magic()
    
    def next_size(self):
        print "next_size:",self.next.__class__.__name__,self.next.size()
        return self.next.size()

    def serialize(self):
        # todo add caching,call functions after all other fields were set or prioritize
        if False and self.data_serialized:
            return self.data_serialized
        #print "[L]"+self.__class__.__name__
        #self.data_serialized = "".join([field.serialize() for field in self.fields.values()]) 
        self.data_serialized = ''
        for field in self.fields.values():
            #print "[L]"+ field.name
            self.data_serialized += field.serialize()
        return self.data_serialized
    
    def unserialize(self, data):
        size = 0
        for name,field in self.fields.iteritems():
            print name,field,data
            size +=field.unserialize(data[size:])       # feed next chunk
        return size
    
    def add_field(self, **kwargs):
        self.fields[kwargs.get('name')]=Field(**kwargs)
        
    def __str__(self):
        return self.serialize()
    
    def __repsr__(self):
        str = "[ %s ]\n  "%self.__class__.__name__
        str += "\n  ".join([repr(f) for f in self.fields.values()])
        return str
            
    
    def __len__(self):
        return len(self.serialize())
    
    def total_len(self):
        return len(self)+self.next_len()

    
from utils import *    
class CompoundLayer(object):
    '''
    
    track and handle /concatenations and provide interface for easy serialization
    
    '''
    
    def __init__(self, first, second):
        self.list=[first, second]
        
    def __div__(self,other):
        self.list[-1].next = other
        other.prev = self.list[-1]
        self.list.append(other)
        
        return self
    
    def __add__(self, other):
        return self.__div__(other)
        
    def __str__(self):
        return self.serialize()
    
    def __repr__(self):
        return self.__class__.__name__+"|"+str(self.list)
        return self.__str__()

    def size(self):
        return len(self.serialize())
    
class CompoundLayerDiv(CompoundLayer):
    
    def serialize(self):
        print "COMPOUND_serializeDIV"
        ret = ''
        print repr(self.list)
        for layer in reversed(self.list):
            print layer.__class__.__name__
            data = layer.serialize()
            length=len(data)
            print "*  serializing %s size=%s"%(repr(layer.__class__.__name__),length)
            
            ret = data + ret
            hexdump_squashed(data)
            
            # update layer properties
            layer.length = length           # update current layers length
            
        hexdump_squashed(ret)
        return ret
    
class CompoundLayerAdd(CompoundLayer):
    
    def serialize(self):
        print "COMPOUND_serializeADD"
        ret = ''
        print repr(self.list)
        for layer in self.list:
            print ">>"+layer.__class__.__name__
            data = layer.serialize()
            length=len(data)
            print "*  serializing %s size=%s"%(repr(layer.__class__.__name__),length)
            
            ret +=  data
            
        hexdump_squashed(ret)
        return ret       
    
