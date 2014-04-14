'''
@author: tintinweb

'''
from collections import OrderedDict
import struct

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
        
    def get(self):
        value = self.value or self.default
        print isinstance(value, Layer)
        if hasattr(value,"__call__"):   # is function?
            value = value()
        return value
    
    def serialize(self):
        value = self.get()

        print repr(self)
        
        if self.struct:
            return struct.pack(self.struct, value) 
        return value 
    
    def unserialize(self, data):
        size = struct.calcsize(self.struct)
        self.value = struct.unpack(self.struct,data[:size])[0]
        return size
        
    def __repr__(self):
        return "[F]   %-20s : %-5s %10s"%(self.name,self.struct, repr(self.get()))
    
    def __len__(self):
        return len(self.serialize())

class Layer(object):
    def __init__(self, **kwargs):
        self.next = None            # previous -- linked by / operator
        self.next_layer_len=0
        self.curr_layer_len=0
        self.prev = None            # next layer
        self.data_serialized = ''   # last serialized data
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
                
        if '__raw' in kwargs.keys():
            # load from __raw.. skip all other fields
            self.unserialize(kwargs['__raw'])

    def __div__(self, other):
        self.next = other
        other.prev = self
        #print "%s/%s"%(repr(self),repr(other))
        return other
        
    def next_len(self):
        return self.next_layer_len
    
    def curr_len(self):
        return self.curr_layer_len

    def serialize(self):
        print self.__class__.__name__
        self.data_serialized = "".join([field.serialize() for field in self.fields.values()]) 
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
    
    def __repr__(self):
        str = "[ %s ]\n  "%self.__class__.__name__
        str += "\n  ".join([repr(f) for f in self.fields.values()])
        return str
            
    
    def __len__(self):
        return len(self.serialize())
    
    def total_len(self):
        return len(self)+self.next_len()