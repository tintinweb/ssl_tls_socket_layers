
import socket, time, select
from  layer import *

class BaseSocket(object):
    def __init__(self, ip, port, timeout=2, buffer=2048):
        self.ip = ip
        self.port = port
        self.timeout = timeout
        self.buffer=buffer
        self.sock = None
        
        self.next = None
        self.prev = None
        
    def __div__(self, other):
        self.next = other
        return self.serialize()
    
    def send(self, *args, **kwargs):
        self.sock.send(*args,**kwargs)
        
    def recv(self, *args, **kwargs):
        return self.sock.recv(*args, **kwargs)
        
    def recvall(self, buffer=None, timeout=None):
        buffer = buffer or self.buffer
        timeout = self.timeout if timeout==None else timeout
        endtime = time.time() + timeout
        rdata = ''
        remain = buffer
        while remain > 0:
            rtime = endtime - time.time()
            if rtime < 0:
                print "timeout"
                return rdata if len(rdata) else None
            r, w, e = select.select([self.sock], [], [], timeout)
            if self.sock in r:
                data = self.recv(remain)
                # EOF?
                if not data:
                    print "EOF?"
                    return None
                rdata += data
                remain -= len(data)
        return rdata
    
    def _sendrcv(self, data, buffer=None):
        self.send(data)
        return self.recvall(buffer=buffer)
    
    def serialize(self):
        if not self.sock:
            self._connect()
        return self._sendrcv(self.next.serialize())

class TCP(BaseSocket):
    def _connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.ip,self.port))
        
        
class UDP(BaseSocket):
    def _connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.ip,self.port))
        
        
        
class Raw(Layer):
    def _definition(self):
        self.add_field(name="data", default='')