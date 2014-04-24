'''
@author: tintinweb

'''
import socket, time, select
from  layer import *


import thread


class BaseSocket(object):
    def __init__(self, ip, port, timeout=2, buffer=2048, mode='client'):
        self.ip = ip
        self.port = port
        self.timeout = timeout
        self.buffer=buffer
        self.sock = None
        
        self.next = None
        self.prev = None
        
        self.mode = mode
        
        if mode.lower()=='server':
            self._func = self._listen
            self._listen()
        else:
            self._func = self._connect
        
        
    def __div__(self, other):
        self.next = other
        return self.serialize()
    
    def send(self, *args, **kwargs):
        self.sock.send(*args,**kwargs)
        
    def recv(self, *args, **kwargs):
        '''
        if self.mode=='server':
            if not len(self._stack):
                return None
            return self._stack.pop()
        '''
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
            self._func()
        return self._sendrcv(self.next.serialize())

class TCP(BaseSocket):
    def _connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.ip,self.port))
        
    def _listen(self):
        self._stack = []
        self.srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv_sock.bind((self.ip,self.port))
        self.srv_sock.listen(5)
        print "server listening..."
        print 'waiting for connection...'
        self.sock, addr = self.srv_sock.accept()
        print 'client: ', addr
        thread.start_new_thread(self.client_handler, (self.sock, addr))

    def client_handler(self, clientsock, addr):
        while 1:
            pass
            #self.client_recv(clientsock, addr)
            
    def client_recv(self, clientsock, addr):
        data=''
        while 1:
            data += clientsock.recv(1)
            print 'data:' + repr(data)
            if not len(data):
                break
        self._stack.append(data)
        
            
            
    def shutdown(self):
        self.sock.close()
        self.srv_sock.close()
            
        
class UDP(BaseSocket):
    def _connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.ip,self.port))

    def _listen(self):
        pass
        
        
class Raw(Layer):
    def _definition(self):
        self.add_field(name="data", default='')