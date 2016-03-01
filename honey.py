#!/usr/bin/python

import socket
import paramiko
import sys
import signal
from datetime import datetime
import json

IP=""
PORT=22
TIMEOUT=15

try:
    if sys.argv[1]:
        IP=str(sys.argv[1])
except:
    pass

try:
    if sys.argv[2]:
        PORT=int(sys.argv[2])
except:
    pass

def signal_handler(signal, frame):
    print('You pressed Ctrl+C!')
    try:
        t.close()
        client.close()
    except:
        pass
    try:
        sock.close()
    except:
        pass
    
    sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

host_key = paramiko.RSAKey(filename='/root/.ssh/id_rsa')

class Server (paramiko.ServerInterface):
    def _init_(self):
        self.event = threading.Event()
        self.addr = None
        self.port = None
        self.count = 1
    def setAddr(self,addr):
        print("set addr !")
        self.addr=str(addr[0])
        self.port=int(addr[1])
    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    def check_auth_password(self, username, password):
        print("Auth !")
        data = {}
        data['username'] = username
        data['password'] = password
        if self.addr.startswith('::ffff:'):
            data['src_ip'] = str(self.addr).replace('::ffff:','')
        else:
            data['src_ip'] = self.addr
        data['src_port'] = self.port
        data['timestamp'] = datetime.isoformat(datetime.utcnow())
        #data['try'] = int(self.count)
        #       self.count += 1
        #        try:
        #            rversion = self.transport.remote_version.split('-', 2)[2]
        #            data['software_version'] = rversion
        #        except:
        #            data['software_version'] = self.transport.remote_version
        #            pass
        #       data['cipher'] = self.transport.remote_cipher
        #       data['mac'] = self.transport.remote_mac
        fl=open("./logfile","a")
        fl.write(json.dumps(data) + '\n')
        fl.close()
        print("Try : "+username+"/"+password)
        if (username == 'root') and (password == 'toor'):
            return paramiko.AUTH_FAILED
            #return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return False
    def check_channel_shell_request(self, channel):
        self.event.set()
        return False
def runServer(IP,PORT):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((IP, PORT))
        print("[*] Running on "+str(IP)+":"+str(PORT))
        sock.listen(100)
        print('[+] Listening for connection ...')
    except Exception, e:
        print('[-] Listen/bind failed: ' + str(e))
        sock.close()
        sys.exit(1)
    return sock

def getAClient(sock): 
    try:
        client, addr = sock.accept()
        print("[+] Connection from "+str(addr)) 
    except Exception, e:
        print('[-] Accept failed: ' + str(e))
        sock.close()
        sys.exit(1)

    try:
        t = paramiko.Transport(client)
        t.local_version="SSH-2.0-OpenSSH_6.7p1 Debian-5+deb8u1"
        try:
            t.load_server_moduli()
        except:
            print('[-] (Failed to load moduli -- gex will be unsupported.)')
            raise
        t.add_server_key(host_key)
        server = Server()
        server.setAddr(addr)
        try:
            t.start_server(server=server)
        except paramiko.SSHException, x:
            print('[-] SSH negotiation failed.')

        chan = t.accept(TIMEOUT)
        if chan is None:
            print('*** No channel.')
            return False
        #print('[+] SSH client Connected !')

        #chan.send('Happy birthday !\r\n\r\n')
        chan.close()
        return True
    except socket.error as e:
        print('[-] Client connected but socket was closed')
        try:
            t.close()
            client.close()
        except:
            pass
#    except AttributeError as ex:
#        print("[ ] Time out")
#    except Exception, e:
#        print('[-] Caught exception: '+str(type(e))+ str(e))
#        try:
#            t.close()
#            client.close()
#            sock.close()
#        except:
#            pass

sock=runServer(IP,PORT)
while 1:
    getAClient(sock)

t.close()
client.close()
sock.close()
