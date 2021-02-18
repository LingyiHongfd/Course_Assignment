from socket import *
import rsa
from Crypto.Cipher import AES
import hmac
import base64

BUFFER_SIZE=4096
TLS_STRING='[TLS] '

def log_read():
    fo = open(r".\log\server_tls.log", "rb")
    i=0
    addr=""
    port=0
    for line in fo.readlines():
        u=str(line.decode()).split()[0].split(":")[1]
        if i==0:
            addr=u
        else:
            port=int(u)
        i=i+1
    fo.close()
    return addr,port


def server_socket_create():
    host_addr,host_port=log_read()

    server_socket=socket(AF_INET, SOCK_STREAM)
    server_socket.bind((host_addr,host_port))
    server_socket.listen(10)
    return server_socket

def create_keys():
    (public_key,private_key)=rsa.newkeys(1024)

    pub = public_key.save_pkcs1().decode()
    pubfile = open('../client/public_key.pem', 'w+')
    pubfile.write(pub)
    pubfile.close()

    pri = private_key.save_pkcs1().decode()
    prifile = open('private_key.pem', 'w+')
    prifile.write(pri)
    prifile.close()

def read_private_key():
    with open('private_key.pem') as private_key_file:
        p = private_key_file.read().encode()
    private_key = rsa.PrivateKey.load_pkcs1(p)
    return private_key


def listen(server_socket):
    private_key=read_private_key()
    while True:
        print (TLS_STRING+'listening')
        client_link,client_addr=server_socket.accept()
        print (TLS_STRING+'Have listened a TLS client hello')
        print ('addr',client_addr)
        print (TLS_STRING+'The client address is: '+client_addr[0],',port is: '+str(client_addr[1]))
        while True:
            data=client_link.recv(BUFFER_SIZE)
            data=data.decode()
            if data=='Hello':
                session_key,digestmod,block_cipher=tls_connection_create(data,client_link,private_key,)
            else:
                decrypt_receive(data,session_key,client_link,digestmod,block_cipher)


def tls_connection_create(data,client_link,private_key,):
    print(TLS_STRING+'Receive: '+data)
    client_link.send('Hello'.encode())
    data = client_link.recv(BUFFER_SIZE)
    data = rsa.decrypt(data, private_key)
    session_key = data.decode()
    data = data.decode()
    print(TLS_STRING+'Session Key: '+data)
    data = client_link.recv(BUFFER_SIZE)
    data=data.decode()
    data=str.split(data,',')
    digestmod,block_cipher=data[0],data[1]
    data = 'Hello Done'
    print(TLS_STRING+'TLS connection has been created')
    data = data.encode()
    client_link.send(data)
    return session_key,digestmod,block_cipher

def decrypt_receive(data,session_key,client_link,digestmod,block_cipher):
    block_cipher=switch_block_cipher(block_cipher)
    aes = AES.new(str.encode(session_key), block_cipher)  
    decrypted_text = str(aes.decrypt(base64.decodebytes(bytes(data,encoding='utf8'))).rstrip(b'\0').decode("utf8")) 
    str_len=len(decrypted_text)
    encrypted_str,mac_str=decrypted_text[0:str_len-32],decrypted_text[str_len-32:str_len]
    hash_function = hmac.new(session_key.encode(), encrypted_str.encode(), digestmod=digestmod)
    if hash_function.hexdigest() == mac_str:
        print(TLS_STRING+'Receive: '+encrypted_str)
        #client_link.send(data.encode())
    else:
        print (TLS_STRING+'Have received a message but verification failed')
    


def switch_block_cipher(block_cipher):
    if block_cipher=='OFB':
        return AES.MODE_OFB
    if block_cipher=='CFB':
        return AES.MODE_CFB
    if block_cipher=='ECB':
        return AES.MODE_ECB
    if block_cipher=='CBC':
        return AES.MODE_CBC