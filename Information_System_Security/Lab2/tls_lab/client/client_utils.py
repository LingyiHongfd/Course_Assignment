from socket import *
import rsa
import hmac
import base64
from Crypto.Cipher import AES
from random import randint

BUFFER_SIZE=4096
TLS_STRING='[TLS] '


def padding(s):
    while len(s) % 16 != 0:
        s += '\0'
    return str.encode(s) 

def show_algorithms(args):
    print (TLS_STRING+'Using digestmod:   '+args.digestmod)
    print (TLS_STRING+'Using block cipher:'+args.block_cipher)
    print (TLS_STRING+'Using key length:  '+str(args.key_length))


def log_read():
    fo = open(r".\log\client_tls.log", "rb")
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


def client_socket_create():
    host_addr,host_port=log_read()

    client_socket=socket(AF_INET, SOCK_STREAM)
    client_socket.connect((host_addr,host_port))
    return client_socket

def read_public_key():
    with open('public_key.pem') as public_key_file:
        p = public_key_file.read().encode()
    public_key = rsa.PublicKey.load_pkcs1(p)
    return public_key

def session_key_create(args):
    session_key=''
    random_p=randint(0,pow(2,args.key_length))
    session_key_p  = str(random_p).zfill(args.key_length)
    session_key=session_key+session_key_p
    return session_key

def tls_connection_create(client_socket,args):
    client_socket.send("Hello".encode())
    data = client_socket.recv(BUFFER_SIZE)
    print(TLS_STRING+'Create TLS connection: '+data.decode())
    session_key=session_key_create(args)
    public_key=read_public_key()
    message = rsa.encrypt(session_key.encode(), public_key)
    client_socket.send(message)
    print(TLS_STRING+"Session key: " + session_key) 
    message=args.digestmod+','+args.block_cipher
    client_socket.send(message.encode())
    data = client_socket.recv(BUFFER_SIZE)
    print(TLS_STRING+'TLS connection has been created')
    return session_key

def send_encrypted_data(client_socket,session_key,args,block_cipher):
    while True:
        data = input(TLS_STRING+'>>> ')
        if not data:
            break
        data = data.encode()
        print(TLS_STRING+'Input data: '+data.decode())
        hash_function = hmac.new(session_key.encode(), data, digestmod=args.digestmod)
        message = data.decode() + hash_function.hexdigest()
        aes = AES.new(str.encode(session_key), block_cipher) 
        encrypted_text = str(base64.encodebytes(aes.encrypt(padding(message))), encoding='utf8').replace('\n', '') 
        client_socket.send(encrypted_text.encode())
        print(TLS_STRING+'Encrypted string: '+encrypted_text)
        #data = client_socket.recv(BUFFER_SIZE)
        #print(TLS_STRING+'Encrypted string: '+data.decode())


def switch_block_cipher(args):
    if args.block_cipher=='OFB':
        return AES.MODE_OFB
    if args.block_cipher=='CFB':
        return AES.MODE_CFB
    if args.block_cipher=='ECB':
        return AES.MODE_ECB
    if args.block_cipher=='CBC':
        return AES.MODE_CBC