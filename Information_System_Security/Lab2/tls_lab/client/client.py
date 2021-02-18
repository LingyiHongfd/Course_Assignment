import socket
from client_utils import *
import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--digestmod', type=str, default='MD5',
                        help='set the digestmod,default is MD5，and u can alse use SHA1')
    parser.add_argument('--block_cipher',type=str,default='ECB',
                        help='set the block digestmod default is ECB,and u can alse ues OFB,CFB,CBC')
    parser.add_argument('--key_length',type=int,default=16,
                        help='set the key length, the key length supported by aes is 16 or 24 or 32')
    args = parser.parse_args()

    show_algorithms(args)
    client_socket=client_socket_create()
    session_key=tls_connection_create(client_socket,args)
    block_cipher=switch_block_cipher(args)
    send_encrypted_data(client_socket,session_key,args,block_cipher)
    client_socket.close()


if __name__=='__main__':
    main()



