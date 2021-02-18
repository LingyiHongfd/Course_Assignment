from socket import *
import rsa
import hmac
import argparse

from server_utils import *



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--new_key', type=bool, default=False,
                        help='create and store a new pair of key')
    args = parser.parse_args()
    if args.new_key:
        create_keys()

    server_socket=server_socket_create()
    listen(server_socket)
    server_socket.close()





if __name__=='__main__':
    main()














