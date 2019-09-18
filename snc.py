#!/usr/bin/env python3

import sys
import socket
import argparse
import select
import queue as Queue
import threading
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes


INT_STR_LEN = 16

def get_fixed_sized_string(msg_len):
    msg_len_str = str(msg_len)
    msg_len_str_len = len(msg_len_str)
    prepend = '0' * (INT_STR_LEN - msg_len_str_len)

    #print("send_len = ", prepend + msg_len_str)

    return prepend + msg_len_str

def get_encrypted_data(send_data):
    return send_data

def get_decrypted_data(recv_data):
    return recv_data

def invoke_server(key, server_port):
    #Receive connection from client (Single client support for now)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('', server_port))

    s.listen(5)

    c, addr = s.accept()

    read_list = [sys.stdin, c]
    write_list = []
    exception_list = []

    outgoing_client = Queue.Queue()
    outgoing_stdout = Queue.Queue()

    #generate AES256 key from key from user
    salt = c.recv(16)
    aes_key = PBKDF2(key, salt, 32, count=1000000, hmac_hash_module=SHA512)

    #print("AES key", aes_key, len(aes_key))

    client_done = False
    stdin_done = False
    already_closed = False

    while not (client_done and stdin_done):
        #print(client_done, stdin_done)
        readable, writeable, exceptions = select.select(read_list, write_list, exception_list)

        for sock in readable:
            #if server has data to send
            if sock == sys.stdin:
                #print("server stdin data")
                send_data = sock.readline()
                #print(len(send_data))
                if send_data:
                    final_send_data = get_fixed_sized_string(len(send_data)) + send_data
                    outgoing_client.put(final_send_data)
                    #print("data added to queue")
                    if c not in write_list:
                        write_list.append(c)
                else:
                    #print("Closing client")
                    #print("server stdin done")
                    read_list.remove(sys.stdin)
                    stdin_done = True

            #data from client
            else:
                #get msg length first
                msg_len = sock.recv(INT_STR_LEN)

                if msg_len:
                    msg_len = int(msg_len.decode())

                    #get actual msg
                    total_received = 0
                    to_receive = msg_len

                    recv_data = b''
                    while total_received < to_receive:
                        recv_data_part = sock.recv(to_receive-total_received)
                        recv_data += recv_data_part
                        total_received += len(recv_data_part)

                    recv_data = get_decrypted_data(recv_data)
                    outgoing_stdout.put(recv_data.decode())
                    if sys.stdout not in write_list:
                        write_list.append(sys.stdout)
                    #print("data added to queue")
                else:
                    read_list.remove(c)
                    #print("client done")
                    client_done = True
                    if not select.select([sys.stdin,],[],[],0.0)[0]:
                        stdin_done = True

        for sock in writeable:
            if sock == sys.stdout:
                while not outgoing_stdout.empty():
                    #print("writing data to stdout")
                    send_data = outgoing_stdout.get_nowait()
                    sock.write(send_data)
                    #print(send_data)
            else:
                while not outgoing_client.empty():
                    #print("sending data to client")
                    send_data = outgoing_client.get(False)
                    send_data = get_encrypted_data(send_data)
                    sock.sendall(send_data.encode())

            write_list.remove(sock)

        if stdin_done and not already_closed:
            c.shutdown(socket.SHUT_WR)
            already_closed = True

        for e in exceptions:
            c.close()
            s.close()

    #print("server closing sockets")
    c.close()
    s.close()

def invoke_client(key, server_ip, server_port):
    #connect to the server 
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server_ip, server_port))

    read_list = [sys.stdin, s]
    write_list = []
    exception_list = []

    outgoing_server = Queue.Queue()
    outgoing_stdout = Queue.Queue()

    #generate AES256 key from key from user
    salt = get_random_bytes(16)
    aes_key = PBKDF2(key, salt, 32, count=1000000, hmac_hash_module=SHA512)

    #print("AES key", aes_key, len(aes_key))
    s.sendall(salt)

    stdin_done = False
    server_done = False
    already_closed = False

    while not (stdin_done and server_done):
        #print(server_done, stdin_done)
        readable, writeable, exceptions = select.select(read_list, write_list, exception_list)

        for sock in readable:
            #if client has data to send
            if sock == sys.stdin:
                #print("client stdin data")
                send_data = sock.readline()
                #print(len(send_data))
                if send_data:
                    final_send_data = get_fixed_sized_string(len(send_data)) + send_data
                    outgoing_server.put(final_send_data)
                    if s not in write_list:
                        write_list.append(s)
                    #print("data added to queue")
                else:
                    #print("Client stdin done")
                    read_list.remove(sys.stdin)
                    stdin_done = True
                    #s.shutdown(socket.SHUT_WR)

            #data from server
            else:
                #print("data from server")

                #get msg len
                msg_len = sock.recv(INT_STR_LEN)
                if msg_len:
                    msg_len = int(msg_len.decode())

                    #get actual data
                    total_received = 0
                    to_receive = msg_len

                    recv_data = b''
                    while total_received < to_receive:
                        recv_data_part = sock.recv(to_receive-total_received)
                        recv_data += recv_data_part
                        total_received += len(recv_data_part)

                    recv_data = get_decrypted_data(recv_data)
                    outgoing_stdout.put(recv_data.decode())
                    if sys.stdout not in write_list:
                        write_list.append(sys.stdout)
                    #print("data added to queue")
                else:
                    #print("server_done")
                    read_list.remove(s)
                    server_done = True
                    if not select.select([sys.stdin,],[],[],0.0)[0]:
                        stdin_done = True

        for sock in writeable:
            if sock == sys.stdout:
                while not outgoing_stdout.empty():
                    #print("writing data to stdout")
                    send_data = outgoing_stdout.get(False)
                    sock.write(send_data)
            else:
                while not outgoing_server.empty():
                    #print("sending data to server")
                    send_data = outgoing_server.get(False)
                    send_data = get_encrypted_data(send_data)
                    sock.sendall(send_data.encode())
                
            write_list.remove(sock)

        if stdin_done and not already_closed:
            s.shutdown(socket.SHUT_WR)
            already_closed = True

        for e in exceptions:
            #print("exception ", e)
            s.close()

    #print("client closing socket")
    #s.shutdown(socket.SHUT_WR)
    s.close()

#main function
if __name__ == '__main__':
    #Parse CLI arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('--key', required=True, dest='key', type=str, help='Communication password (key)')
    parser.add_argument('-l', dest='is_listen', action='store_true', help='Is port listening? (for server)')
    parser.add_argument('server_ip', nargs='?', help='server IP', type=str)
    parser.add_argument('server_port', help='server port', type=int)
    args = parser.parse_args()

    key = args.key
    is_listen = args.is_listen
    server_ip = args.server_ip
    server_port = args.server_port
    
    #print(key, is_listen, server_ip, server_port)


    #Decision to invoke server of client on this machine
    if is_listen:
        #print("invoking server")
        invoke_server(key, server_port)
    else:
        #print("invoking client")
        invoke_client(key, server_ip, server_port)
