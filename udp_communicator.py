# Author: Samuel Hetteš, ID: 110968
# Subject: Computer and Communication Networks
# Assignment: Communication using UDP Protocol
# IDE: PyCharm 2021.2.3
# Programming language: Python 3.8.10
# Date: 25.11.2021


# IMPORTS #
import socket  # server, client socket
import time  # connection maintenance packets sending timing
import struct  # packing/unpacking data
import os  # system calls for clearing console screen


# CONSTANTS #

MAX_FRAG_SIZE = 1500  # maximum fragment size


# CLASSES #

# Client
class Client:
    sock = None  # socket
    server_address = None  # (server ip, port)
    frag_size = None  # fragment size defined by user
    window_size = None  # window size defined by user

# Server
class Server:
    sock = None  # socket
    window_size = None  # window size defined by user
    client_address = None  # (client ip, port)


# FUNCTIONS SHARED BETWEEN MODULES #

# Cyclic redundancy check 16-bit
# Source: https://gist.github.com/oysstu/68072c44c02879a2abf94ef350d1c7c6#gistcomment-3943460
def crc16(data):
    table = [
        0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7, 0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD,
        0xE1CE, 0xF1EF, 0x1231, 0x0210, 0x3273, 0x2252, 0x52B5, 0x4294, 0x72F7, 0x62D6, 0x9339, 0x8318, 0xB37B, 0xA35A,
        0xD3BD, 0xC39C, 0xF3FF, 0xE3DE, 0x2462, 0x3443, 0x0420, 0x1401, 0x64E6, 0x74C7, 0x44A4, 0x5485, 0xA56A, 0xB54B,
        0x8528, 0x9509, 0xE5EE, 0xF5CF, 0xC5AC, 0xD58D, 0x3653, 0x2672, 0x1611, 0x0630, 0x76D7, 0x66F6, 0x5695, 0x46B4,
        0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D, 0xC7BC, 0x48C4, 0x58E5, 0x6886, 0x78A7, 0x0840, 0x1861,
        0x2802, 0x3823, 0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948, 0x9969, 0xA90A, 0xB92B, 0x5AF5, 0x4AD4, 0x7AB7, 0x6A96,
        0x1A71, 0x0A50, 0x3A33, 0x2A12, 0xDBFD, 0xCBDC, 0xFBBF, 0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A, 0x6CA6, 0x7C87,
        0x4CE4, 0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41, 0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD, 0xAD2A, 0xBD0B, 0x8D68, 0x9D49,
        0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13, 0x2E32, 0x1E51, 0x0E70, 0xFF9F, 0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A,
        0x9F59, 0x8F78, 0x9188, 0x81A9, 0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E, 0xE16F, 0x1080, 0x00A1, 0x30C2, 0x20E3,
        0x5004, 0x4025, 0x7046, 0x6067, 0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E, 0x02B1, 0x1290,
        0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277, 0x7256, 0xB5EA, 0xA5CB, 0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D,
        0x34E2, 0x24C3, 0x14A0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405, 0xA7DB, 0xB7FA, 0x8799, 0x97B8, 0xE75F, 0xF77E,
        0xC71D, 0xD73C, 0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657, 0x7676, 0x4615, 0x5634, 0xD94C, 0xC96D, 0xF90E, 0xE92F,
        0x99C8, 0x89E9, 0xB98A, 0xA9AB, 0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882, 0x28A3, 0xCB7D, 0xDB5C,
        0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBB9A, 0x4A75, 0x5A54, 0x6A37, 0x7A16, 0x0AF1, 0x1AD0, 0x2AB3, 0x3A92,
        0xFD2E, 0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B, 0x9DE8, 0x8DC9, 0x7C26, 0x6C07, 0x5C64, 0x4C45, 0x3CA2, 0x2C83,
        0x1CE0, 0x0CC1, 0xEF1F, 0xFF3E, 0xCF5D, 0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9, 0x9FF8, 0x6E17, 0x7E36, 0x4E55, 0x5E74,
        0x2E93, 0x3EB2, 0x0ED1, 0x1EF0
    ]
    crc = 0xFFFF
    for byte in data:
        crc = (crc << 8) ^ table[(crc >> 8) ^ byte]
        crc &= 0xFFFF
    return crc

# Checking if specific flag is set
def get_answer_flag(flags): return (flags & 0b00000001) == 128
def get_start_flag(flags): return (flags & 0b01000000) == 64
def get_end_flag(flags): return (flags & 0b00100000) == 32
def get_control_flag(flags): return (flags & 0b00010000) == 16
def get_message_flag(flags): return (flags & 0b00001000) == 8
def get_file_flag(flags): return (flags & 0b00000100) == 4
def get_wrong_flag(flags): return (flags & 0b00000010) == 2
def get_ack_flag(flags): return (flags & 0b00000001) == 1


# CLIENT MODULE FUNCTIONS #

# Fragments data based on fragment size
def fragment_data(data, frag_size):
    return [data[i - frag_size:i] for i in range(frag_size, len(data) + frag_size, frag_size)]

# Creates a data packet
def create_data_packet(data, flags, seq_num, crc):
    return struct.pack(f'!BI2H{len(data)}s', flags, seq_num, len(data), crc, data)

# Sends data
def send_data(data, data_type, file_name, client):
    if len(data) == 0:  # empty message/file will not be sent
        print('> Cannot send empty message/file')
        return 1

    data_size = len(data)  # total data size
    data = fragment_data(data, client.frag_size)  # fragment data
    frag_count = len(data)  # number of fragments

    if data_type == 'message':  # create initialization packet for message transfer
        flags = 0b00001000
        init_packet = struct.pack('!BIH', flags | 0b01000000, frag_count, client.frag_size)
    else:  # create initialization packet for file transfer
        flags = 0b00000100
        init_packet = struct.pack(f'!BIH{len(file_name)}s', flags | 0b01000000, frag_count, client.frag_size, file_name)

    packets, ready_seq = [None] * frag_count, [None] * frag_count  # all data packets, sequence numbers of packets ready to be sent
    print('> Creating data packets')
    for i in range(frag_count):  # fill up the arrays
        packets[i] = create_data_packet(data[i], flags, i, crc16(data[i]))  # create data packet
        ready_seq[i] = frag_count - i - 1

    print('------------------------------------------')
    print(f'> Number of fragments: {frag_count}')
    print(f'> Max size of a fragment: {client.frag_size}')
    print(f'> Total data size: {data_size} bytes')
    print('------------------------------------------')
    while True:  # sequence number of corrupted packet
        try:
            corrupted_seq_num = int(input(f'[?] Sequence number of corrupted packet (unknown for no simulation): '))
            if 0 <= corrupted_seq_num < frag_count:
                break
            else:
                corrupted_seq_num = -1
                break
        except ValueError:
            print('[!] Input')

    print('------------------------------------------')
    print('> Sending transfer initialization packet')
    client.sock.sendto(init_packet, client.server_address)  # send initialization packet
    client.sock.settimeout(20)  # server needs to specify storage directory

    while True:
        try:  # receiving response from server
            response = client.sock.recvfrom(MAX_FRAG_SIZE)[0]
            try:  # unpacking packet as informative packet
                response = struct.unpack('!B', response)[0]
                if response == (flags | 0b01000001): # acknowledged
                    print('> Server is ready to transfer data')
                    print('------------------------------------------')
                    break
                elif response == 0b00110000:  # server terminated the whole connection
                    print('------------------------------------------')
                    print(f'> Server terminated the connection')
                    return 0
                else:  # unknown
                    continue
            except struct.error:  # unknown
                continue
        except socket.timeout:  # server not responding
            client.sock.sendto(struct.pack('!B', flags | 0b00100010), client.server_address)  # send transfer termination packet
            print('> Server not responding')
            print('> Transfer terminated')
            return 1

    stack, chunk_counter, default_timeout = [], 0, client.window_size * 0.1
    while True:
        while ready_seq:  # fill up the stack with packets ready to be sent
            if len(stack) < client.window_size:
                if ready_seq[-1] == corrupted_seq_num:  # append corrupted packet if there is one to be sent
                    ready_seq.pop()
                    corrupted_seq_num = -1
                    data = struct.unpack(f'!{len(packets[corrupted_seq_num])}s', packets[corrupted_seq_num])[0].decode('ISO-8859-1')
                    if data[9] != 'X':
                        corrupted = data[:9] + 'X' + data[10:]
                    else:
                        corrupted = data[:9] + 'Y' + data[10:]
                    corrupted = corrupted.encode('ISO-8859-1')
                    stack.append(corrupted)
                else:  # else append normal packet
                    stack.append(packets[ready_seq.pop()])
            else:
                break
        stack.reverse()
        while stack:  # send packets while stack is not empty
            client.sock.sendto(stack.pop(), client.server_address)

        no_answer_count = 0
        client.sock.settimeout(default_timeout)
        while True:  # cycle to collect responses from server
            try:  # receiving response
                response = client.sock.recvfrom(MAX_FRAG_SIZE)[0]

                try:
                    if len(response) == 1:
                        response = struct.unpack('!B', response)
                    elif len(response) == 5:  # try unpacking packet as chunk ACK
                        response = struct.unpack('!BI', response)
                    else:  # try unpacking packet as chunk NACK
                        response = struct.unpack(f'!BI2H{len(response)-9}s', response)

                    if response[0] == (flags | 0b00000001):  # acknowledged
                        if response[1] == chunk_counter:
                            print(f'> Chunk #{response[1]} ACK')
                            chunk_counter += 1
                        break
                    elif response[0] == (flags | 0b00000010):  # not acknowledged
                        if response[1] != chunk_counter:  # duplicate
                            break
                        if crc16(response[4]) == response[3]:
                            print(f'[!] Chunk #{response[1]} NACK, resending: {response[2]}')
                            indexes = struct.unpack(f'!{int(len(response[4])/4)}I', response[4])
                            for i in reversed(indexes):
                                ready_seq.append(i)
                            chunk_counter += 1
                            break
                        else:
                            print('[!] Chunk response CRC error')
                            print('> Asking server for response')
                            client.sock.sendto(struct.pack('!B', flags | 0b10000000), client.server_address)
                            continue
                    elif response[0] == (flags | 0b00100010):  # transfer termination from server
                        print('------------------------------------------')
                        print('> Transfer terminated by Server')
                        return 1
                    elif response[0] == (flags | 0b00100000):  # transfer completion from server
                        print('------------------------------------------')
                        print('> Transfer completed')
                        print('> All packets transferred')
                        return 1
                except socket.error:  # not a data packet
                    continue

            except socket.timeout:
                no_answer_count += 1
                if no_answer_count == 3:  # terminate transfer if server did not respond 3 times
                    client.sock.sendto(struct.pack('!B', flags | 0b00100010), client.server_address)  # send transfer termination packet
                    print('> Server not responding')
                    print('> Transfer terminated')
                    return 1
                else:
                    print('> Asking server for response')
                    client.sock.settimeout(default_timeout + no_answer_count)
                    client.sock.sendto(struct.pack('!B', flags | 0b10000000), client.server_address)  # send him packet what to do next

# Controls connection - starts, maintains, ends
def control_connection(client, start, end):
    client.sock.settimeout(5)
    while True:
        if start == 1:  # start of connection flags
            flags = 0b01010000
            print("> Sending connection initialization packet")
        elif end == 1:  # end of connection flags
            flags = 0b00110000
            print('------------------------------------------')
            print("> Sending connection termination packet")
        else:  # maintaining connection flags
            flags = 0b00010000

        try:
            if start:  # for start send window size as well
                client.sock.sendto(struct.pack('!BH', flags, client.window_size), client.server_address)
            else:
                client.sock.sendto(struct.pack('!B', flags), client.server_address)
            if end:  # if end set, return
                print('> Terminating connection')
                return
        except OSError:  # network unreachable, return 0
            print('> Network unreachable')
            return 0

        try:  # for connection maintenance and start collect response
            response = client.sock.recvfrom(MAX_FRAG_SIZE)[0]
            try:  # unpacking response as a informative packet
                if start:  # for start unpack it with window size
                    response = struct.unpack('!BH', response)
                else:
                    response = struct.unpack('!B', response)
                if response[0] == (flags | 0b00000001):  # acknowledged
                    if start:  # start of communication acknowledged, return 1
                        return 1
                    else:  # maintenance packet acknowledged, sleep for 10 seconds
                        time.sleep(10)
                elif response[0] == (flags | 0b00000010) and start:  # start of communication NACK, window size was too big
                        print(f'> Server changed the window size to {response[1]}')
                        client.window_size = response[1]  # set the new window size
                        return 1
                elif response[0] == 0b00110000:  # server terminated the whole connection, return -1
                    print('------------------------------------------')
                    print(f'> Server terminated the connection')
                    return -1
                else:  # unknown response
                    continue
            except struct.error:  # unknown response
                continue
        except socket.timeout:  # server not responding
            print('> Server not responding')
            if start: return 0  # no response for start of communication, return 0
            print('------------------------------------------')
            print('0 - Back to main menu\n1 - Ping again')
            while True:  # ping again/close client input
                try:
                    ping = int(input('[?] Option: '))
                    if ping in {0, 1}:
                        print('------------------------------------------')
                        break
                    else:
                        print('[!] Option Є (0, 1)')
                except ValueError:
                    print('[!] Input')
            if ping != 1:  # close client if user wants to, else ping again
                print('> Closing Client')
                client.sock.close()
                return 0

# Starts client module
def start_client():
    client = Client()  # create class
    client.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # create client socket

    print('------------------------------------------')
    print('               CLIENT SETUP               ')
    print('------------------------------------------')
    while True:  # fragment size input
        try:
            frag_size = int(input('[?] Fragment size (1-1463): '))
            if 0 < frag_size <= 1463:
                break
            else:
                print('[!] Fragment size')
        except ValueError:
            print('[!] Input')
    client.frag_size = frag_size

    while True:  # window size input
        try:
            window_size = int(input('[?] Window size (2-65535): '))
            if window_size < 2 or window_size > 65535:
                print('[!] Window size')
                continue
            else:
                client.window_size = window_size
                break
        except ValueError:
            print('[!] Input')
            continue

    while True:  # server ip and port input
        server_ip = input('[?] Server IP: ')
        while True:
            try:
                port = int(input('[?] Port: '))
                break
            except ValueError:
                print('[!] Input')

        print('------------------------------------------')
        print('> Establishing connection')
        client.server_address = (server_ip, port)
        status = control_connection(client, 1, 0)  # send connection initialization packet and save return value

        if status == 1:  # connection established
            print(f'> Connection with Server established\nIP: {client.server_address[0]}\nPort: {client.server_address[1]}')
            break
        else:  # connection not established
            print('------------------------------------------')
            print('0 - Back to menu\n1 - Change Server address')
            while True:  # close client/change server address input
                try:
                    change_address = int(input('[?] Option: '))
                    if change_address in {0, 1}:
                        print('------------------------------------------')
                        break
                    else:
                        print('[!] Option Є (0, 1)')
                except ValueError:
                    print('[!] Input')
            if change_address == 0:  # close client if user wants to, else change address
                print('> Closing Client')
                client.sock.close()
                return

    while True:  # cycle for maintaining connection
        print('------------------------------------------')
        print('[!] Press CTRL+C to show Client menu [!]')
        print('------------------------------------------')
        print('> Maintaining connection')

        try:  # start maintaining connection
            status = control_connection(client, 0, 0)  # should not end if connection is alive
            if status == 0:  # server stopped responding
                control_connection(client, 0, 1)  # send connection termination packet
            client.sock.close()  # close socket and return
            return
        except KeyboardInterrupt:  # connection maintenance interrupted, show client menu
            print('\n> Ending connection maintenance')

        print('------------------------------------------')
        print('               CLIENT MENU                ')
        print('------------------------------------------')
        print('0 - Back to menu')
        print('1 - Send message')
        print('2 - Send file')
        print('3 - Keep alive')
        print('4 - Clear screen')

        while True:  # option input
            try:
                client_option = int(input('[?] Option: '))
                if client_option in {0, 1, 2, 3, 4}:
                    break
                else:
                    print('[!] Option Є (0, 1, 2, 3, 4)')
            except ValueError:
                print('[!] Input')

        if client_option == 0:  # end connection
            control_connection(client, 0, 1)  # send connection termination packet
            client.sock.close()  # close socket and return
            print('------------------------------------------')
            print(f'> Connection with Server terminated')
            return
        elif client_option == 1:  # message transfer
            print('------------------------------------------')
            message = input('[?] Message: ').encode('ISO-8859-1')  # get input message and encode it
            status = send_data(message, 'message', None, client)  # send message
            if status == 0:  # server terminated the whole connection during transfer
                client.sock.close()  # close socket and return
                return
        elif client_option == 2:  # file transfer
            print('------------------------------------------')
            while True:  # file path input
                file_path = input('[?] File path: ')
                if os.path.isfile(file_path):  # file path exists
                    file_name = os.path.basename(file_path)
                    print(f'> File name: {file_name}')
                    print(f'> Absolute path: {os.path.abspath(file_path)}')
                    print('------------------------------------------')
                    file = open(file_path, 'rb')  # open file in read binary mode
                    file_data = file.read()  # read file
                    status = send_data(file_data, 'file', file_name.encode(), client)  # send file
                    file.close()  # close file
                    if status == 0:  # server terminated the whole connection during transfer
                        client.sock.close()  # close socket and return
                        return
                    break
                else:  # file path does not exist
                    print('[!] File path not existing')
        elif client_option == 3:  # continue maintaining connection
            pass
        else:  # clear screen
            os.system('cls||clear')  # system call for clearing screen for both linux and windows
            pass


# SERVER MODULE FUNCTIONS #

# Processes transfer - collects packets from client during transfer and sends responses
def process_transfer(server, data_type, frag_count, file_name, storage_dir):
    total_nack, chunk_ack, chunk_nack, last_chunk_size = 0, 0, 0, frag_count % server.window_size
    if last_chunk_size == 0:  # sequence number of last chunk
        last_chunk_seq = int(frag_count / server.window_size) - 1
    else:
        last_chunk_seq = int(frag_count / server.window_size)
    data_size, call_event, chunk_counter = 0, 0, 0 # call event = auxiliary bool
    ready_seq, data_stream = [None] * frag_count, [None] * frag_count  # sequence numbers of packets ready to be received, received data

    for i in range(frag_count):  # create a list of packets that are ready to be received
        ready_seq[i] = i

    if data_type == 'message':  # message transfer flags
        flags = 0b00001000
    else:  # file transfer flags
        flags = 0b00000100

    server.sock.settimeout(5)  # during transfer timeout is low
    while ready_seq:  # collect packets while all packets are not received
        if (chunk_ack + chunk_nack) == server.window_size or call_event or (chunk_ack + chunk_nack == last_chunk_size and chunk_counter == last_chunk_seq):  # if all packets in a chunk were received send chunk ACK or server is calling
            call_event = 0
            if chunk_ack != server.window_size:  # packets in a chunk were corrupted
                nack_seq = b''
                for i in range(len(ready_seq)):  # create list of sequence numbers that should have been transferred in a chunk
                    if i < (server.window_size - chunk_ack):
                        nack_seq += ready_seq[i].to_bytes(4, byteorder = 'big')
                        total_nack += 1
                        print(f'> Packet #{ready_seq[i]} NACK')
                    else:
                        break
                chunk_nack = int(len(nack_seq) / 4)
                if chunk_nack * 4 > 1463:
                    server.sock.sendto(struct.pack('!B', flags | 0b00100010), server.client_address)  # send transfer termination packet
                    print('------------------------------------------')
                    print(f'> Chunk #{chunk_counter} total ACK: {chunk_ack}')
                    print(f'> Chunk #{chunk_counter} total NACK: {chunk_nack}')
                    print('------------------------------------------')
                    print('> Window size is too big, server cannot handle all the packets')
                    print('> Transfer terminated')
                    return 1
                response = struct.pack(f'!BI2H{chunk_nack*4}s', flags | 0b00000010, chunk_counter, chunk_nack, crc16(nack_seq), nack_seq)  # chunk NACK with sequence numbers
            else:  # all packets in a chunk acknowledged
                response = struct.pack('!BI', flags | 0b00000001, chunk_counter)
            print('------------------------------------------')
            print(f'> Chunk #{chunk_counter} total ACK: {chunk_ack}')
            print(f'> Chunk #{chunk_counter} total NACK: {chunk_nack}')
            print('------------------------------------------')
            chunk_counter += 1
            chunk_ack, chunk_nack = 0, 0
            server.sock.sendto(response, server.client_address)  # send response

        try:  # receiving a packet
            data, server.client_address = server.sock.recvfrom(MAX_FRAG_SIZE)

            try:  # unpack packet as informative packet
                data = struct.unpack('!B', data)[0]
                if data == (flags | 0b00100010):  # transfer terminated by client
                    print('> Transfer terminated by Client')
                    return
                elif data == (flags | 0b10000000):  # client is asking for response
                    call_event = 1
                    continue
                else:  # unknown
                    continue
            except struct.error:
                pass

            try:  # unpacking packet as data packet
                data = struct.unpack(f'!BI2H{len(data)-9}s', data)
                if data[3] == crc16(data[4]):  # if crc is same, packet is correct
                    chunk_ack += 1
                    if data_stream[data[1]] is None:  # if packet was not already acknowledged
                        ready_seq.remove(data[1])
                        data_size += len(data[4])
                        data_stream[data[1]] = data[4]  # add packet to data stream
                        print(f'> Packet #{data[1]} ACK, Data size: {data[2]}')
                else:
                    chunk_nack += 1
                continue
            except struct.error:  # unknown
                continue

        except socket.timeout:  # client not responding
            server.sock.sendto(struct.pack('!B', flags | 0b00100010), server.client_address)  # send transfer termination packet
            print('------------------------------------------')
            print('> Client not responding')
            print('> Transfer terminated')
            return

    print('------------------------------------------')
    print(f'> Chunk #{chunk_counter} total ACK: {chunk_ack}')
    print(f'> Chunk #{chunk_counter} total NACK: {chunk_nack}')
    print('------------------------------------------')
    server.sock.sendto(struct.pack('!BI', flags | 0b00000001, chunk_counter), server.client_address)
    server.sock.sendto(struct.pack('!B', flags | 0b00100000), server.client_address)  # everything good, send transfer completion packet
    print('> Transfer completed')
    print('> All packets transferred')
    print(f'> Total ACK: {frag_count}')
    print(f'> Total NACK: {total_nack}')
    print(f'> Total data size: {data_size} bytes')
    print('------------------------------------------')
    if data_type == 'message':  # decode message and print it
        print('> Message: ', end='')
        for data in data_stream:
            print(data.decode('ISO-8859-1'), end='')
        print()
    else:  # open file and write binary data
        file = open(f'{os.path.abspath(storage_dir)}/{file_name}', 'wb')
        for data in data_stream:
            file.write(data)
        file.close()
        print(f'> File name: {file_name}')
        print(f'> Absolute path: {os.path.abspath(file_name)}')
    return

# Starts server module
def start_server():
    server = Server()  # create server class
    server.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # create server socket

    print('------------------------------------------')
    print('               SERVER SETUP               ')
    print('------------------------------------------')

    while True:  # port input
        try:
            port = int(input('[?] Port (0-65535): '))
            if port < 0 or port > 65535:
                print('[!] Port')
                continue
        except ValueError:
            print('[!] Input')
            continue
        try:  # binding socket
            server.sock.bind(('', port))
            break
        except socket.error:  # port not available
            print('[!] Port unavailable')

    while True:  # window size input
        try:
            window_size = int(input('[?] Window size (2-65535): '))
            if window_size < 2 or window_size > 65535:
                print('[!] Window size')
                continue
            else:
                server.window_size = window_size
                break
        except ValueError:
            print('[!] Input')
            continue

    while True:  # server auto-timeout input
        try:
            server_timeout = int(input('[?] Server auto-timeout in seconds: '))
            if server_timeout < 1:
                print('[!] Timeout > 0')
            else:  # set timeout
                print('> Server initialized')
                print('------------------------------------------')
                print('[!] Press CTRL+C to show server menu [!]')
                print('------------------------------------------')
                print('> Waiting for Client')
                break
        except ValueError:
            print('[!] Input')

    while True:  # cycle where server collects start, maintenance, end communication packets and start of transfer packets
        server.sock.settimeout(server_timeout)
        try:  # receiving a packet
            data, client_address = server.sock.recvfrom(MAX_FRAG_SIZE)

            try:  # unpacking packet as informative packet
                data = struct.unpack('!B', data)[0]
                if get_control_flag(data):  # communication control packet
                    if get_end_flag(data):  # end of communication
                        print('------------------------------------------')
                        print('> Connection with Client terminated')
                        print('------------------------------------------')
                        print('> Waiting for Client')
                        server.client_address = None
                    else:  # server pinged
                        response = struct.pack('!B', data | 0b00000001)  # send acknowledgement
                        server.sock.sendto(response, server.client_address)
                continue
            except struct.error:
                pass

            try:  # unpacking packet as a start of communication packet
                data = struct.unpack('!BH', data)
                if server.client_address is not None:  # if client is connected, ignore packet
                    continue
                if get_control_flag(data[0]) and get_start_flag(data[0]):  # start of communication
                    server.client_address = client_address
                    if data[1] <= server.window_size:  # window size of client is smaller than window size of server
                        server.window_size = data[1]
                        response = struct.pack('!BH', data[0] | 0b00000001, data[1])  # send ACK
                    else:  # window size of client is bigger than window size of server
                        response = struct.pack('!BH', data[0] | 0b00000010, server.window_size)  # send NACK with servers window size
                    server.sock.sendto(response, server.client_address)
                    print(f'> Connection with Client established\nIP: {server.client_address[0]}\nPort: {server.client_address[1]}')
                    print('------------------------------------------')
                    print('> Waiting for data')
                continue
            except struct.error:
                pass

            try:  # unpacking packet as a start of transfer packet
                data = struct.unpack(f'!BIH{len(data) - 7}s', data)
                if get_start_flag(data[0]):  # start flag set
                    frag_count, file_name, storage_dir = data[1], None, None
                    print('------------------------------------------')
                    if get_message_flag(data[0]):  # message transfer
                        data_type = 'message'
                        print('> Message transfer incoming')
                    elif get_file_flag(data[0]):  # file transfer
                        data_type = 'file'
                        file_name = data[3].decode('ISO-8859-1')  # get file name
                        print('> File transfer incoming')
                        print(f'> File name: {file_name}')
                        while True:  # storage directory input
                            storage_dir = input('[?] Storage directory path: ')
                            if os.path.isdir(storage_dir):  # check if exists
                                break
                            else:
                                print('[!] Directory not existing')
                    else:  # unknown
                        continue
                    response = struct.pack('!B', data[0] | 0b00000001)
                    server.sock.sendto(response, server.client_address)  # send acknowledgement
                    print(f'> Number of fragments: {data[1]}')
                    print(f'> Max size of a fragment: {data[2]}')
                    print('------------------------------------------')
                    process_transfer(server, data_type, frag_count, file_name, storage_dir)  # start collecting data
                    print('------------------------------------------')
                    print('> Waiting for data')
                continue
            except struct.error:  # unknown
                pass

        except KeyboardInterrupt:  # packet receiving interrupted, show server menu
            print('\n------------------------------------------')
            print('               SERVER MENU                ')
            print('------------------------------------------')
            print('0 - Shut down server')
            print('1 - Clear screen')
            print('2 - Continue waiting for data')
            while True:  # option input
                try:
                    choice = int(input('[?] Option: '))
                    if choice == 0:  # shut down server
                        if server.client_address is not None:  # if server is connected to client, send connection termination packet
                            print('------------------------------------------')
                            print('> Sending connection termination packet')
                            server.sock.sendto(struct.pack('B', 0b00110000), server.client_address)
                            print(f'> Connection with Client terminated')
                        server.sock.close()  # close server socket and return
                        print('> Shutting down the server')
                        return
                    elif choice == 1:  # clear screen
                        os.system('cls||clear')  # system call for clearing screen for both linux and windows
                        print('------------------------------------------')
                        print('[!] Press CTRL+C to show Server menu [!]')
                        print('------------------------------------------')
                        print('> Waiting for data')
                        break
                    elif choice == 2:  # continue waiting for data
                        print('------------------------------------------')
                        print('[!] Press CTRL+C to show Server menu [!]')
                        print('------------------------------------------')
                        print('> Waiting for data')
                        break
                    else:
                        print('[!] Option Є (0, 1, 2)')
                except ValueError:
                    print('[!] Input')

        except socket.timeout:  # client not responding
            if server.client_address is not None:  # if server is connected to client, send connection termination packet
                print('> Sending connection termination packet')
                server.sock.sendto(struct.pack('!B', 0b00110000), server.client_address)
                print(f'> Connection with Client terminated')
            print('------------------------------------------')
            print('> Server timed out')
            server.sock.close()  # close server socket and return
            return


# MAIN MENU #

while True:
    print('------------------------------------------')
    print('                   MENU                   ')
    print('------------------------------------------')
    print('0 - End program')
    print('1 - Server')
    print('2 - Client')

    while True:  # option input
        try:
            option = int(input('[?] Option: '))
            if option in {0, 1, 2}:
                break
            else:
                print('[!] Option Є (0, 1, 2)')
        except ValueError:
            print('[!] Input')

    if option == 0:  # end program
        break
    elif option == 1:  # start server module
        start_server()
    else:  # start client module
        start_client()
