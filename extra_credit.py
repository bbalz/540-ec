import random
import binascii
import json

class Message:
    def __init__(self, data):
        self.data = data
        self.headers = {}

    def to_dict(self):
        return {
            'data': self.data.decode('utf-8') if isinstance(self.data, bytes) else self.data,
            'headers': self.headers
        }

    @classmethod
    def from_dict(cls, dict_data):
        msg = cls(dict_data['data'].encode('utf-8') if isinstance(dict_data['data'], str) else dict_data['data'])
        msg.headers = dict_data['headers']
        return msg

def application_layer(msg, is_sending):
    if is_sending:
        print("Application Layer: Preparing message for transmission")
        return Message(msg)
    else:
        print("Application Layer: Delivering message to application")
        return msg.data

def presentation_layer(msg, is_sending):
    if is_sending:
        print("Presentation Layer: Encoding and encrypting data")
        msg.data = msg.data.encode('utf-8')  # Simple encoding
    else:
        print("Presentation Layer: Decoding and decrypting data")
        msg.data = msg.data.decode('utf-8')  # Simple decoding
    return msg

def session_layer(msg, is_sending):
    if is_sending:
        print("Session Layer: Establishing session")
        msg.headers['session_id'] = random.randint(1000, 9999)
    else:
        print("Session Layer: Verifying session")
        if 'session_id' not in msg.headers:
            raise ValueError("No session ID found")
    return msg

def transport_layer(msg, is_sending):
    if is_sending:
        print("Transport Layer: Segmenting data and adding sequence numbers")
        segments = [msg.data[i:i+4] for i in range(0, len(msg.data), 4)]
        msg.headers['segments'] = [seg.decode('utf-8') for seg in segments]
        msg.headers['seq_nums'] = list(range(len(segments)))
    else:
        print("Transport Layer: Reassembling segments")
        if 'segments' not in msg.headers or 'seq_nums' not in msg.headers:
            raise ValueError("Segment information missing")
        segments = [seg.encode('utf-8') for seg in msg.headers['segments']]
        seq_nums = msg.headers['seq_nums']
        msg.data = b''.join([seg for _, seg in sorted(zip(seq_nums, segments))])
    return msg

def network_layer(msg, is_sending):
    if is_sending:
        print("Network Layer: Adding source and destination IP")
        msg.headers['src_ip'] = '192.168.1.1'
        msg.headers['dest_ip'] = '10.0.0.1'
    else:
        print("Network Layer: Verifying IP addresses")
        if 'src_ip' not in msg.headers or 'dest_ip' not in msg.headers:
            raise ValueError("IP address information missing")
    return msg

def data_link_layer(msg, is_sending):
    def calculate_parity(data):
        return bin(binascii.crc32(data) & 0xffffffff)[2:].zfill(32)
    
    if is_sending:
        print("Data Link Layer: Framing data and adding error checking")
        msg.headers['parity'] = calculate_parity(msg.data)
    else:
        print("Data Link Layer: Checking for errors")
        if 'parity' not in msg.headers:
            raise ValueError("Parity information missing")
        if msg.headers['parity'] != calculate_parity(msg.data):
            raise ValueError("Data corruption detected")
    return msg

def physical_layer(msg, is_sending):
    if is_sending:
        print("Physical Layer: Converting to binary for transmission")
        msg_dict = msg.to_dict()
        json_data = json.dumps(msg_dict)
        binary = ''.join(format(ord(char), '08b') for char in json_data)
        return binary
    else:
        print("Physical Layer: Receiving binary data")
        # Convert binary string to JSON string
        json_data = ''.join(chr(int(msg[i:i+8], 2)) for i in range(0, len(msg), 8))
        # Parse JSON string to dictionary
        msg_dict = json.loads(json_data)
        # Create Message object from dictionary
        return Message.from_dict(msg_dict)

def send_message(message):
    print("\nSending message:", message)
    msg = application_layer(message, True)
    msg = presentation_layer(msg, True)
    msg = session_layer(msg, True)
    msg = transport_layer(msg, True)
    msg = network_layer(msg, True)
    msg = data_link_layer(msg, True)
    binary = physical_layer(msg, True)
    print("\nTransmitted data:", binary[:64] + "..." if len(binary) > 64 else binary)
    return binary

def receive_message(binary, original_msg):
    print("\nReceiving message...")
    msg = physical_layer(binary, False)
    msg = data_link_layer(msg, False)
    msg = network_layer(msg, False)
    msg = transport_layer(msg, False)
    msg = session_layer(msg, False)
    msg = presentation_layer(msg, False)
    received_msg = application_layer(msg, False)
    print("\nReceived message:", received_msg)
    print("Original message:", original_msg)
    print("Transmission successful:", received_msg == original_msg)

#siumlate of send/receive message
original_message = "Hello World!"
binary_data = send_message(original_message)
receive_message(binary_data, original_message)
