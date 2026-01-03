"""CLI chat client with end-to-end encryption."""

import socket
import threading
import json
import base64
import sys
from crypto_utils import (
    generate_rsa_keypair, serialize_public_key, deserialize_public_key,
    encrypt_message, decrypt_message
)

HOST = '127.0.0.1'
PORT = 5555


def encode_bytes(data: bytes) -> str:
    """Encode bytes to base64 string for JSON transport."""
    return base64.b64encode(data).decode('ascii')


def decode_bytes(data: str) -> bytes:
    """Decode base64 string to bytes."""
    return base64.b64decode(data.encode('ascii'))


def send_json(sock: socket.socket, data: dict):
    """Send JSON data with length prefix."""
    json_data = json.dumps(data).encode('utf-8')
    length = len(json_data)
    sock.sendall(length.to_bytes(4, 'big') + json_data)


def recv_json(sock: socket.socket) -> dict:
    """Receive JSON data with length prefix."""
    length_data = sock.recv(4)
    if not length_data:
        return None
    length = int.from_bytes(length_data, 'big')
    data = b''
    while len(data) < length:
        chunk = sock.recv(min(4096, length - len(data)))
        if not chunk:
            return None
        data += chunk
    return json.loads(data.decode('utf-8'))


class ChatClient:
    def __init__(self, username: str):
        self.username = username
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.private_key, self.public_key = generate_rsa_keypair()
        self.public_key_cache = {}  # {username: public_key_object}
        self.running = True
        self.online_users = []
    
    def connect(self):
        """Connect to server and register."""
        try:
            self.socket.connect((HOST, PORT))
            send_json(self.socket, {
                'type': 'register',
                'username': self.username,
                'public_key': encode_bytes(serialize_public_key(self.public_key))
            })
            
            response = recv_json(self.socket)
            if response['type'] == 'error':
                print(f"Error: {response['message']}")
                return False
            
            print(f"Connected! {response['message']}")
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            return False
    
    def get_public_key(self, target_username: str):
        """Get public key for a user (cached or from server)."""
        if target_username in self.public_key_cache:
            return self.public_key_cache[target_username]
        
        send_json(self.socket, {
            'type': 'get_public_key',
            'username': target_username
        })
        return None  # Will be received asynchronously
    
    def send_message(self, recipient: str, message: str):
        """Encrypt and send a message to a user."""
        if recipient not in self.public_key_cache:
            print(f"Fetching public key for {recipient}...")
            self.get_public_key(recipient)
            return False
        
        try:
            encrypted = encrypt_message(message, self.public_key_cache[recipient])
            send_json(self.socket, {
                'type': 'message',
                'to': recipient,
                'encrypted_key': encode_bytes(encrypted['encrypted_key']),
                'nonce': encode_bytes(encrypted['nonce']),
                'ciphertext': encode_bytes(encrypted['ciphertext'])
            })
            return True
        except Exception as e:
            print(f"Encryption error: {e}")
            return False
    
    def receive_loop(self):
        """Background thread to receive messages."""
        while self.running:
            try:
                msg = recv_json(self.socket)
                if not msg:
                    print("\nDisconnected from server")
                    self.running = False
                    break
                
                if msg['type'] == 'message':
                    try:
                        encrypted_data = {
                            'encrypted_key': decode_bytes(msg['encrypted_key']),
                            'nonce': decode_bytes(msg['nonce']),
                            'ciphertext': decode_bytes(msg['ciphertext'])
                        }
                        plaintext = decrypt_message(encrypted_data, self.private_key)
                        print(f"\n[{msg['from']}]: {plaintext}")
                        print("> ", end='', flush=True)
                    except Exception as e:
                        print(f"\nFailed to decrypt message from {msg['from']}: {e}")
                
                elif msg['type'] == 'public_key':
                    key = deserialize_public_key(decode_bytes(msg['public_key']))
                    self.public_key_cache[msg['username']] = key
                    print(f"\nReceived public key for {msg['username']}")
                    print("> ", end='', flush=True)
                
                elif msg['type'] == 'user_list':
                    self.online_users = msg['users']
                
                elif msg['type'] == 'sent':
                    pass  # Message sent confirmation
                
                elif msg['type'] == 'error':
                    print(f"\nServer: {msg['message']}")
                    print("> ", end='', flush=True)
            
            except Exception as e:
                if self.running:
                    print(f"\nReceive error: {e}")
                    self.running = False
                break
    
    def print_help(self):
        """Print available commands."""
        print("\nCommands:")
        print("  /msg <user> <message>  - Send encrypted message")
        print("  /users                 - List online users")
        print("  /key <user>            - Fetch user's public key")
        print("  /help                  - Show this help")
        print("  /quit                  - Exit chat\n")
    
    def run(self):
        """Main client loop."""
        if not self.connect():
            return
        
        receiver = threading.Thread(target=self.receive_loop)
        receiver.daemon = True
        receiver.start()
        
        self.print_help()
        
        while self.running:
            try:
                user_input = input("> ").strip()
                if not user_input:
                    continue
                
                if user_input.startswith('/msg '):
                    parts = user_input[5:].split(' ', 1)
                    if len(parts) < 2:
                        print("Usage: /msg <user> <message>")
                        continue
                    recipient, message = parts
                    if recipient == self.username:
                        print("Cannot send message to yourself")
                        continue
                    self.send_message(recipient, message)
                
                elif user_input == '/users':
                    send_json(self.socket, {'type': 'list_users'})
                    import time
                    time.sleep(0.2)
                    print(f"Online users: {', '.join(self.online_users)}")
                
                elif user_input.startswith('/key '):
                    target = user_input[5:].strip()
                    self.get_public_key(target)
                
                elif user_input == '/help':
                    self.print_help()
                
                elif user_input == '/quit':
                    print("Goodbye!")
                    self.running = False
                    break
                
                else:
                    print("Unknown command. Type /help for available commands.")
            
            except KeyboardInterrupt:
                print("\nGoodbye!")
                self.running = False
                break
            except EOFError:
                self.running = False
                break
        
        self.socket.close()


def main():
    """Entry point for the chat client."""
    print("=" * 50)
    print("  FortChat - End-to-End Encrypted Messaging")
    print("=" * 50)
    
    if len(sys.argv) > 1:
        username = sys.argv[1]
    else:
        username = input("Enter your username: ").strip()
    
    if not username:
        print("Username cannot be empty")
        return
    
    print(f"Generating RSA-2048 keypair...")
    client = ChatClient(username)
    client.run()


if __name__ == '__main__':
    main()
