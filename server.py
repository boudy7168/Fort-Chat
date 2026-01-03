"""Socket-based message relay server for encrypted chat."""

import socket
import threading
import json
import base64

HOST = '127.0.0.1'
PORT = 5555

clients = {}  # {username: {'socket': socket, 'public_key': pem_bytes}}
clients_lock = threading.Lock()


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


def broadcast_user_list():
    """Broadcast updated user list to all clients."""
    with clients_lock:
        user_list = list(clients.keys())
        for username, client_data in clients.items():
            try:
                send_json(client_data['socket'], {
                    'type': 'user_list',
                    'users': user_list
                })
            except Exception:
                pass


def handle_client(client_socket: socket.socket, address):
    """Handle individual client connection."""
    username = None
    try:
        # Registration
        msg = recv_json(client_socket)
        if not msg or msg.get('type') != 'register':
            client_socket.close()
            return
        
        username = msg['username']
        public_key = decode_bytes(msg['public_key'])
        
        with clients_lock:
            if username in clients:
                send_json(client_socket, {'type': 'error', 'message': 'Username taken'})
                client_socket.close()
                return
            
            clients[username] = {'socket': client_socket, 'public_key': public_key}
        
        send_json(client_socket, {'type': 'registered', 'message': f'Welcome {username}!'})
        print(f"[+] {username} connected from {address}")
        broadcast_user_list()
        
        # Message loop
        while True:
            msg = recv_json(client_socket)
            if not msg:
                break
            
            if msg['type'] == 'get_public_key':
                target = msg['username']
                with clients_lock:
                    if target in clients:
                        send_json(client_socket, {
                            'type': 'public_key',
                            'username': target,
                            'public_key': encode_bytes(clients[target]['public_key'])
                        })
                    else:
                        send_json(client_socket, {
                            'type': 'error',
                            'message': f'User {target} not found'
                        })
            
            elif msg['type'] == 'message':
                recipient = msg['to']
                with clients_lock:
                    if recipient in clients:
                        send_json(clients[recipient]['socket'], {
                            'type': 'message',
                            'from': username,
                            'encrypted_key': msg['encrypted_key'],
                            'nonce': msg['nonce'],
                            'ciphertext': msg['ciphertext']
                        })
                        send_json(client_socket, {
                            'type': 'sent',
                            'message': f'Message sent to {recipient}'
                        })
                    else:
                        send_json(client_socket, {
                            'type': 'error',
                            'message': f'User {recipient} not online'
                        })
            
            elif msg['type'] == 'list_users':
                with clients_lock:
                    send_json(client_socket, {
                        'type': 'user_list',
                        'users': list(clients.keys())
                    })
    
    except Exception as e:
        print(f"[-] Error with {username or address}: {e}")
    
    finally:
        if username:
            with clients_lock:
                clients.pop(username, None)
            print(f"[-] {username} disconnected")
            broadcast_user_list()
        client_socket.close()


def main():
    """Start the chat server."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(10)
    
    print(f"[*] Server listening on {HOST}:{PORT}")
    print("[*] Press Ctrl+C to stop")
    
    try:
        while True:
            client_socket, address = server.accept()
            thread = threading.Thread(target=handle_client, args=(client_socket, address))
            thread.daemon = True
            thread.start()
    except KeyboardInterrupt:
        print("\n[*] Server shutting down...")
    finally:
        server.close()


if __name__ == '__main__':
    main()
