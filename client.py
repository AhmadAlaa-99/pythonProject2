import socket
import json
import bcrypt
from cryptography.fernet import Fernet
# Client class to connect to the server and send requests
class Client:

    encryption_key = Fernet.generate_key()
    cipher_suite = Fernet(encryption_key)
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((host, port))
        self.is_logged_in = False

    def hash_password(self, password):
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    def send_request(self, request_type, username, password):
        hashed_password = self.hash_password(password)
        request_data = json.dumps({
            "type": request_type,
            "username": username,
            "password": hashed_password.decode()
        })
        self.client_socket.send(request_data.encode())
        response = self.client_socket.recv(1024).decode()
        return response

    @staticmethod
    def encrypt_data(data):
        return Client.cipher_suite.encrypt(data.encode()).decode()

    
    def send_update_info_request(self, username, info):
        encrypted_info = encrypt_data(json.dumps(info))
        request_data = json.dumps({
            "type": "update_info",
            "username": username,
            "info": encrypted_info
        })
        self.client_socket.send(request_data.encode())
        response = self.client_socket.recv(1024).decode()
        return response

    def close(self):
        self.client_socket.close()

# Example usage of the client
client = Client("127.0.0.1", 5555)

# Example of sending a register request
register_response = client.send_request("register", "user1", "password123")
print("Register response:", register_response)

# Example of sending a login request
login_response = client.send_request("login", "user1", "password123")
print("Login response:", login_response)

client.close()