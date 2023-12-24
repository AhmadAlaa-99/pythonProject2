import socket
import json
import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
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
        self.private_key, self.public_key = self.generate_keys()

        def generate_keys(self):
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            public_key = private_key.public_key()
            return private_key, public_key

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
        encrypted_info = self.encrypt_data(json.dumps(info))
        request_data = json.dumps({
            "type": "update_info",
            "username": username,
            "info": encrypted_info
        })
        self.client_socket.send(request_data.encode())
        response = self.client_socket.recv(1024).decode()
        return response

    def send_public_key(self):
        public_key = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.client_socket.send(public_key)


    def receive_server_public_key(self):
        server_public_key = self.client_socket.recv(1024)
        return serialization.load_pem_public_key(
            server_public_key,
            backend=default_backend()
        )

    def encrypt_with_public_key(self, message, public_key):
        encrypted = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted

    def decrypt_with_private_key(self, encrypted_message):
        decrypted = self.private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted

#وظيفة في العميل للتحقق من التوقيع الذي يتلقاه من السيرفر. هذا يضمن أن البيانات لم يتم
    # تعديلها أثناء النقل وأنها صادرة فعلاً من السيرفر.
    def verify_signature(self, public_key, signature, data):
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False

        def handle_response(self, response):
            response_json = json.loads(response)
            data = response_json["data"]
            signature = bytes.fromhex(response_json["signature"])
            is_valid = self.verify_signature(server_public_key, signature, data.encode())
            if is_valid:
                print("Data is valid and verified.")
            else:
                print("Data verification failed.")

    def close(self):
        self.client_socket.close()



client = Client("127.0.0.1", 5555)
client.send_public_key()
server_public_key = client.receive_server_public_key()


register_response = client.send_request("register", "user1", "password123")
print("Register response:", register_response)


login_response = client.send_request("login", "user1", "password123")
print("Login response:", login_response)

client.close()