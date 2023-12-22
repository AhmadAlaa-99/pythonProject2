import socket
import threading
import json
import mysql.connector
import bcrypt
from cryptography.fernet import Fernet

# Server class to handle multiple client connections and requests
class Server:
    def __init__(self, host, port, db_host, db_user, db_password, db_name):
        # إعداد الاتصال بالخادم الخاص بالسوكت
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((host, port))
        self.server_socket.listen(5)
        print(f"Server listening on {host}:{port}")

        # إعداد الاتصال بقاعدة البيانات MySQL
        self.db = mysql.connector.connect(
            host=db_host,       # عنوان المضيف لقاعدة البيانات
            user=db_user,       # اسم المستخدم لقاعدة البيانات
            password=db_password, # كلمة المرور لقاعدة البيانات
            database=db_name    # اسم قاعدة البيانات
        )
        self.cursor = self.db.cursor()

    def start(self):
        try:
            while True:
                client_socket, address = self.server_socket.accept()
                print(f"Connection from {address} has been established.")
                threading.Thread(target=self.handle_client, args=(client_socket,)).start()
        except Exception as e:
            print("Server error:", e)
        finally:
            self.server_socket.close()

    def handle_client(self, client_socket):
        try:
            while True:
                request = client_socket.recv(1024).decode()
                if not request:
                    break
                response = self.process_request(request)
                client_socket.send(response.encode())
        except Exception as e:
            print("Client handling error:", e)
        finally:
            client_socket.close()

    encryption_key = Fernet.generate_key()
    cipher_suite = Fernet(encryption_key)
    def decrypt_data(data):
        return cipher_suite.decrypt(data.encode()).decode()
    def update_client_info(self, username, info):
        encrypted_info = decrypt_data(json.dumps(info))
        try:
            self.cursor.execute("UPDATE InformationClient SET info = %s WHERE username = %s",
                                (encrypted_info, username))
            self.db.commit()
            return json.dumps({"status": "success", "message": "Information updated successfully"})
        except mysql.connector.Error as err:
            return json.dumps({"status": "error", "message": str(err)})
    def process_request(self, request):
        request_data = json.loads(request)
        if request_data["type"] == "register":
            return self.register_user(request_data["username"], request_data["password"])
        elif request_data["type"] == "login":
            return self.login_user(request_data["username"], request_data["password"])
        elif request_data["type"] == "update_info":
            return self.update_client_info(request_data["username"], request_data["info"])
        else:
            return json.dumps({"status": "error", "message": "Invalid request type"})

    def register_user(self, username, password):
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        try:
            self.cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
            self.db.commit()
            return json.dumps({"status": "success", "message": "User registered successfully"})
        except mysql.connector.Error as err:
            return json.dumps({"status": "error", "message": str(err)})

    def login_user(self, username, password):
        self.cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
       # self.cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
        user = self.cursor.fetchone()
        if user and bcrypt.checkpw(password.encode(), user[0].encode()):

            return json.dumps({"status": "success", "message": "Login successful"})
        else:
            return json.dumps({"status": "error", "message": "Invalid username or password"})
# Start the server
server = Server("127.0.0.1", 5555)
server.start()