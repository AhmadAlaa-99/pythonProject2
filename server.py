import socket
import threading
import json
import mysql.connector
import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from pymongo import MongoClient
class Server:
    def __init__(self, host, port):
        # إنشاء سوكت للخادم
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # ربط السوكت بعنوان IP ومنفذ
        self.server_socket.bind((host, port))
        # بدء الاستماع على السوكت بحد أقصى 5 اتصالات في الانتظار
        self.server_socket.listen(5)
        # توليد مفتاح خاص وعام للتشفير
        self.private_key, self.public_key = self.generate_keys()

        self.mongo_client = MongoClient('localhost', 27017)
        self.db = self.mongo_client['sys']  # اسم قاعدة البيانات
        self.clients_collection = self.db['clients']  # اسم المجموعة

    def generate_keys(self):
        # توليد مفتاح خاص باستخدام RSA
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        # توليد المفتاح العام من المفتاح الخاص
        public_key = private_key.public_key()
        return private_key, public_key

    def start(self):
        try:
            while True:
                # قبول الاتصالات الواردة
                client_socket, address = self.server_socket.accept()
                print(f"Connection from {address} has been established.")
                # بدء خيط جديد لكل اتصال عميل
                threading.Thread(target=self.handle_client, args=(client_socket,)).start()
        except Exception as e:
            print("Server error:", e)
        finally:
            # إغلاق السوكت عند انتهاء الخدمة
            self.server_socket.close()

    def receive_client_public_key(self, client_socket):
        # استقبال المفتاح العام للعميل
        client_public_key = client_socket.recv(1024)
        # تحميل المفتاح العام وتحويله من تنسيق PEM
        return serialization.load_pem_public_key(
            client_public_key,
            backend=default_backend()
        )

    def send_public_key(self, client_socket):
        # تحويل المفتاح العام للخادم إلى تنسيق PEM
        public_key = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        # إرسال المفتاح العام للعميل
        client_socket.send(public_key)

    def handle_client(self, client_socket):
        try:
            # استقبال المفتاح العام للعميل وإرسال المفتاح العام للخادم
            client_public_key = self.receive_client_public_key(client_socket)
            self.send_public_key(client_socket)
            while True:
                # استقبال الطلبات من العميل
                request = client_socket.recv(1024).decode()
                if not request:
                    break
                # معالجة الطلب وإرسال الرد
                response = self.process_request(request)
                client_socket.send(response.encode())
        except Exception as e:
            print("Client handling error:", e)
        finally:
            # إغلاق الاتصال مع العميل
            client_socket.close()



    # توليد مفتاح تشفير وإعداد جلسة التشفير
    encryption_key = Fernet.generate_key()
    cipher_suite = Fernet(encryption_key)


    def decrypt_data(data, cipher_suite=None):
        # فك تشفير البيانات
        return cipher_suite.decrypt(data.encode()).decode()

    def update_client_info(self, logged_in_user, phone,location,idNumber):

        # فك تشفير المعلومات (تأكد من تعريف وتنفيذ decrypt_data بشكل صحيح)
        phone = self.decrypt_data(json.dumps(phone))
        location = self.decrypt_data(json.dumps(location))
        idNumber = self.decrypt_data(json.dumps(idNumber))

        # تحديث المعلومات في قاعدة البيانات
        try:
            update_result = self.clients_collection.update_one(
                {"username": logged_in_user},
                {"$set":
                     {"phone": phone,"location": location,"idNumber": idNumber}}
            )
            # التحقق من نجاح التحديث
            if update_result.modified_count > 0:
                return json.dumps({"status": "success", "message": "Information updated successfully"})
            else:
                return json.dumps({"status": "error", "message": "No information was updated"})
        except Exception as err:
            return json.dumps({"status": "error", "message": str(err)})

    def process_request(self, request):
        # تحليل الطلب وتنفيذ العملية المطلوبة
        request_data = json.loads(request)
        if request_data["type"] == "register":
            return self.register_user(request_data["username"], request_data["password"])
        elif request_data["type"] == "login":
            return self.login_user(request_data["username"], request_data["password"])
        elif request_data["type"] == "cpmplete_register":
            return self.update_client_info(request_data["logged_in_user"], request_data["phone"],request_data["location"],request_data["idNumber"])
        else:
            return json.dumps({"status": "error", "message": "Invalid request type"})
              #تطبيق عملية التوقيع والتحقق في عملية الاتصال بين العميل والسيرفر.
        # على سبيل المثال، عندما يرسل السيرفر بيانات إلى العميل،
        # يجب أن يقوم بتوقيع هذه البيانات وإرسال التوقيع معها.
        # وعندما يتلقى العميل هذه البيانات، يجب عليه التحقق من التوقيع باستخدام المفتاح العام للسيرفر.
        #signature = self.sign_data(response_data.encode())
       # return json.dumps({"data": response_data, "signature": signature.hex()})

    def register_user(self, username, password):
        # تشفير كلمة المرور وتسجيل المستخدم الجديد
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        try:
            self.clients_collection.insert_one({"username": username, "password": hashed_password})
            return json.dumps({"status": "success", "message": "User registered successfully"})
        except Exception as err:
            return json.dumps({"status": "error", "message": str(err)})

    def login_user(self, username, password):
        # البحث عن المستخدم بناءً على اسم المستخدم
        user = self.clients_collection.find_one({"username": username})
        # التحقق من كلمة المرور
        if user and bcrypt.checkpw(password.encode(), user['password']):
            return json.dumps({"status": "success", "message": "Login successful"})
        else:
            return json.dumps({"status": "error", "message": "Invalid username or password"})
            
            
            #وظيفة لتوقيع البيانات في السيرفر. هذا يتضمن استخدام المفتاح الخاص للسيرفر لتوقيع البيانات قبل إرسالها إلى العميل.

    def sign_data(self, data):
        # توقيع البيانات باستخدام المفتاح الخاص للخادم
        signature = self.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

server = Server("127.0.0.1",5080)
server.start()

