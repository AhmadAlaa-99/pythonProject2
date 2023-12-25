import socket
import json
import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
class Client:
    # توليد مفتاح تشفير وإعداد جلسة التشفير
    encryption_key = Fernet.generate_key()
    cipher_suite = Fernet(encryption_key)
    def __init__(self, host, port):
        # تعيين عنوان الخادم والمنفذ
        self.host = host
        self.port = port
        # إنشاء سوكت والاتصال بالخادم
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((host, port))
        # تعيين حالة تسجيل الدخول
        self.is_logged_in = False
        # توليد مفتاح خاص وعام للتشفير
        self.private_key, self.public_key = self.generate_keys()
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

    def hash_password(self, password):
        # تشفير كلمة المرور باستخدام bcrypt
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    def send_request(self, request_type, username, password):
        # تشفير كلمة المرور وإعداد بيانات الطلب
        hashed_password = self.hash_password(password)
        request_data = json.dumps({
            "type": request_type,
            "username": username,
            "password": hashed_password.decode()
        })
        # إرسال الطلب إلى الخادم
        self.client_socket.send(request_data.encode())
        # استقبال الرد من الخادم
        response = self.client_socket.recv(1024).decode()
        return response

    @staticmethod
    def encrypt_data(data):
        # تشفير البيانات باستخدام Fernet
        return Client.cipher_suite.encrypt(data.encode()).decode()

    def send_update_info_request(self, username, info):
        # تشفير المعلومات وإعداد بيانات الطلب
        encrypted_info = self.encrypt_data(json.dumps(info))
        request_data = json.dumps({
            "type": "update_info",
            "username": username,
            "info": encrypted_info
        })
        # إرسال الطلب إلى الخادم
        self.client_socket.send(request_data.encode())
        # استقبال الرد من الخادم
        response = self.client_socket.recv(1024).decode()
        return response

    def send_public_key(self):
        # تحويل المفتاح العام للعميل إلى تنسيق PEM وإرساله
        public_key = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.client_socket.send(public_key)

    def receive_server_public_key(self):
        # استقبال المفتاح العام للخادم
        server_public_key = self.client_socket.recv(1024)
        return serialization.load_pem_public_key(
            server_public_key,
            backend=default_backend()
        )

    def encrypt_with_public_key(self, message, public_key):
        # تشفير الرسالة باستخدام المفتاح العام
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
        # فك تشفير الرسالة باستخدام المفتاح الخاص
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
        # التحقق من التوقيع باستخدام المفتاح العام
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
        # معالجة الرد من الخادم
        response_json = json.loads(response)
        data = response_json["data"]
        signature = bytes.fromhex(response_json["signature"])
        # التحقق من صحة البيانات
        is_valid = self.verify_signature(server_public_key, signature, data.encode())
        if is_valid:
            print("Data is valid and verified.")
        else:
            print("Data verification failed.")

    def close(self):
        # إغلاق الاتصال بالخادم
        self.client_socket.close()

# إنشاء كائن العميل والاتصال بالخادم
client = Client("127.0.0.1", 5080)
# إرسال المفتاح العام للعميل إلى الخادم
client.send_public_key()
# استقبال المفتاح العام للخادم
server_public_key = client.receive_server_public_key()


def display_main_menu():
    print("1. Register")
    print("2. Login")
    print("3. Exit")
    choice = input("Enter your choice (1-3): ")
    return choice

def display_logged_in_menu():
    print("1. Complete Information")
    print("2. Logout")
    choice = input("Enter your choice (1-2): ")
    return choice

logged_in = False
logged_in_user = None

while True:
    if not logged_in:
        user_choice = display_main_menu()

        if user_choice == "1":
            username = input("Enter username for registration: ")
            password = input("Enter password for registration: ")
            register_response = client.send_request("register", username, password)
            print("Register response:", register_response)

        elif user_choice == "2":
            # جمع بيانات تسجيل الدخول وإرسال طلب تسجيل الدخول
            username = input("Enter username for login: ")
            password = input("Enter password for login: ")
            login_response = client.send_request("login", username, password)
            print("Login response:", login_response)
            # تحقق من نجاح تسجيل الدخول
            if "success" in login_response:
                logged_in = True
                logged_in_user = username  # تخزين اسم المستخدم

        elif user_choice == "3":
            print("Exiting the program.")
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 3.")
    else:
        user_choice = display_logged_in_menu()
        if user_choice == "1":
            phone = input("Enter phone for cpmplete_register: ")
            location = input("Enter location for cpmplete_register: ")
            idNumber = input("Enter location for idNumber: ")
            login_response = client.send_request("cpmplete_register",logged_in_user,phone,location, idNumber)
            print("Login response:", login_response)
        elif user_choice == "2":
            # تسجيل الخروج
            logged_in = False
            logged_in_user = None  # إعادة تعيين اسم المستخدم
        else:
            print("Invalid choice. Please enter 1 or 2.")

# إغلاق الاتصال بالخادم
client.close()