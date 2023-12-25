from flask import Flask
from pymongo import MongoClient
app = Flask(__name__)
# إعداد اتصال MongoDB
mongo_client = MongoClient('localhost', 27017)
db = mongo_client['sys']  # اسم قاعدة البيانات

