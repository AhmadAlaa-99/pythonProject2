# models/client.py
from extensions import db


class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.ENUM('student', 'professor', 'admin'), nullable=False)
    information = db.relationship('InformationClient', backref='client', uselist=False, lazy=True)



class InformationClient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    number = db.Column(db.String(20), nullable=True)
    location = db.Column(db.String(255), nullable=True)



