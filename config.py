# config.py
import os
from cryptography.fernet import Fernet
key = Fernet.generate_key()
decoded_key = key.decode()
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a_secret_key'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    ENCRYPTION_KEY = decoded_key  # Replace this with the actual generated key
