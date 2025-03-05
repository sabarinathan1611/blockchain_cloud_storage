from flask_mail import Message
from flask import url_for
from .Encryption.dataencryption import AESCipher 
import os
from app import mail

aes_cipher=AESCipher()

def send_verification_email(user,passChange=False):
    if  passChange:
        print('Enter into Change password ')
        verification_link = url_for('auth.changepass', verification_token=user.verification_token, _external=True)
        subject = 'Verify Your Email for Web App'
        body = f'Click the following link to verify your email: {verification_link}'
        email=aes_cipher.decrypt_data(user.email) 
        print("Email passChange")
        send_email(email, subject, body)
    else:
        verification_link = url_for('auth.verify_email', verification_token=user.verification_token, _external=True)
        subject = 'Verify Your Email for Web App'
        body = f'Click the following link to verify your email: {verification_link}'
        email=aes_cipher.decrypt_data(user.email) 
        print("Email")
        send_email(email, subject, body)


def send_email(to, subject, body):
    sender=os.environ.get('GMAIL_USERNAME')
    print("SENDER MAIL: ",sender)
    msg = Message(subject, sender=os.environ.get('GMAIL_USERNAME'), recipients=[to])
    msg.body = body
    mail.send(msg)
