# functions.py
from flask_mail import Message
from flask import url_for
from . import mail
from .Converter import Converter
import os
import  json
import uuid
from flask  import current_app as app
from cryptography.fernet import Fernet
import os
from .dataencryption import AESCipher 
from . import scheduler
import logging
from .DeleteTask import delete_user_files_and_data

#scheduler.add_job(id='minute_task', func=delete_user_files_and_data, trigger='interval', minutes=2)
scheduler.add_job(id='daily_task', func=delete_user_files_and_data, trigger='cron', hour=0, minute=0)

aes_cipher = AESCipher()
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

def dict_to_string(input_dict):
    """
    Convert a dictionary to a string.
    
    Args:
        input_dict (dict): The dictionary to be converted.
    
    Returns:
        str: The converted string.
    """
    return json.dumps(input_dict)

def string_to_dict(input_string):
    """
    Convert a string to a dictionary.
    
    Args:
        input_string (str): The string to be converted.
    
    Returns:
        dict: The converted dictionary.
    """
    return json.loads(input_string)

def generate_filename(types):
    if types == 'der':
        return  str(uuid.uuid4()) + '.der'
    elif types == 'file':

        return  str(uuid.uuid4())




def makedir():
    uuid_str = str(uuid.uuid4())
    APP_ROOT = os.path.dirname(os.path.abspath(__file__))
    private_key_keypath = os.path.join(APP_ROOT, f'static/key/private_key/{uuid_str}')
    public_key_keypath = os.path.join(APP_ROOT, f'static/key/public_key/{uuid_str}')

    print('keypath', private_key_keypath, public_key_keypath)
    uploadfolder = os.path.join(APP_ROOT, f'static/uploads/{uuid_str}')
    decryptfolder = os.path.join(APP_ROOT, f'static/Decrypt/{uuid_str}')
    
    try:
        if not (os.path.exists(private_key_keypath) and os.path.exists(public_key_keypath) and os.path.exists(uploadfolder)and os.path.exists(decryptfolder)):
            os.makedirs(decryptfolder,exist_ok=True)
            os.makedirs(private_key_keypath, exist_ok=True)
            os.makedirs(public_key_keypath, exist_ok=True)
            os.makedirs(uploadfolder, exist_ok=True)
        else:
            print("Folder Already Exists")
    except OSError as e:
        print(e)
    return uuid_str




def get_folder_size(folder_path):
    total_size = 0
    for dirpath, _, filenames in os.walk(folder_path):
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            total_size += os.path.getsize(file_path)
        inGB=Converter.convert_to_GB(total_size)
    return inGB

def string_to_hex(input_string):
    try:
        # Encode the string to bytes using UTF-8 encoding
        byte_value = input_string.encode('utf-8')
        
        # Convert each byte to its hexadecimal representation and join them
        hex_value = byte_value.hex()
        return hex_value.encode()
    except Exception as e:
        print(f"Error encoding string: {e}")
        return None
# def user_login(db,File,current_user):
        
#         user_files = current_user.files  # Assuming 'files' is the relationship between User and File models

#         # Initialize a list to store image data
#         file_data_list = []

#         # Decrypt and encode each file's data
#         for file in user_files:
#             file_path = aes_cipher.decrypt_data(file.filepath)
#             private_key_path = aes_cipher.decrypt_data(file.private_key_path)

#             # Decrypt the file
#             decryption_instance = File_Decryption()
#             private_key = decryption_instance.load_key_from_file(private_key_path)
#             decrypted_data = decryption_instance.decrypt_file(file_path, private_key)

#             # Base64 encode the decrypted file data
#             decrypted_data_base64 = rbase64.b64encode(decrypted_data).decode('utf-8')
            

#             mimetype = aes_cipher.decrypt_data(file.mimetype)

         




# def user_logut(db,File,current_user):
#         user_files = current_user.files
#         for file in user_files:
#             _, extension = os.path.splitext(filename)
#             keypath=app.config['KEY_FOLDER']
#             public_key_path=aes_cipher.decrypt_data(file.public_key_path)
#             private_key_path=aes_cipher.decrypt_data(file.private_key_path)
#             encryption_instance = File_Encryption()
#             key_pair = encryption_instance.generate_key_pair()
#             public_key = key_pair.publickey()
#             private_key = key_pair
#             encryption_instance.save_key_to_file(public_key, public_key_path)
#             encryption_instance.save_key_to_file(private_key, private_key_path)
#             public_key = encryption_instance.load_key_from_file(public_key_path)
#             output=file.filepath
#             print("\n\n\n",output,'\n',type(output),'\n\n')
#             encryption_instance.encrypt_file(filepath, public_key)

#             addnew=File(filename=aes_cipher.encrypt_data(filename),filepath=aes_cipher.encrypt_data(output),private_key_path=aes_cipher.encrypt_data(private_key_path),public_key_path=aes_cipher.encrypt_data(public_key_path),user_id=current_user.id,mimetype=aes_cipher.encrypt_data(file.mimetype))
#             db.session.add(addnew)
#             db.session.commit()
#             thread = threading.Thread(target=os.remove, args=(filepath,))
#             thread.start()
#             size=os.path.getsize(output)
#             print("SIZE:",size)
#             print("TYPE OF SIZE",type(size))




