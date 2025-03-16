from flask import Blueprint, render_template, request, flash, redirect, url_for,jsonify,abort,session
from . import db
from .models import User,Text,File,DeleteAccount,Feedback
from flask_login import login_required,current_user
from .utils.sysinfo import *
from .utils.forms import *
from .utils.encryption import dict_to_string, string_to_dict
from .utils.file_utils import generate_filename
from .utils.email_utils import send_verification_email
from flask  import current_app as app
from .utils.Encryption.TextEncryption import text_encryption,text_decryption
from .utils.Encryption.dataencryption import AESCipher 

from .API.API import APIManager
# from .utils.config import Config
import os
from werkzeug.utils import secure_filename
import threading
import base64
from .utils.Encryption.FileEncryption import *
import traceback
from .utils.Converter import Converter
aes_cipher = AESCipher()
from base64 import b64decode, b64encode

view = Blueprint('view', __name__)

api =APIManager()



@view.route('/',methods=['POST','GET'])
@login_required
def home():

    if current_user.is_verified != True:
        flash("Verify Your Email")
        return redirect(url_for('auth.logout'))
    else:
            fileform=FileForm()
            user = User.query.get_or_404(current_user.id);
            if user.used_storage == user.limited_storage :
                flash("Your storage is full")

                return redirect(url_for('view.profile'))
            form = PasswordForm()

    return render_template('home.html',form=form,fileform=fileform)



    
@view.route('/admin',methods=['POST','GET'])
@login_required
def admin():
    
    if current_user.role == 'admin':
        system_info_printer = SystemInfoPrinter()
        storage_info= system_info_printer.print_storage_info()
        system_info =system_info_printer.print_system_info()
        user = User.query.order_by(User.date)
        feedback = Feedback.query.order_by(Feedback.date)
        

    else: 
        flash("You Don't have a Access")
        return redirect(url_for('view.home'))


    return render_template ('admin.html',storage_info=storage_info,system_info=system_info,user=user,feedback=feedback)

@view.route('/password', methods=['POST'])
@login_required
def store_pass():
    form = PasswordForm()
    if request.method == 'POST' and form.validate_on_submit():
        url = form.url.data
        name = form.name.data
        username = form.username.data
        password = form.password.data
        keypath = app.config['KEY_FOLDER']
        data = {'url': url, 'name': name, 'username': username, 'password': password, 'keypath': keypath}
        
        string = dict_to_string(data)
        
        public_key_path = os.path.join(keypath, 'public_key', aes_cipher.decrypt_data(current_user.path), generate_filename('der'))
        encrypted_public = aes_cipher.encrypt_data(public_key_path)  # Assuming public_key_path is bytes
        
        private_key_path = os.path.join(keypath, 'private_key', aes_cipher.decrypt_data(current_user.path), generate_filename('der'))
        encrypted_private = aes_cipher.encrypt_data(private_key_path)  # Assuming private_key_path is bytes

        encrypted_session_key, iv, ciphertext = text_encryption(public_key_path, private_key_path, string, salt=session.get('salt'))
        
        newtext=api.add_password_data(user_id=current_user.id,user_email=aes_cipher.decrypt_data(current_user.email) ,encrypted_key=encrypted_session_key, iv=iv, ciphertext=ciphertext, private_key_path=encrypted_private, public_key_path=encrypted_public, data_type="password")
        print(newtext)
        # newtext = Text(user_id=current_user.id, encrypted_Key=encrypted_session_key, nonce=iv, ciphertext=ciphertext, private_key_path=encrypted_private, public_key_path=encrypted_public, store_type=stype)
        # db.session.add(newtext)
        # db.session.commit()
    
    return redirect(url_for('view.home'))

@view.route('/showpass', methods=['POST', 'GET'])
@login_required
def showpass():
    form = EditPasswordForm()
    if current_user.is_authenticated:
        
        passwordLists = api.list_data("password-list", user_id=current_user.id, user_email=aes_cipher.decrypt_data(current_user.email))

        data = []
        for password_entry in passwordLists.get('passwords', []):
            # Decode from Base64 to original bytes
            encrypted_key = base64.b64decode(password_entry['data']['encrypted_Key'])
            iv = base64.b64decode(password_entry['data']['iv'])
            ciphertext = base64.b64decode(password_entry['data']['ciphertext'])
            
            # Decrypt private and public key paths
            private_key_path = aes_cipher.decrypt_data(base64.b64decode(password_entry['data']['private_key_path']))
            public_key_path = aes_cipher.decrypt_data(base64.b64decode(password_entry['data']['public_key_path']))
            
            decrypted_message = text_decryption(
                encrypted_key=encrypted_key,
                iv=iv,
                ciphertext=ciphertext,
                salt=session.get('salt'),
                public_key_path=public_key_path,
                private_key_path=private_key_path
            )
            
            data.append({
                "id": current_user.id,
                "data": string_to_dict(decrypted_message),
                "store_type": password_entry['data']['type']
            })

        return render_template('passwords.html', data=data, form=form)
    else:
        return redirect(url_for('view.home'))

# def ensure_keys(public_key_path, private_key_path):
#     if not os.path.exists(public_key_path) or not os.path.exists(private_key_path):
#         kyber = FileCryptoKyber(public_key_path, private_key_path)
#         kyber.generate_keys()

@view.route('/uploadfile', methods=['POST'])
@login_required
def fileupload():
    form = FileForm()
    if form.validate_on_submit():
        file = form.file.data
        filename = secure_filename(file.filename)
        filemimetype = file.mimetype

        # File paths and key paths
        keypath = app.config['KEY_FOLDER']
        user_folder = aes_cipher.decrypt_data(current_user.path)
        public_key_path = os.path.join(keypath, 'public_key', user_folder, generate_filename('der'))
        private_key_path = os.path.join(keypath, 'private_key', user_folder, generate_filename('der'))
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], user_folder, generate_filename('file') + filename)

        # Save file temporarily
        try:
            file.save(filepath)
        except Exception as e:
            flash(f"File upload failed: {e}")
            return redirect(url_for('view.fileupload'))

        # Encrypt file
        try:
            with open(filepath, 'rb') as f:
                file_data = f.read()

            salt = current_user.salt
            kyber_instance = FileCryptoKyber(public_key_path, private_key_path)
            encrypted_key, iv, ciphertext = kyber_instance.encrypt_file(file_data, salt)

            # Save encrypted data to a new file
            encrypted_filepath = filepath 
            with open(encrypted_filepath, 'wb') as f:
                f.write(ciphertext)

            # ✅ Fix: Convert all binary fields to bytes before storing
            addnew = File(
                filename=b64encode(filename.encode()),  # Convert to bytes
                filepath=b64encode(encrypted_filepath.encode()),  # Convert to bytes
                private_key_path=b64encode(private_key_path.encode()),  # Convert to bytes
                public_key_path=b64encode(public_key_path.encode()),  # Convert to bytes
                user_id=current_user.id,
                mimetype=b64encode(filemimetype.encode()),  # Convert to bytes
                iv=iv,  # Already bytes
                encrypted_key=encrypted_key  # Already bytes
            )
            # newtext=api.add_password_data(user_id=current_user.id,user_email=aes_cipher.decrypt_data(current_user.email) ,encrypted_key=encrypted_session_key, iv=iv, ciphertext=ciphertext, private_key_path=encrypted_private, public_key_path=encrypted_public, data_type="password")
            newfile=api.add_file_data(data_type="file", user_id=current_user.id, user_email=aes_cipher.decrypt_data(current_user.email), filename=filename, filepath=filepath, private_key_path=private_key_path, public_key_path=public_key_path, mimetype=filemimetype, iv=iv, encrypted_key=encrypted_key)
            print(newfile)
            db.session.add(addnew)
            db.session.commit()

        except Exception as e:
            print(traceback.format_exc())
            flash(f"Encryption failed: {e}")
        return redirect(url_for('view.decrypt_file'))




@view.route('/showfile')
@login_required
def decrypt_file():
    file_data_list = []

    static_folder = os.path.abspath(app.config['STATIC_FOLDER'])
    decrypt_folder = os.path.join(static_folder, 'Decrypt')

    Filelist = api.list_data("filedata-list", user_id=current_user.id, user_email=aes_cipher.decrypt_data(current_user.email))

    for file in Filelist.get('files', []):
        try:
            # Use paths directly (no base64 decode needed!)
            file_path = file['data']['filepath']
            private_key_path = file['data']['private_key_path']
            public_key_path = file['data']['public_key_path']
            encrypted_key = base64.b64decode(file['data']['encrypted_key'])
            iv = base64.b64decode(file['data']['iv'])
            salt = current_user.salt

            # Read encrypted file
            with open(file_path, 'rb') as f:
                ciphertext = f.read()

            # Decrypt the file
            kyber_instance = FileCryptoKyber(public_key_path, private_key_path)
            decrypted_data = kyber_instance.decrypt_file(encrypted_key, iv, ciphertext, salt)

            # Create user-specific decrypt folder
            user_folder = aes_cipher.decrypt_data(current_user.path)
            user_decrypt_path = os.path.join(decrypt_folder, user_folder)
            os.makedirs(user_decrypt_path, exist_ok=True)

            # Create decrypted file path
            decrypted_filename = secure_filename(os.path.basename(file_path))
            decrypted_filepath = os.path.join(user_decrypt_path, decrypted_filename)
            
            # Save decrypted file
            with open(decrypted_filepath, 'wb') as f:
                f.write(decrypted_data)

            filee = file['data']['filename']
            relative_path = os.path.relpath(decrypted_filepath, static_folder).replace('\\', '/')

            file_data_list.append({
                'file_path': url_for('static', filename=relative_path),
                'filename': filee,
                'mimetype': file['data']['mimetype']
            })

        except Exception as e:
            print(traceback.format_exc())
            flash(f"Decryption failed: {str(e)}", 'error')
            continue

    return render_template('decrypted_file.html', file_data_list=file_data_list)

@view.route('/profile', methods=['POST'])
@login_required
def save_profile():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        print('username:', username)
        print('Email: ', email)

        user_id = current_user.id
        user = User.query.get_or_404(user_id)
        
        # Encrypt data, encoding to bytes if necessary
        user.username = aes_cipher.encrypt_data(username)
        user.email = aes_cipher.encrypt_data(email)
        user.is_verified=False
        send_verification_email(user)
        flash('Verify Your Email')

        
        db.session.commit()

    return redirect(url_for('view.profile'))




@view.route('/profile', methods=['GET'])
@login_required
def profile():
    form=ProfileForm()
    convert=Converter()
    user_id = current_user.id
    user = User.query.get_or_404(user_id)
    used = user.used_storage
    print('used', used)
    limit = user.limited_storage
    print('limit', limit)
    percentage=Converter.calculate_percentage(used,limit)
    print("percentage",percentage)
    users = {
        'username': aes_cipher.decrypt_data(user.username),
        'email': aes_cipher.decrypt_data(user.email),
        'used_storage': convert.convert_to_GB(used),  
        'limited_storage': convert.convert_to_GB(limit)  
    }

    return render_template('profile.html', users=users,form=form)
    

@view.route('/edit-password', methods=['POST'])
@login_required
def edit_password():
    print("Method :",request.method)
    if request.method == 'POST':
        id= request.form.get('id')
        url=request.form.get('url')
        username = request.form.get('username')
        password=request.form.get('password')
        name=request.form.get('name')
        print("ID :",id,"\n url :",url,"\n username :",username," \n password:",password)
        text = Text.query.get_or_404(id)
        # print("\n\n\n\n\t",text.user_id,"\n\n\n\n\t")
        if text and text.user_id == current_user.id:
            # print("\n\n \t",True ,"\n \n\t")
            keypath=app.config['KEY_FOLDER']
            data={'url':url,'name':name,'username':username,'password':password,'keypath':keypath}
            string=dict_to_string(data)
            public_key_path=os.path.join(keypath,'public_key',aes_cipher.decrypt_data(current_user.path),generate_filename('der'))
            print('public_key_path',public_key_path)
            encrypted_public=aes_cipher.encrypt_data(public_key_path)
            private_key_path=os.path.join(keypath,'private_key',aes_cipher.decrypt_data(current_user.path),generate_filename('der'))
            print('private_key_path',private_key_path)
            encrypted_private=aes_cipher.encrypt_data(private_key_path)
            encrypted_session_key, iv, ciphertext = text_encryption(public_key_path, private_key_path, string)
            stype=aes_cipher.encrypt_data("password")

            path=aes_cipher.decrypt_data(text.private_key_path)
            if os.path.exists(path):
                os.remove(path)
            else:
                print(f"File not found: {path}")
            path=aes_cipher.decrypt_data(text.public_key_path)
            if os.path.exists(path):
                os.remove(path)

            text.user_id=current_user.id 
            text.encrypted_Key=encrypted_session_key
            text.nonce=iv
            text.ciphertext=ciphertext
            text.private_key_path=encrypted_private
            text.public_key_path=encrypted_public
            text.store_type=stype
            db.session.commit()      
    return redirect(url_for('view.showpass'))


@view.route('/delete-me', methods=['POST', 'GET'])
@login_required  # Ensure the user is logged in
def deleteaccount():
    try:
        # Create a new entry in the DeleteAccount table with decrypted email
        addnew = DeleteAccount(user_id=current_user.id, email=aes_cipher.decrypt_data(current_user.email))
        db.session.add(addnew)

        # Set the user's is_verified attribute to False
        current_user.is_verified = False
        print(current_user.is_verified)

        # Commit the transaction to the database
        db.session.commit()

        # Flash a success message
        flash('Your account deletion request has been submitted.', 'success')

    except Exception as e:
        # Rollback the session in case of an error
        db.session.rollback()
        flash(f'An error occurred: {str(e)}', 'danger')

    # Redirect to the home page
    return redirect(url_for('view.home'))

@view.route('/about',methods=['POST','GET'])
def about():
    form=FeedBack()
    if form.validate_on_submit() and request.method == 'POST':
        name = form.name.data
        email = form.email.data
        text=form.text.data

        print("Name :"+name)
        print("Email :"+ email)
        print("Text :"+ text)

        feedback=Feedback(name=name,email=email,text=text)
        db.session.add(feedback)
        db.session.commit()
    return render_template("About.html",form=form)
