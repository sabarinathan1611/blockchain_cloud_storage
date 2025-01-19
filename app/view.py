from flask import Blueprint, render_template, request, flash, redirect, url_for,jsonify,abort,session
from . import db
from .models import User,Text,File,DeleteAccount,Feedback
from flask_login import login_required,current_user
from .sysinfo import *
from .functions import dict_to_string,string_to_dict,generate_filename,send_verification_email
from .forms import *
from flask  import current_app as app
from .TextEncryption import text_encryption,text_decryption
from .dataencryption import *
from .config import Config
import os
from werkzeug.utils import secure_filename
import threading
import base64
from .FileEncryption import *
from .Converter import Converter

aes_cipher = AESCipher()

view = Blueprint('view', __name__)





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
        
        stype = aes_cipher.encrypt_data("password")
        
        newtext = Text(user_id=current_user.id, encrypted_Key=encrypted_session_key, nonce=iv, ciphertext=ciphertext, private_key_path=encrypted_private, public_key_path=encrypted_public, store_type=stype)
        db.session.add(newtext)
        db.session.commit()
    
    return redirect(url_for('view.home'))

@view.route('/showpass', methods=['POST', 'GET'])
@login_required
def showpass():
    form = EditPasswordForm()
    if current_user.is_authenticated:
        passwords = Text.query.filter_by(user_id=current_user.id)
        data = []
        # decryption_ = CryptoKyber()
        for password in passwords:
            decrypted_public_key_path = aes_cipher.decrypt_data(password.public_key_path)  # Assuming it's bytes
            decrypted_private_key_path = aes_cipher.decrypt_data(password.private_key_path)  # Assuming it's bytes
            
            decrypted_message = text_decryption(
                public_key_path=decrypted_public_key_path, 
                private_key_path=decrypted_private_key_path, 
                encrypted_session_key=password.encrypted_Key, 
                iv=password.nonce, 
                ciphertext=password.ciphertext, 
                salt=session.get('salt')
            )
            
            data.append({
                "id": password.id,
                "data": string_to_dict(decrypted_message),
                "store_type": aes_cipher.decrypt_data(password.store_type)
            })

        return render_template('passwords.html', data=data, form=form)
    else:
        return redirect(url_for('view.home'))



@view.route('/uploadfile', methods=['POST'])
@login_required
def fileuplod():
    form = FileForm()
    if form.validate_on_submit():
        file = form.file.data
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], generate_filename('file')+filename)
        filemimetype=file.mimetype
        file.save(filepath)
        print("File:", filename)
        _, extension = os.path.splitext(filename)
        keypath=app.config['KEY_FOLDER']
        public_key_path=os.path.join(keypath,'public_key',aes_cipher.decrypt_data(current_user.path),generate_filename('der'))
        private_key_path=os.path.join(keypath,'private_key',aes_cipher.decrypt_data(current_user.path),generate_filename('der'))
        encryption_instance = FileEncryption()
        key_pair = encryption_instance.generate_key_pair()
        public_key = key_pair.publickey()
        private_key = key_pair
        encryption_instance.save_key_to_file(public_key, public_key_path)
        encryption_instance.save_key_to_file(private_key, private_key_path)
        public_key = encryption_instance.load_key_from_file(public_key_path)
        output=os.path.join(app.config['UPLOAD_FOLDER'], aes_cipher.decrypt_data(current_user.path),generate_filename('file')+extension)
        print("\n\n\n",output,'\n',type(output),'\n\n')
        encryption_instance.encrypt_file(filepath, public_key)

        addnew=File(filename=aes_cipher.encrypt_data(filename),filepath=aes_cipher.encrypt_data(output),private_key_path=aes_cipher.encrypt_data(private_key_path),public_key_path=aes_cipher.encrypt_data(public_key_path),user_id=current_user.id,mimetype=aes_cipher.encrypt_data(file.mimetype))
        db.session.add(addnew)
        db.session.commit()
        thread = threading.Thread(target=os.remove, args=(filepath,))
        thread.start()
        size=os.path.getsize(output)
        print("SIZE:",size)
        print("TYPE OF SIZE",type(size))

    return redirect(url_for('view.decrypt_file'))


@view.route('/showfile')
@login_required
def decrypt_file():
# Get all files associated with the current user
    user_files = current_user.files  # Assuming 'files' is the relationship between User and File models

    # Initialize a list to store image data
    file_data_list = []

    # Decrypt and encode each file's data
    for file in user_files:
        file_path = aes_cipher.decrypt_data(file.filepath)


        private_key_path = aes_cipher.decrypt_data(file.private_key_path)

        # Decrypt the file
        decryption_instance = FileDecryption()
        private_key = decryption_instance.load_key_from_file(private_key_path)
        decrypted_data = decryption_instance.decrypt_file(file_path, private_key)

        # Base64 encode the decrypted file data
        decrypted_data_base64 = base64.b64encode(decrypted_data).decode('utf-8')

        mimetype = aes_cipher.decrypt_data(file.mimetype)

        # Append the file data to the list
        file_data_list.append({
            'decrypted_data_base64': decrypted_data_base64,
            'mimetype': mimetype
        })


    # Pass the list of file data to the template
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
