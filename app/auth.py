# auth.py
from flask import Blueprint, render_template, request, flash, redirect, url_for,jsonify,session
from flask_login import login_required, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from . import db, mail
from .models import User
from .forms import LoginForm, SignUpForm,EmailForm,ChangePassForm
from .functions import send_verification_email,makedir,string_to_hex
from .config import Config 
from flask_cors import cross_origin
from .dataencryption import AESCipher 
import secrets
from .Log import Log as log
from datetime import timedelta,datetime
from secrets import token_bytes


auth = Blueprint('auth', __name__)
aes_cipher = AESCipher()



@auth.route('/login', methods=['GET', 'POST'])
def login():
    loginform = LoginForm() 
    form = SignUpForm()
    if loginform.validate_on_submit():
        email = form.email.data
        password = form.password.data   
        # print("Email",email)
        encrypted_email = aes_cipher.encrypt_data(email)
        # print("encrypted_email:",encrypted_email)
        user = User.query.filter_by(email=encrypted_email).first()

        
       

 

        if user and check_password_hash(user.password, password):
            session['last_active'] = datetime.now()
            login_user(user, remember=True)
            session['salt']=current_user.salt
            
            # log.writeLog("Login",user.id)
            return redirect(url_for('view.home'))
        else:
            flash("Login unsuccessful. Please check your email and password.")
    return render_template('login.html', form=form,login=loginform)





@auth.route('/sign-up', methods=['POST', 'GET'])
def sign_up():
    

    if request.method == 'POST' :
        email = request.form.get('email')

        password = request.form.get('password')
        name = request.form.get('fullname')
        hashed_password = generate_password_hash(password)
        print("\t\n\n\n\n\n\n\n\n\n\nencrypted_email :",type(hashed_password),"\t\n\n\n\n\n\n\n\n")


        
        encrypted_name=aes_cipher.encrypt_data(data=name)
        encrypted_email=aes_cipher.encrypt_data(data=email)

        already_in = User.query.filter_by(email=encrypted_email).first()
        if already_in:
            flash('Email address is already in use.', 'danger')
            return redirect(url_for('auth.sign_up'))
        else:
            if email == Config.AdminMail:
                print("Admin Email:",Config.AdminMail)
                path=makedir()
                user = User(email=encrypted_email,path=aes_cipher.encrypt_data(path), password=hashed_password, username=encrypted_name,is_verified=True,role='admin',limited_storage=1073741824)
                db.session.add(user)
                db.session.commit()


                flash('Admin Account created successfully', 'success')
                return redirect(url_for('view.home'))
            else:
                path=makedir()
                
                user = User(email=encrypted_email,path=aes_cipher.encrypt_data(path), password=hashed_password, username=encrypted_name,is_verified=True)
                db.session.add(user)
                db.session.commit()
                print('Account created')

                # Send verification email to the user
                # send_verification_email(user)

                flash('Account created successfully. Check your email for verification.', 'success')
    return redirect(url_for('view.home'))

   

@auth.route('/verify_email/<string:verification_token>')
def verify_email(verification_token):
    user = User.query.filter_by(verification_token=verification_token).first()

    if user:
        # Mark the user as verified
        user.is_verified = True
        user.verification_token=None
        db.session.commit()

        # Log in the user after successful verification
        login_user(user)

        flash('Email verification successful! You can now access your account.')
        return redirect(url_for('view.home'))
    else:
        flash('Invalid verification token. Please try again.')
        return redirect(url_for('auth.sign_up'))

@auth.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/delete-account')
def deleteaccount():
    id=current_user.id
    
    return redirect(url_for('auth.login'))

@auth.route('/forget-password',methods=['POST','GET'])
def forgetpassword():
    emailform=EmailForm()
    print('Worl',request.method)
    if request.method=='POST':
        encrypted_email=aes_cipher.encrypt_data(emailform.email.data)
        print("Email",emailform.email.data)
        user=User.query.filter_by(email=encrypted_email).first()
        #print("User: ",aes_cipher.decrypt_data(user.email))
        if user:
            print("Link",user.verification_token)
            user.verification_token=secrets.token_urlsafe().replace("}" ,"-").replace('{','-')
            print("user",user)
            db.session.commit()
            print('User',user.verification_token)
            send_verification_email(user,passChange=True)
            flash("Check your email for verification",'success')

            return redirect(url_for('auth.login'))


        else:
            flash('Email Not Found')
    return render_template('email.html',form=emailform)

@auth.route('/changepass/<string:verification_token>', methods=['POST', 'GET'])
def changepass(verification_token):
    print("verification_token: ", verification_token)
    user = User.query.filter_by(verification_token=verification_token).first()
    
    if not user:
        flash('Invalid verification token. Please try again.')
        return redirect(url_for('auth.sign_up'))
    
    changepass_form = ChangePassForm()
    print("User: ", user)

    print("request.method: ", request.method)
    if request.method == 'POST':
        password = changepass_form.password.data
        confirm_password = changepass_form.confirm_password.data
        if password == confirm_password:
            new_password_hash = generate_password_hash(password)
            old_password = user.password
            print("new_password_hash: ", new_password_hash)
            print("old_password: ", old_password)
            user.password = new_password_hash
            flash('Password Changed')
            print('Password Changed')
            user.verification_token = None
            db.session.commit()
            #login_user(user)
            flash('Email verification successful! You can now access your account.')
            return redirect(url_for('auth.login'))
        else:
            flash('Passwords do not match. Please try again.')
    return render_template('changepass.html', form=changepass_form)
