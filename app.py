import os
import base64
import json
import uuid
import tempfile
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from io import BytesIO
from itsdangerous import URLSafeTimedSerializer, SignatureExpired

from forms import (
    LoginForm, RegisterForm, EncryptForm, DecryptForm, HashForm, 
    CompareHashesForm, GeneratePasswordForm, GenerateKeyForm, DHKeyExchangeForm, ResetPasswordForm, ResetPasswordRequestForm
)
from crypto_utils import (
    decrypt_file_with_verification, encrypt_file_with_signing, generate_password, generate_rsa_keypair, encrypt_file, decrypt_file, hash_file, compare_hashes,
    ENCRYPTION_METHODS, HASH_METHODS
)

# Configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-for-testing-only')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///crypto_site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload size

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Initialize URLSafeTimedSerializer for generating tokens
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    files = db.relationship('File', backref='owner', lazy=True)
    keys = db.relationship('Key', backref='owner', lazy=True)
    hash_records = db.relationship('HashRecord', backref='owner', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(50), nullable=False)  # 'original', 'encrypted', 'decrypted'
    encryption_method = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    key_id = db.Column(db.Integer, db.ForeignKey('key.id'), nullable=True)

class Key(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    key_type = db.Column(db.String(20), nullable=False)  # 'symmetric', 'asymmetric'
    algorithm = db.Column(db.String(50), nullable=False)  # 'AES-256', 'RSA', etc.
    key_value = db.Column(db.Text, nullable=True)  # For symmetric keys
    public_key = db.Column(db.Text, nullable=True)  # For asymmetric keys
    private_key = db.Column(db.Text, nullable=True)  # For asymmetric keys
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    files = db.relationship('File', backref='key', lazy=True)

class HashRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    hash_value = db.Column(db.String(255), nullable=False)
    hash_method = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class SharedKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    key_id = db.Column(db.Integer, db.ForeignKey('key.id'), nullable=False)
    shared_with = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    shared_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    include_private_key = db.Column(db.Boolean, default=False)  # Added this field
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    key = db.relationship('Key', backref='shared_keys', lazy=True)
    recipient = db.relationship('User', foreign_keys=[shared_with], backref='received_keys', lazy=True)
    sender = db.relationship('User', foreign_keys=[shared_by], backref='shared_keys', lazy=True)

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper Functions
def save_file(file, file_type, encryption_method=None, key_id=None):
    """Save an uploaded file to disk and database"""
    original_filename = secure_filename(file.filename)
    
    # Get extension to include in the saved filename
    file_ext = os.path.splitext(original_filename)[1]
    
    # Create a unique filename including the extension
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    if file_ext:
        # If there's an extension, use it in the stored filename
        base_name = os.path.splitext(original_filename)[0]
        filename = f"{timestamp}_{current_user.id}_{base_name}{file_ext}"
    else:
        # No extension
        filename = f"{timestamp}_{current_user.id}_{original_filename}"
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    # Save the actual file
    file.save(file_path)
    
    # Create database record
    db_file = File(
        filename=filename,
        original_filename=original_filename,
        file_path=file_path,
        file_type=file_type,
        encryption_method=encryption_method,
        user_id=current_user.id,
        key_id=key_id
    )
    
    db.session.add(db_file)
    db.session.commit()
    
    return db_file

def save_key(name, key_type, algorithm, key_value=None, public_key=None, private_key=None):
    """Save a cryptographic key to the database"""
    key = Key(
        name=name,
        key_type=key_type,
        algorithm=algorithm,
        key_value=key_value,
        public_key=public_key,
        private_key=private_key,
        user_id=current_user.id
    )
    
    db.session.add(key)
    db.session.commit()
    
    return key

def get_key_from_request(request_form, key_option_field='key_option'):
    """Extract key information from form submission"""
    key_option = request_form.get(key_option_field, 'new')
    key = None
    key_id = None
    
    if key_option == 'existing':
        existing_key = request_form.get('existing_key', '')
        if existing_key.startswith('sym_'):
            key_id = int(existing_key.split('_')[1])
            key_record = Key.query.get(key_id)
            if key_record:
                key = key_record.key_value
        elif existing_key.startswith('asym_'):
            key_id = int(existing_key.split('_')[1])
            key_record = Key.query.get(key_id)
            if key_record:
                # For asymmetric keys, return public or private key as needed
                if request.path == '/encrypt':
                    key = key_record.public_key
                else:  # decrypt
                    key = key_record.private_key
                    
        # If key_id is set but key is not, it means the key record was not found
        if key_id and not key:
            raise ValueError(f"Key not found with ID {key_id}")
            
    elif key_option == 'manual':
        key = request_form.get('manual_key', '')
        if not key:
            raise ValueError("No key provided in manual key input")
    
    return key, key_id

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('login.html', form=LoginForm())

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        flash('Invalid username or password', 'danger')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
        else:
            user = User(username=form.username.data)
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            flash('Account created successfully. You can now log in.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password_request():
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            token = s.dumps(user.username, salt='password-reset')
            reset_url = url_for('reset_password_token', token=token, _external=True)
            # Replace with email in production
            flash(f'Reset link: {reset_url}', 'info')
        else:
            flash('Username not found', 'danger')
        return redirect(url_for('login'))
    return render_template('reset_request.html', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password_token(token):
    try:
        username = s.loads(token, salt='password-reset', max_age=3600)
    except SignatureExpired:
        flash('The password reset link has expired.', 'danger')
        return redirect(url_for('reset_password_request'))

    user = User.query.filter_by(username=username).first_or_404()
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.password_hash = generate_password_hash(form.new_password.data)
        db.session.commit()
        flash('Your password has been updated.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', form=form)

@app.route('/generate_reset_link')
@login_required
def generate_reset_link():
    token = s.dumps(current_user.username, salt='password-reset')
    reset_url = url_for('reset_password_token', token=token, _external=True)
    flash(f"Password reset link: {reset_url}", "info")
    return redirect(url_for('profile'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    user = current_user

    # Delete user's related data if needed (keys, files, etc.)
    File.query.filter_by(user_id=user.id).delete()
    Key.query.filter_by(user_id=user.id).delete()
    HashRecord.query.filter_by(user_id=user.id).delete()

    # Finally delete the user
    db.session.delete(user)
    db.session.commit()
    logout_user()

    flash("Your account has been permanently deleted.", "success")
    return redirect(url_for('register'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get recent files (last 10)
    recent_files = []
    files = File.query.filter_by(user_id=current_user.id).order_by(File.created_at.desc()).limit(10).all()
    
    for file in files:
        type_class = 'primary'
        if file.file_type == 'encrypted':
            type_class = 'warning'
        elif file.file_type == 'decrypted':
            type_class = 'success'
        
        recent_files.append({
            'filename': file.original_filename,
            'type': file.file_type.capitalize(),
            'type_class': type_class,
            'date': file.created_at.strftime('%Y-%m-%d %H:%M')
        })
    
    return render_template('dashboard.html', recent_files=recent_files)

@app.route('/encrypt', methods=['GET', 'POST'])
@login_required
def encrypt():
    form = EncryptForm()
    
    # Get available keys for the dropdown
    symmetric_keys = Key.query.filter_by(user_id=current_user.id, key_type='symmetric').all()
    asymmetric_keys = Key.query.filter_by(user_id=current_user.id, key_type='asymmetric').all()
    
    # Get public keys shared with the user
    shared_public_keys = []
    shared_keys_records = SharedKey.query.filter_by(shared_with=current_user.id).all()
    for shared in shared_keys_records:
        if shared.key.key_type == 'asymmetric':
            shared_public_keys.append({
                'id': shared.id,
                'name': shared.name,
                'public_key': shared.key.public_key,
                'owner': shared.sender
            })
    
    if form.validate_on_submit():
        file = form.file.data
        encryption_method = form.encryption_method.data
        
        # Check if signing is requested
        signing_key = None
        signing_key_record = None
        if request.form.get('sign_file') == '1':
            signing_key_id = request.form.get('signing_key')
            if signing_key_id:
                try:
                    signing_key_record = Key.query.get(int(signing_key_id))
                    if signing_key_record and signing_key_record.user_id == current_user.id and signing_key_record.key_type == 'asymmetric':
                        signing_key = signing_key_record.private_key
                        print(f"Using signing key: {signing_key_record.name}")
                    else:
                        flash("Invalid signing key selected", "warning")
                except:
                    flash("Error retrieving signing key", "warning")
        
        # Get key based on selected option (only if not signing)
        key = None
        key_id = None
        if not signing_key:
            key_option = request.form.get('key_option', 'new')
            
            if key_option == 'existing':
                existing_key = request.form.get('existing_key', '')
                if existing_key.startswith('sym_'):
                    key_id = int(existing_key.split('_')[1])
                    key_record = Key.query.get(key_id)
                    if key_record:
                        key = key_record.key_value
                elif existing_key.startswith('asym_'):
                    key_id = int(existing_key.split('_')[1])
                    key_record = Key.query.get(key_id)
                    if key_record:
                        key = key_record.public_key
            elif key_option == 'manual':
                key = request.form.get('manual_key', '')
            elif key_option == 'public':
                # Handle using someone's public key
                shared_key_id = request.form.get('shared_key', '')
                if shared_key_id and shared_key_id.startswith('shared_'):
                    shared_id = int(shared_key_id.split('_')[1])
                    shared_record = SharedKey.query.get(shared_id)
                    if shared_record and shared_record.key.key_type == 'asymmetric':
                        key = shared_record.key.public_key
                else:
                    # Use manually entered public key
                    key = request.form.get('public_key_input', '')
        
        # Check if user wants to customize IV
        custom_iv = None
        if request.form.get('customize_iv'):
            if not request.form.get('iv'):
                flash("Custom IV checkbox was selected but no IV was provided. Please enter a valid IV.", "danger")
                return render_template('encrypt.html', form=form, 
                                      symmetric_keys=symmetric_keys, 
                                      asymmetric_keys=asymmetric_keys,
                                      shared_public_keys=shared_public_keys)
                
            try:
                custom_iv = base64.b64decode(request.form.get('iv'))
                # Validate IV length based on encryption method
                if encryption_method.startswith('aes') and len(custom_iv) != 16:
                    flash(f"Invalid IV length for AES: must be exactly 16 bytes, got {len(custom_iv)} bytes.", "danger")
                    return render_template('encrypt.html', form=form, 
                                          symmetric_keys=symmetric_keys, 
                                          asymmetric_keys=asymmetric_keys,
                                          shared_public_keys=shared_public_keys)
                elif encryption_method.startswith('3des') and len(custom_iv) != 8:
                    flash(f"Invalid IV length for 3DES: must be exactly 8 bytes, got {len(custom_iv)} bytes.", "danger")
                    return render_template('encrypt.html', form=form, 
                                          symmetric_keys=symmetric_keys, 
                                          asymmetric_keys=asymmetric_keys,
                                          shared_public_keys=shared_public_keys)
            except Exception as e:
                flash(f"Invalid IV format: {str(e)}. Please provide a valid base64-encoded IV.", "danger")
                return render_template('encrypt.html', form=form, 
                                      symmetric_keys=symmetric_keys, 
                                      asymmetric_keys=asymmetric_keys,
                                      shared_public_keys=shared_public_keys)
        
        # Read file contents
        file_contents = file.read()
        
        # Encrypt the file
        try:
            if signing_key:
                # Use signing functionality
                encrypted_data_json = encrypt_file_with_signing(
                    file_contents, 
                    encryption_method, 
                    key, 
                    signing_key,
                    custom_iv, 
                    original_filename=file.filename
                )
            else:
                # Regular encryption
                encrypted_data_json = encrypt_file(
                    file_contents, 
                    encryption_method, 
                    key, 
                    custom_iv, 
                    original_filename=file.filename
                )
            
            encrypted_data = json.loads(encrypted_data_json)
        except Exception as e:
            flash(f"Encryption failed: {str(e)}", "danger")
            return render_template('encrypt.html', form=form, 
                                  symmetric_keys=symmetric_keys, 
                                  asymmetric_keys=asymmetric_keys,
                                  shared_public_keys=shared_public_keys)
        
        # Save the encrypted file if requested
        if request.form.get('save_output') == '1':
            # Create a temporary file to store the encrypted data
            temp_file = tempfile.NamedTemporaryFile(delete=False)
            temp_file.write(encrypted_data_json.encode())
            temp_file.close()
            
            # Create a file-like object for save_file
            class TempFileObj:
                def __init__(self, path, filename):
                    self.path = path
                    self.filename = filename
                
                def save(self, destination):
                    import shutil
                    shutil.copy(self.path, destination)
            
            encrypted_file_obj = TempFileObj(temp_file.name, f"{os.path.splitext(file.filename)[0]}.encrypted")
            
            # Save to database
            db_file = save_file(
                encrypted_file_obj, 
                'encrypted',
                encryption_method,
                key_id
            )
            
            # Clean up temporary file
            os.unlink(temp_file.name)
            
            # If we generated a new key, save it
            if key_id is None and not signing_key and key_option == 'new' and 'key' in encrypted_data:
                if encryption_method.startswith('aes'):
                    key_name = f"AES-{encryption_method.split('-')[1]}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
                    algorithm = f"AES-{encryption_method.split('-')[1]} ({encryption_method.split('-')[2].upper()} Mode)"
                    key_value = encrypted_data['key']
                    new_key = save_key(key_name, 'symmetric', algorithm, key_value=key_value)
                    key_id = new_key.id
                elif encryption_method == '3des-cbc':
                    key_name = f"3DES-{datetime.now().strftime('%Y%m%d%H%M%S')}"
                    algorithm = "3DES (CBC Mode)"
                    key_value = encrypted_data['key']
                    new_key = save_key(key_name, 'symmetric', algorithm, key_value=key_value)
                    key_id = new_key.id
            elif key_id is None and not signing_key and key_option == 'new' and encryption_method == 'rsa' and 'private_key' in encrypted_data:
                key_name = f"RSA-{datetime.now().strftime('%Y%m%d%H%M%S')}"
                algorithm = "RSA"
                public_key = encrypted_data['public_key']
                private_key = encrypted_data['private_key']
                new_key = save_key(key_name, 'asymmetric', algorithm, public_key=public_key, private_key=private_key)
                key_id = new_key.id
            
            # Provide results to the template
            result = {
                'original_filename': file.filename,
                'encrypted_filename': f"{os.path.splitext(file.filename)[0]}.encrypted",
                'method': ENCRYPTION_METHODS.get(encryption_method, encryption_method),
                'key_id': key_id,
                'file_id': db_file.id
            }
            
            # If we have key details to show
            if not signing_key and key_option == 'new':
                if 'key' in encrypted_data:
                    result['key_value'] = encrypted_data['key']
                elif encryption_method == 'rsa' and 'private_key' in encrypted_data:
                    result['key_value'] = encrypted_data['private_key']
            
            # Add signing info if applicable
            if signing_key:
                result['signed'] = True
                result['signing_key_name'] = signing_key_record.name
            
            return render_template('encrypt.html', form=form, result=result, 
                                   symmetric_keys=symmetric_keys, 
                                   asymmetric_keys=asymmetric_keys,
                                   shared_public_keys=shared_public_keys)
        
    return render_template('encrypt.html', form=form, 
                          symmetric_keys=symmetric_keys, 
                          asymmetric_keys=asymmetric_keys,
                          shared_public_keys=shared_public_keys)

@app.route('/decrypt', methods=['GET', 'POST'])
@login_required
def decrypt():
    form = DecryptForm()

    # Get keys
    symmetric_keys = Key.query.filter_by(user_id=current_user.id, key_type='symmetric').all()
    asymmetric_keys = Key.query.filter_by(user_id=current_user.id, key_type='asymmetric').all()

    shared_public_keys = []
    shared_keys_records = SharedKey.query.filter_by(shared_with=current_user.id).all()
    for shared in shared_keys_records:
        if shared.key.key_type == 'asymmetric':
            shared_public_keys.append({
                'id': shared.id,
                'name': shared.name,
                'public_key': shared.key.public_key,
                'owner': shared.sender
            })

    if form.validate_on_submit():
        if not form.file.data:
            flash("Please select a file to decrypt", "danger")
            return render_template('decrypt.html', form=form, symmetric_keys=symmetric_keys,
                                   asymmetric_keys=asymmetric_keys, shared_public_keys=shared_public_keys)

        file = form.file.data
        is_verification_only = request.form.get('verify_signature') == '1'

        verification_key = None
        verification_key_name = None
        if is_verification_only:
            verification_key_id = request.form.get('verification_key')
            if verification_key_id:
                try:
                    if verification_key_id.startswith('shared_'):
                        shared_id = int(verification_key_id.split('_')[1])
                        shared_record = SharedKey.query.get(shared_id)
                        if shared_record and shared_record.shared_with == current_user.id:
                            verification_key = shared_record.key.public_key
                            verification_key_name = f"{shared_record.name} (from {shared_record.sender.username})"
                    else:
                        verification_key_record = Key.query.get(int(verification_key_id))
                        if verification_key_record and verification_key_record.user_id == current_user.id:
                            verification_key = verification_key_record.public_key
                            verification_key_name = verification_key_record.name
                except Exception as e:
                    flash("Error retrieving verification key", "warning")

        key = None
        key_name = None
        try:
            key_option = request.form.get('key_option', 'existing')

            if key_option == 'existing':
                existing_key = request.form.get('existing_key', '')
                if not existing_key and not is_verification_only:
                    flash("Please select a key", "danger")
                    return render_template('decrypt.html', form=form, symmetric_keys=symmetric_keys,
                                           asymmetric_keys=asymmetric_keys, shared_public_keys=shared_public_keys)
                if existing_key:
                    key_id = int(existing_key.split('_')[1])
                    key_record = Key.query.get(key_id)
                    if not key_record:
                        flash(f"Key not found with ID {key_id}", "danger")
                        return render_template('decrypt.html', form=form, symmetric_keys=symmetric_keys,
                                               asymmetric_keys=asymmetric_keys, shared_public_keys=shared_public_keys)
                    key = key_record.private_key if 'asym_' in existing_key else key_record.key_value
                    key_name = key_record.name
                    key_record.last_used = datetime.utcnow()
                    db.session.commit()

            elif key_option == 'manual':
                key = request.form.get('manual_key', '')
                if not key and not is_verification_only:
                    flash("Please enter a key", "danger")
                    return render_template('decrypt.html', form=form, symmetric_keys=symmetric_keys,
                                           asymmetric_keys=asymmetric_keys, shared_public_keys=shared_public_keys)

            encrypted_data_json = file.read().decode('utf-8')
            encrypted_data = json.loads(encrypted_data_json)

            if 'encryption_method' not in encrypted_data or 'ciphertext' not in encrypted_data:
                flash("Invalid encrypted file format. Missing required encryption data.", "danger")
                return render_template('decrypt.html', form=form, symmetric_keys=symmetric_keys,
                                       asymmetric_keys=asymmetric_keys, shared_public_keys=shared_public_keys)

            encryption_method = encrypted_data.get('encryption_method')

            if verification_key and 'signature' in encrypted_data:
                decryption_result = decrypt_file_with_verification(encrypted_data_json, key, verification_key)
                decrypted_data = decryption_result['data']
                signature_verified = decryption_result['signature_verified']
            else:
                decrypted_data = decrypt_file(encrypted_data_json, key)
                signature_verified = None

            original_filename = file.filename.rsplit('.encrypted', 1)[0]
            if 'original_ext' in encrypted_data:
                original_filename += f".{encrypted_data['original_ext']}"

            save_to_account = request.form.get('save_output') == '1'
            file_id = None
            if save_to_account:
                temp_file = tempfile.NamedTemporaryFile(delete=False)
                temp_file.write(decrypted_data)
                temp_file_path = temp_file.name
                temp_file.close()

                class TempFileObj:
                    def __init__(self, path, filename):
                        self.path = path
                        self.filename = filename
                    def save(self, destination):
                        import shutil
                        shutil.copy(self.path, destination)

                file_obj = TempFileObj(temp_file_path, original_filename)
                db_file = save_file(file_obj, 'decrypted')
                file_id = db_file.id
                os.unlink(temp_file_path)
            else:
                decrypted_file_id = str(uuid.uuid4())
                if 'decrypted_files' not in session:
                    session['decrypted_files'] = {}
                session['decrypted_files'][decrypted_file_id] = {
                    'data': base64.b64encode(decrypted_data).decode('utf-8'),
                    'filename': original_filename,
                    'created_at': datetime.utcnow().isoformat()
                }
                file_id = decrypted_file_id

            result = {
                'original_filename': file.filename,
                'decrypted_filename': original_filename,
                'method': ENCRYPTION_METHODS.get(encryption_method, encryption_method),
                'key_name': key_name,
                'file_id': file_id,
                'is_saved': save_to_account,
                'signature_verified': signature_verified if verification_key else None,
                'verification_key_name': verification_key_name
            }

            flash("File decrypted successfully!", "success")
            return render_template('decrypt.html', form=form, result=result, symmetric_keys=symmetric_keys,
                                   asymmetric_keys=asymmetric_keys, shared_public_keys=shared_public_keys)

        except Exception as e:
            flash(f"An error occurred: {str(e)}", "danger")
            return render_template('decrypt.html', form=form, symmetric_keys=symmetric_keys,
                                   asymmetric_keys=asymmetric_keys, shared_public_keys=shared_public_keys)

    return render_template('decrypt.html', form=form, symmetric_keys=symmetric_keys,
                           asymmetric_keys=asymmetric_keys, shared_public_keys=shared_public_keys)

@app.route('/hash', methods=['GET', 'POST'])
@login_required
def hash_view():
    form = HashForm()
    
    if form.validate_on_submit():
        file = form.file.data
        hash_method = form.hash_method.data
        
        # Read file contents
        file_data = file.read()
        
        # Generate hash
        hash_value = hash_file(file_data, hash_method)
        
        # Save hash record if requested
        if request.form.get('save_hash') == '1':
            hash_record = HashRecord(
                filename=file.filename,
                hash_value=hash_value,
                hash_method=hash_method,
                user_id=current_user.id
            )
            db.session.add(hash_record)
            db.session.commit()
        
        # Provide results to the template
        result = {
            'filename': file.filename,
            'method': HASH_METHODS.get(hash_method, hash_method),
            'hash_value': hash_value
        }
        
        return render_template('hash.html', form=form, result=result)
    
    return render_template('hash.html', form=form)

@app.route('/compare', methods=['GET', 'POST'])
@login_required
def compare_hashes_view():
    form = CompareHashesForm()
    
    # Pre-fill hash1 if provided in query string
    if request.args.get('hash1') and not form.hash1.data:
        form.hash1.data = request.args.get('hash1')
    
    if form.validate_on_submit():
        hash_method = form.hash_method.data
        hash1 = None
        hash2 = None
        
        # Get first hash
        if request.form.get('first_hash_option') == 'file' and form.file1.data:
            file_data = form.file1.data.read()
            hash1 = hash_file(file_data, hash_method)
        elif request.form.get('first_hash_option') == 'value' and form.hash1.data:
            hash1 = form.hash1.data
        
        # Get second hash
        if request.form.get('second_hash_option') == 'file' and form.file2.data:
            file_data = form.file2.data.read()
            hash2 = hash_file(file_data, hash_method)
        elif request.form.get('second_hash_option') == 'value' and form.hash2.data:
            hash2 = form.hash2.data
        
        # Compare hashes
        if hash1 and hash2:
            match = compare_hashes(hash1, hash2)
            
            # Provide results to the template
            result = {
                'method': HASH_METHODS.get(hash_method, hash_method),
                'hash1': hash1,
                'hash2': hash2,
                'match': match
            }
            
            return render_template('compare_hashes.html', form=form, result=result)
        else:
            flash('Please provide two hashes to compare', 'danger')
    
    return render_template('compare_hashes.html', form=form)

@app.route('/keys')
@login_required
def keys():
    symmetric_keys = Key.query.filter_by(user_id=current_user.id, key_type='symmetric').all()
    asymmetric_keys = Key.query.filter_by(user_id=current_user.id, key_type='asymmetric').all()
    
    return render_template('keys.html', symmetric_keys=symmetric_keys, asymmetric_keys=asymmetric_keys)

@app.route('/keys/generate', methods=['GET', 'POST'])
@login_required
def generate_key():
    form = GenerateKeyForm()
    
    if form.validate_on_submit():
        key_type = form.key_type.data
        key_name = request.form.get('key_name')
        
        if not key_name:
            flash('Please provide a name for your key', 'danger')
            return render_template('generate_keys.html', form=form)
        
        new_key = None
        
        if key_type == 'aes-128':
            # Generate AES-128 key
            key_value = base64.b64encode(os.urandom(16)).decode('utf-8')  # 16 bytes = 128 bits
            new_key = save_key(key_name, 'symmetric', 'AES-128', key_value=key_value)
        
        elif key_type == 'aes-256':
            # Generate AES-256 key
            key_value = base64.b64encode(os.urandom(32)).decode('utf-8')  # 32 bytes = 256 bits
            new_key = save_key(key_name, 'symmetric', 'AES-256', key_value=key_value)
        
        elif key_type == '3des':
            # Generate 3DES key (192 bits)
            key_value = base64.b64encode(os.urandom(24)).decode('utf-8')  # 24 bytes = 192 bits
            new_key = save_key(key_name, 'symmetric', '3DES (CBC Mode)', key_value=key_value)
        
        elif key_type == 'rsa':
            # Generate RSA keypair
            key_size = int(form.key_size.data)
            keypair = generate_rsa_keypair(key_size=key_size)
            new_key = save_key(
                key_name, 
                'asymmetric', 
                f'RSA-{key_size}', 
                public_key=keypair['public_key'],
                private_key=keypair['private_key']
            )
        
        flash('Key generated successfully', 'success')
        return render_template('generate_keys.html', form=form, new_key=new_key)
    
    return render_template('generate_keys.html', form=form)

@app.route('/keys/<int:key_id>/download')
@login_required
def download_key(key_id):
    key = Key.query.get_or_404(key_id)
    
    # Ensure current user owns the key
    if key.user_id != current_user.id:
        flash('Access denied', 'danger')
        return redirect(url_for('keys'))
    
    # Prepare key content for download
    if key.key_type == 'symmetric':
        content = key.key_value
        filename = f"{key.name}_key.txt"
    else:  # asymmetric
        content = f"PUBLIC KEY:\n{key.public_key}\n\nPRIVATE KEY:\n{key.private_key}"
        filename = f"{key.name}_keypair.txt"
    
    # Create BytesIO object
    key_io = BytesIO(content.encode('utf-8'))
    
    # Send file
    return send_file(
        key_io,
        as_attachment=True,
        download_name=filename,
        mimetype='text/plain'
    )

@app.route('/keys/<int:key_id>/delete')
@login_required
def delete_key(key_id):
    key = Key.query.get_or_404(key_id)
    
    # Ensure current user owns the key
    if key.user_id != current_user.id:
        flash('Access denied', 'danger')
        return redirect(url_for('keys'))
    
    # Check if key is used by any files
    if key.files:
        flash('Cannot delete key that is used by files', 'danger')
        return redirect(url_for('keys'))
    
    # Delete key
    db.session.delete(key)
    db.session.commit()
    
    flash('Key deleted successfully', 'success')
    return redirect(url_for('keys'))

@app.route('/files')
@login_required
def files():
    user_files = File.query.filter_by(user_id=current_user.id).order_by(File.created_at.desc()).all()
    return render_template('files.html', files=user_files)

@app.route('/files/<int:file_id>/download')
@login_required
def download_file(file_id):
    file = File.query.get_or_404(file_id)
    
    # Ensure current user owns the file
    if file.user_id != current_user.id:
        flash('Access denied', 'danger')
        return redirect(url_for('files'))
    
    # Send file
    return send_file(
        file.file_path,
        as_attachment=True,
        download_name=file.original_filename
    )

@app.route('/download_decrypted/<file_id>')
@login_required
def download_decrypted(file_id):
    # Check if this is a database file or a session file
    if file_id.isdigit():
        # This is a database file
        file = File.query.get_or_404(int(file_id))
        
        # Ensure current user owns the file
        if file.user_id != current_user.id:
            flash('Access denied', 'danger')
            return redirect(url_for('decrypt'))
        
        # Send file with original filename
        return send_file(
            file.file_path,
            as_attachment=True,
            download_name=file.original_filename
        )
    else:
        # This is a session file
        decrypted_files = session.get('decrypted_files', {})
        if file_id not in decrypted_files:
            flash('File not found or expired', 'danger')
            return redirect(url_for('decrypt'))
        
        file_data = decrypted_files[file_id]
        binary_data = base64.b64decode(file_data['data'])
        
        # Create BytesIO object
        file_io = BytesIO(binary_data)
        
        # Get file extension for mimetype detection
        filename = file_data['filename']
        
        # Send file with original filename
        return send_file(
            file_io,
            as_attachment=True,
            download_name=filename,
            # Let the browser determine the mimetype based on the file extension
            mimetype=None  
        )

@app.route('/files/<int:file_id>/delete')
@login_required
def delete_file(file_id):
    file = File.query.get_or_404(file_id)
    
    # Ensure current user owns the file
    if file.user_id != current_user.id:
        flash('Access denied', 'danger')
        return redirect(url_for('files'))
    
    # Delete file from disk
    if os.path.exists(file.file_path):
        os.remove(file.file_path)
    
    # Delete from database
    db.session.delete(file)
    db.session.commit()
    
    flash('File deleted successfully', 'success')
    return redirect(url_for('files'))

@app.route('/password_generator', methods=['GET', 'POST'])
@login_required
def password_generator():
    form = GeneratePasswordForm()
    password = None
    
    if form.validate_on_submit():
        length = form.length.data
        password = generate_password(length)
    
    return render_template('password_generator.html', form=form, password=password)

@app.route('/shared_keys', methods=['GET', 'POST'])
@login_required
def shared_keys():
    # Get keys shared with current user
    received_keys = SharedKey.query.filter_by(shared_with=current_user.id).all()
    
    # Get keys shared by current user
    shared_by_me = SharedKey.query.filter_by(shared_by=current_user.id).all()
    
    # Handle new key sharing
    if request.method == 'POST':
        key_id = request.form.get('key_id')
        username = request.form.get('username')
        share_name = request.form.get('share_name')
        include_private_key = 'include_private_key' in request.form  # Check if private key should be included
        
        if not all([key_id, username, share_name]):
            flash('All fields are required', 'danger')
        else:
            user = User.query.filter_by(username=username).first()
            if not user:
                flash('User not found', 'danger')
            elif user.id == current_user.id:
                flash('You cannot share keys with yourself', 'danger')
            else:
                key = Key.query.get(key_id)
                if not key or key.user_id != current_user.id:
                    flash('Invalid key', 'danger')
                else:
                    # Check if already shared
                    existing = SharedKey.query.filter_by(
                        key_id=key_id, shared_with=user.id, shared_by=current_user.id
                    ).first()
                    
                    if existing:
                        flash('Key already shared with this user', 'danger')
                    else:
                        # Create new shared key
                        shared_key = SharedKey(
                            name=share_name,
                            key_id=key_id,
                            shared_with=user.id,
                            shared_by=current_user.id,
                            include_private_key=include_private_key  # Set this based on the checkbox
                        )
                        db.session.add(shared_key)
                        db.session.commit()
                        
                        # Create a success message based on the key type
                        if key.key_type == 'asymmetric':
                            if include_private_key:
                                flash('Key pair (public and private) shared successfully', 'success')
                            else:
                                flash('Public key shared successfully', 'success')
                        else:
                            flash('Key shared successfully', 'success')
                            
                        return redirect(url_for('shared_keys'))
    
    # Get all shareable keys owned by current user
    keys = Key.query.filter_by(user_id=current_user.id).all()
    
    return render_template('shared_keys.html', 
                          received_keys=received_keys, 
                          shared_by_me=shared_by_me,
                          keys=keys)

@app.route('/shared_keys/<int:shared_key_id>/revoke')
@login_required
def revoke_shared_key(shared_key_id):
    shared_key = SharedKey.query.get_or_404(shared_key_id)
    
    # Ensure current user owns the shared key
    if shared_key.shared_by != current_user.id:
        flash('Access denied', 'danger')
        return redirect(url_for('shared_keys'))
    
    # Delete shared key
    db.session.delete(shared_key)
    db.session.commit()
    
    flash('Key sharing revoked successfully', 'success')
    return redirect(url_for('shared_keys'))

@app.route('/import_key', methods=['GET', 'POST'])
@login_required
def import_key():
    if request.method == 'POST':
        key_name = request.form.get('key_name')
        key_type = request.form.get('key_type')
        
        if not key_name or not key_type:
            flash('Please provide a name and type for your key', 'danger')
            return redirect(url_for('import_key'))
        
        try:
            if key_type in ['aes-128', 'aes-256', '3des']:  # Symmetric keys
                # Try to get key from textarea or file
                key_value = request.form.get('symmetric_key')
                key_file = request.files.get('key_file')
                
                if key_file and key_file.filename:
                    key_value = key_file.read().decode('utf-8').strip()
                
                if not key_value:
                    flash('Please provide a key value', 'danger')
                    return redirect(url_for('import_key'))
                
                # Try to decode the base64 value to check it
                try:
                    decoded_key = base64.b64decode(key_value)
                    
                    # Check key length
                    if key_type == 'aes-128' and len(decoded_key) != 16:
                        flash('AES-128 key must be 16 bytes (128 bits)', 'danger')
                        return redirect(url_for('import_key'))
                    elif key_type == 'aes-256' and len(decoded_key) != 32:
                        flash('AES-256 key must be 32 bytes (256 bits)', 'danger')
                        return redirect(url_for('import_key'))
                    elif key_type == '3des' and len(decoded_key) != 24:
                        flash('3DES key must be 24 bytes (192 bits)', 'danger')
                        return redirect(url_for('import_key'))
                except:
                    flash('Invalid base64-encoded key value', 'danger')
                    return redirect(url_for('import_key'))
                
                # Save the key
                if key_type == 'aes-128':
                    algorithm = 'AES-128'
                elif key_type == 'aes-256':
                    algorithm = 'AES-256'
                else:  # 3des
                    algorithm = '3DES (CBC Mode)'
                
                new_key = save_key(key_name, 'symmetric', algorithm, key_value=key_value)
                
            elif key_type in ['rsa', 'dh']:  # Asymmetric keys
                # Try to get keys from textareas or file
                public_key = request.form.get('public_key')
                private_key = request.form.get('private_key')
                keypair_file = request.files.get('keypair_file')
                
                if keypair_file and keypair_file.filename:
                    # Try to parse the keypair file
                    keypair_content = keypair_file.read().decode('utf-8').strip()
                    
                    # Basic parsing - assumes "PUBLIC KEY:" and "PRIVATE KEY:" markers
                    if 'PUBLIC KEY:' in keypair_content and 'PRIVATE KEY:' in keypair_content:
                        parts = keypair_content.split('PRIVATE KEY:')
                        public_part = parts[0].split('PUBLIC KEY:')[1].strip()
                        private_part = parts[1].strip()
                        
                        public_key = public_part
                        private_key = private_part
                
                if not public_key:
                    flash('Please provide at least a public key', 'danger')
                    return redirect(url_for('import_key'))
                
                # Save the key
                if key_type == 'rsa':
                    algorithm = 'RSA'
                else:  # dh
                    algorithm = 'Diffie-Hellman'
                
                new_key = save_key(key_name, 'asymmetric', algorithm, 
                                  public_key=public_key, private_key=private_key)
            
            flash('Key imported successfully', 'success')
            return redirect(url_for('keys'))
            
        except Exception as e:
            flash(f'Error importing key: {str(e)}', 'danger')
            return redirect(url_for('import_key'))
    
    return render_template('import_key.html')

@app.route('/reset_password')
def reset_password():
    # Placeholder for password reset functionality
    flash('Password reset functionality is not implemented yet.', 'info')
    return redirect(url_for('login'))

# Create database tables
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)