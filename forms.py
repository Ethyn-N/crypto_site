from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import BooleanField, StringField, PasswordField, SubmitField, SelectField, TextAreaField, IntegerField
from wtforms.validators import DataRequired, Length, EqualTo, Optional, NumberRange
from datetime import datetime

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class EncryptForm(FlaskForm):
    file = FileField('File to Encrypt', validators=[FileRequired()])
    encryption_method = SelectField('Encryption Method', choices=[
        ('aes-128-cbc', 'AES-128 (CBC Mode)'),
        ('aes-256-cbc', 'AES-256 (CBC Mode)'),
        ('aes-128-ctr', 'AES-128 (CTR Mode)'),
        ('aes-256-ctr', 'AES-256 (CTR Mode)'),
        ('3des-cbc', '3DES (CBC Mode)'),
        ('rsa', 'RSA Public/Private Key')
    ])
    sign_file = BooleanField('Sign file with my private key (for authentication)', default=False)
    key = TextAreaField('Key (Optional - Leave blank to generate new key)', validators=[Optional()])
    submit = SubmitField('Encrypt')

class DecryptForm(FlaskForm):
    file = FileField('Encrypted File', validators=[FileRequired()])
    verify_signature = BooleanField('Verify file signature (if signed)', default=True)
    key = TextAreaField('Decryption Key', validators=[Optional()])
    submit = SubmitField('Decrypt')

class HashForm(FlaskForm):
    file = FileField('File to Hash', validators=[FileRequired()])
    hash_method = SelectField('Hash Method', choices=[
        ('sha256', 'SHA-256'),
        ('sha384', 'SHA-384'),
        ('sha512', 'SHA-512'),
        ('sha3-256', 'SHA3-256'),
        ('sha3-512', 'SHA3-512')
    ])
    save_hash = BooleanField('Save hash result to my account')
    submit = SubmitField('Generate Hash')

class CompareHashesForm(FlaskForm):
    file1 = FileField('First File', validators=[FileRequired()])
    file2 = FileField('Second File', validators=[Optional()])
    hash1 = StringField('Or Enter First Hash', validators=[Optional()])
    hash2 = StringField('Or Enter Second Hash', validators=[Optional()])
    hash_method = SelectField('Hash Method', choices=[
        ('sha256', 'SHA-256'),
        ('sha384', 'SHA-384'),
        ('sha512', 'SHA-512'),
        ('sha3-256', 'SHA3-256'),
        ('sha3-512', 'SHA3-512')
    ])
    submit = SubmitField('Compare Hashes')

class GeneratePasswordForm(FlaskForm):
    length = IntegerField('Password Length', validators=[DataRequired(), NumberRange(min=8, max=64)], default=12)
    submit = SubmitField('Generate Password')

class GenerateKeyForm(FlaskForm):
    key_type = SelectField('Key Type', choices=[
        ('aes-128', 'AES-128'),
        ('aes-256', 'AES-256'),
        ('3des', '3DES'),
        ('rsa', 'RSA')
    ])
    key_size = SelectField('Key Size (for RSA)', choices=[
        ('2048', '2048 bits'),
        ('3072', '3072 bits'),
        ('4096', '4096 bits')
    ])
    submit = SubmitField('Generate Key')

class DHKeyExchangeForm(FlaskForm):
    peer_public_key = TextAreaField('Peer\'s Public Key', validators=[DataRequired()])
    submit = SubmitField('Compute Shared Key')

class ResetPasswordRequestForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Reset Password')

