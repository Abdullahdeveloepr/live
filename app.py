from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
import base64
import os

app = Flask(__name__)
app.config.from_object('config.Config')
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    decryption_key = db.Column(db.String(256), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        self.decryption_key = Fernet.generate_key().decode()

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Update the load_user function to set the decryption key when loading the user
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Image model
class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.Text, nullable=False)
    encrypted = db.Column(db.Boolean, default=True)

# IP Blocking
from collections import defaultdict

BLOCK_TIME = 300  # 5 minutes

blocked_ips = defaultdict(int)

@app.before_request
def block_ddos():
    if request.remote_addr:
        if blocked_ips[request.remote_addr] > 5:
            return "Too many requests from your IP. Please try again later.", 429
        elif blocked_ips[request.remote_addr] > 0:
            blocked_ips[request.remote_addr] -= 1
        elif len(blocked_ips) > 1000:  # Limit the number of blocked IPs to avoid memory issues
            blocked_ips.popitem()
    
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            try:
                # Handle image processing here if needed
                flash('Image processing completed successfully!')
            except Exception as e:
                flash('Error processing image: ' + str(e))

            return redirect(url_for('index'))

    images = Image.query.all()
    decrypted_images = []
    for image in images:
        try:
            decrypted_data = Fernet(current_user.decryption_key).decrypt(base64.b64decode(image.data))
            decrypted_images.append(base64.b64encode(decrypted_data).decode('utf-8'))
        except Exception as e:
            print(f"Error decrypting image ID {image.id}: {e}")
            flash('An error occurred while decrypting images.')
            decrypted_images.append(None)

    # Filter out None values from decrypted images
    decrypted_images = [img for img in decrypted_images if img is not None]
    image_info_pairs = zip(decrypted_images, images)

    return render_template('index.html', image_info_pairs=image_info_pairs)

@app.route('/delete-image/<int:image_id>', methods=['DELETE'])
@login_required
def delete_image(image_id):
    image = Image.query.get(image_id)
    if image:
        db.session.delete(image)
        db.session.commit()
        return jsonify({'message': 'Image deleted successfully'})
    else:
        return jsonify({'message': 'Image not found'}), 404

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            encrypted_data = Fernet(current_user.decryption_key).encrypt(file.read())
            encoded_img = base64.b64encode(encrypted_data).decode('utf-8')
            new_image = Image(data=encoded_img, encrypted=True)
            db.session.add(new_image)
            db.session.commit()
            flash('Image uploaded successfully!')
            return redirect(url_for('index'))
        else:
            flash('No file selected!')
    return render_template('upload.html')

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        # Verify current password
        if not current_user.check_password(current_password):
            flash('Incorrect current password!')
            return redirect(url_for('change_password'))
        
        # Check if new password matches the confirmation
        if new_password != confirm_password:
            flash('New password and confirm password do not match!')
            return redirect(url_for('change_password'))
        
        # Update the password
        current_user.set_password(new_password)
        db.session.commit()
        flash('Password updated successfully!')
        return redirect(url_for('index'))
    
    return render_template('change_password.html')

@app.route('/deleteImage/<int:id>', methods=['GET', 'POST'])
@login_required
def deleteImage(id):
    query = Image.query.filter_by(id=id).first()
    if query:
        db.session.delete(query)
        db.session.commit()
    return redirect('/')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
       
    app.run(debug=True)
