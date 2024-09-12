from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, Response
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
import os,io
from werkzeug.utils import secure_filename
from app_setup import create_app
import cloudinary
import cloudinary.uploader
import cloudinary.api
from firebase_admin import credentials, auth, initialize_app
import firebase_admin
from datetime import datetime
import requests
from gradio_client import Client


cred = credentials.Certificate("./static/sova-57ac2-firebase-adminsdk-guzzz-2dde9de2e0.json")
firebase_admin.initialize_app(cred)
cloudinary.config(
    cloud_name='divgroq7w',  # Replace with your actual Cloud Name
    api_key='838392239743134',        # Replace with your actual API Key
    api_secret='03yYZMcRf12K6JnHMQUm_yjno34'   # Replace with your actual API Secret
)
app, mongo, users_collection = create_app()

app = Flask(__name__)
app.secret_key = 'your_secret_key' 


from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
uri = "mongodb+srv://mishrashashank006:zsStLs8qzkMeYrOx@vita.ftfzw.mongodb.net/"
# Create a new client and connect to the server

# client = MongoClient('localhost', 27018)
client = MongoClient(uri)
db = client['user_database']
users_collection = db['users']
chat_images_collection = db['chat_images']
sessions_collection = db['sessions']
comment_collection = db['comment']
feedback_collection=db['feedback'] 
# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'shawmishra@gmail.com'  # Your Gmail address
app.config['MAIL_PASSWORD'] = 'lcrfavndzjsqlapj'     # Your Gmail App Password
app.config['MAIL_DEFAULT_SENDER'] = 'shawmishra@gmail.com'
app.config['APP_URL'] = 'http://your-app-url.com'
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024
mail = Mail(app)
s = URLSafeTimedSerializer(app.secret_key)


ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

collection = db['chat_history']

import logging

@app.route('/save-chat-history', methods=['POST'])
def save_chat_history():
    data = request.json
    email = data.get('email')

    if not email:
        return jsonify({'error': 'Email is required'}), 400

    chat_history = {
        'email': email,
        'messages': data.get('messages', []),
        'agentMessages': data.get('agentMessages', []),
        'timestamp': datetime.utcnow()
    }

    # Debugging logs to check received data
    logging.info(f"Saving chat history for email: {email}")
    logging.info(f"Messages: {chat_history['messages']}")
    logging.info(f"Agent Messages: {chat_history['agentMessages']}")

    try:
        # Insert the chat history into MongoDB
        result = collection.insert_one(chat_history)
        logging.info(f"Inserted document ID: {result.inserted_id}")

        return jsonify({'message': 'Chat history saved successfully'}), 200
    except Exception as e:
        logging.error(f"Error saving chat history: {str(e)}")
        return jsonify({'error': 'Failed to save chat history'}), 500


@app.route('/get-session/<session_id>', methods=['GET'])
def get_session(session_id):
    # Retrieve the session data from MongoDB
    session_data = sessions_collection.find_one({"sessionId": session_id})

    if not session_data:
        return jsonify({"status": "error", "message": "Session not found"}), 404

    return jsonify(session_data), 200
@app.route('/register_new', methods=['GET', 'POST'])
def register_new():
    email = request.args.get('email', '')  # Get the email from query params
    
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        username = request.form['username']
        gender = request.form['gender']
        password = request.form['password']
        confirm = request.form['confirm']
        email = request.form['email']  # Get the email from the form

        # Check if the passwords match
        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register_new', email=email))

        # Check if user already exists
        existing_user = users_collection.find_one({"email": email})
        if existing_user:
            flash('An account with this email already exists.', 'danger')
            return redirect(url_for('register_new', email=email))

        # Hash the password before storing it in the database
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Create the user document with default values
        user_data = {
            "first_name": first_name,
            "last_name": last_name,
            "username": username,
            "email": email,
            "gender": gender,
            "password": hashed_password,
            "active": True,  # User is set as active
            "illness": "NA",
            "allergies": "NA",
            "medication": "NA",
            "profile_picture": ""  # Set default profile picture
        }

        # Insert the user data into the database
        users_collection.insert_one(user_data)

        # Retrieve the inserted user data
        user = users_collection.find_one({"email": email})

        # Store user information in session
        session['username'] = user['username']
        session['email'] = user['email']

        # Redirect the user to the home page
        return redirect(url_for('home'))

    # Render the registration form with the email (if any)
    return render_template('register_new.html', email=email)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        username = request.form['username']
        email = request.form['email']  
        gender = request.form['gender']
        password = request.form['password']
        confirm = request.form['confirm']

        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))

        # Check if user already exists
        existing_user = users_collection.find_one({"email": email})
        if existing_user:
            flash('An account with this email already exists.', 'danger')
            return redirect(url_for('register'))

        # Hash the password before storing it in the database
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Generate a token for email verification
        token = s.dumps(email, salt='email-confirmation')

        # Create the user document with default values
        user_data = {
            "first_name": first_name,
            "last_name": last_name,
            "username": username,
            "email": email,
            "gender": gender,
            "password": hashed_password,
            "active": False,  # User is inactive until they verify their email
            "illness": "NA",
            "allergies": "NA",
            "medication": "NA",
            "profile_picture": ""  # Set default profile picture
        }

        # Insert the user data into the database
        users_collection.insert_one(user_data)

        # Send the verification email
        confirm_url = url_for('confirm_email', token=token, _external=True)
        html = render_template('activate.html', confirm_url=confirm_url)
        msg = Message('Please confirm your email address', recipients=[email])
        msg.html = html
        mail.send(msg)

        # Redirect to a page instructing the user to check their email
        flash('A confirmation email has been sent. Please check your email to activate your account.', 'info')
        return redirect(url_for('check_your_email'))

    return render_template('register.html')

@app.route('/')
def index():
    return render_template('index.html')
@app.route('/submit_msg', methods=['POST'])
def submit_form():
    data = request.get_json()  # Get the form data in JSON format
    
    name = data.get('name')
    email = data.get('email')
    subject = data.get('subject')
    message = data.get('message')
    
    # Save the data in MongoDB
    comment_collection.insert_one({
        'name': name,
        'email': email,
        'subject': subject,
        'message': message
    })

    return jsonify({'status': 'success', 'message': 'Form data stored successfully!'}), 200
@app.route('/check_your_email')
def check_your_email():
    return render_template('check_your_email.html')

@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirmation', max_age=3600)
    except SignatureExpired:
        flash('The confirmation link has expired.', 'danger')
        return redirect(url_for('login'))
    except BadTimeSignature:
        flash('Invalid confirmation link.', 'danger')
        return redirect(url_for('login'))

    # Activate the user account
    users_collection.update_one({"email": email}, {"$set": {"active": True}})
    flash('Your account has been activated! You can now log in.', 'success')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Fetch the user from the database
        user = users_collection.find_one({"email": email})

        if user and check_password_hash(user['password'], password):
            if not user.get("active"):
                flash('Please confirm your email address to activate your account.', 'danger')
                return redirect(url_for('login'))

            # Set the session with username
            session['username'] = user['username']
            session['email'] = user['email']
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/firebase_login', methods=['POST'])
def firebase_login():
    data = request.get_json()
    token = data.get('token')
    
    try:
        decoded_token = auth.verify_id_token(token)
        print(decoded_token)
        email = decoded_token['email']
        print(email)
        
        user = users_collection.find_one({'email': email})
        
        if user:
            session['email'] = email
            response = {"success": True, "redirect": url_for('home')}
        else:
            # User does not exist, redirect to register
            response = {"success": False, "redirect": url_for('register_new', email=email)}
        
        print(f"Response: {response}")
        return jsonify(response)
    
    except Exception as e:
        print(f"Error verifying token: {e}")
        return jsonify({"success": False, "error": str(e)})
    
    

@app.route('/home')
def home():
    if 'email' in session:
        email = session['email']
        user = users_collection.find_one({'email': email})
        return render_template('home.html', user=user)
    else:
        print("Redirecting to login because email not in session.")
        return redirect(url_for('login'))


@app.route('/submit-feedback', methods=['POST'])
def submit_feedback():
    if 'email' not in session:
        return jsonify({'category': 'danger', 'message': 'You must be logged in to submit feedback.'}), 403

    # Get feedback data from the form
    csat = request.form.get('csat')
    feedback_text = request.form.get('feedbackText')
    email = session['email']
    timestamp = datetime.utcnow()

    # Prepare the feedback data to store in MongoDB
    feedback_data = {
        'email': email,
        'csat': csat,
        'feedback_text': feedback_text,
        'timestamp': timestamp
    }

    # Insert into MongoDB collection
    feedback_collection.insert_one(feedback_data)

    return jsonify({'category': 'success', 'message': 'Thank you for your feedback!'}), 200
@app.route('/about')
def about():
    if 'email' in session:
        email = session['email']
        user = users_collection.find_one({'email': email})
        return render_template('about.html', user=user)
    else:
        return redirect(url_for('login'))

@app.route('/history')
def history():
    if 'email' in session:
        email = session['email']
        user = users_collection.find_one({'email': email})
        
        # Assuming user's email is used to match disease data
        email = user.get('email')
        
        if email:
            # Fetch disease data from the chat_images collection
            disease_data = chat_images_collection.find({'email': email})
            disease_data = list(disease_data)
        else:
            disease_data = []

        return render_template('history.html', user=user, disease_data=disease_data)
    else:
        return redirect(url_for('login'))





# gradio_client = Client("https://shashankvns-test-deploy.hf.space/")

def predict_image(image_url):
    try:
        # Use Gradio client to predict
        # result = gradio_client.predict(image_url, api_name="/predict")
        result=1
        return result
    except Exception as e:
        return {"error": str(e)}
    
import json

def predict_image(image_url):
    # Assuming you have a Gradio client that makes a prediction
    result_file_path = gradio_client.predict(image_url)
    
    # Read the result from the file path
    with open(result_file_path, 'r') as file:
        result = json.load(file)
    
    # Return the result as a dictionary
    return result


@app.route('/upload_disease', methods=['POST'])
def upload_image():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"})
    
    if file:
        try:
            # Upload image to Cloudinary
            upload_result = cloudinary.uploader.upload(file)
            image_url = upload_result['url']

            # Get prediction using the image URL
            predictions = predict_image(image_url)

            # Store the URL, prediction result, and user email in MongoDB
            email = session.get('email')  # Retrieve email from session
            timestamp = datetime.utcnow().isoformat()
            
            if not email:
                return jsonify({"error": "Email not found in session"})

            # Create a new document for each upload
            upload_data = {
                'email': email,
                'image_url': image_url,
                'timestamp': timestamp,
                'predictions': predictions
            }

            # Insert a new document into MongoDB
            result = chat_images_collection.insert_one(upload_data)

            # Return predictions to the front end
            return jsonify({
                '_id': str(result.inserted_id),
                'image_url': image_url,
                'predictions': predictions
            })

        except Exception as e:
            return jsonify({"error": str(e)})
    else:
        return jsonify({"error": "File upload failed"})
@app.route('/newchat', methods=['GET', 'POST'])
def newchat():
    if 'username' in session:
        email = session['email']
        user = users_collection.find_one({'email': email})

        if request.method == 'POST':
            if 'disease_image' not in request.files:
                flash('No file selected.', 'danger')
                return redirect(url_for('newchat'))

            file = request.files['disease_image']
            if file.filename == '':
                flash('No selected file.', 'danger')
                return redirect(url_for('newchat'))

            if file:
                try:
                    # Upload to Cloudinary
                    upload_result = cloudinary.uploader.upload(file)
                    image_url = upload_result['url']
                    timestamp = datetime.isoformat()

                    # Get prediction for the uploaded image
                    predictions = predict_image(image_url)

                    # Prepare data for updating MongoDB
                    email = user['email']
                    update_data = {
                        'image_url': image_url,
                        'timestamp': timestamp,
                        'predictions': predictions
                    }

                    # Update or create the document in MongoDB
                    chat_images_collection.update_one(
                        {'email': email},
                        {'$set': update_data},
                        upsert=True
                    )

                    flash('Image uploaded and data stored successfully!', 'success')
                except Exception as e:
                    flash(f'Error uploading file: {str(e)}', 'danger')

            return redirect(url_for('newchat'))

        return render_template('newchat.html', user=user)
    else:
        return redirect(url_for('login'))



@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'email' in session:
        email = session['email']
        user = users_collection.find_one({"email": email})

        if request.method == 'POST':
            update_fields = {}

            # Handle profile picture upload
            if 'profile_picture' in request.files:
                file = request.files['profile_picture']
                if file and allowed_file(file.filename):
                    file_size = len(file.read())
                    file.seek(0)  # Reset file pointer after size check
                    if file_size > app.config['MAX_CONTENT_LENGTH']:
                        flash('File size exceeds 10 MB limit.', 'danger')
                    else:
                        try:
                            # Upload to Cloudinary
                            upload_result = cloudinary.uploader.upload(file)
                            image_url = upload_result['url']

                            # Delete old profile picture if it exists
                            old_picture = user.get('profile_picture', 'user.jpg')
                            if old_picture and old_picture != 'user.jpg':
                                old_picture_public_id = old_picture.rsplit('/', 1)[-1].split('.')[0]
                                cloudinary.uploader.destroy(old_picture_public_id)

                            # Update the new profile picture URL in the database
                            update_fields['profile_picture'] = image_url
                        except Exception as e:
                            flash(f'Error uploading file: {str(e)}', 'danger')

            # Handle other profile updates
            allergies = request.form.get('allergies')
            illness = request.form.get('illness')
            medication = request.form.get('medication')

            if allergies:
                update_fields['allergies'] = allergies
            if illness:
                update_fields['illness'] = illness
            if medication:
                update_fields['medication'] = medication

            if update_fields:
                users_collection.update_one(
                    {"email": email},
                    {"$set": update_fields}
                )
                flash('Profile updated successfully!', 'success')

        # Render the profile page with user data
        return render_template('profile.html', user=user)
    else:
        return redirect(url_for('login'))

@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'email' in session:
        email = session['email']
        
        user = users_collection.find_one({"email": email})

        update_fields = {}

        # Check if MAX_CONTENT_LENGTH is set in app.config
        max_content_length = app.config.get('MAX_CONTENT_LENGTH')
        if max_content_length is None:
            return jsonify({'status': 'error', 'message': 'Configuration error: MAX_CONTENT_LENGTH not set'}), 500

        # Handle profile picture upload
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and allowed_file(file.filename):
                file_size = len(file.read())
                file.seek(0)  # Reset file pointer after size check
                if file_size > max_content_length:
                    return jsonify({'status': 'error', 'message': 'File size exceeds 10 MB limit'}), 400

                try:
                    # Upload to Cloudinary
                    upload_result = cloudinary.uploader.upload(file)
                    image_url = upload_result['url']

                    # Delete old profile picture if it exists
                    old_picture = user.get('profile_picture', 'user.png')
                    if old_picture and old_picture != "user.png":
                        old_picture_public_id = old_picture.rsplit('/', 1)[-1].split('.')[0]
                        cloudinary.uploader.destroy(old_picture_public_id)

                    # Update the new profile picture URL in the database
                    update_fields['profile_picture'] = image_url
                except Exception as e:
                    return jsonify({'status': 'error', 'message': f'Error uploading file: {str(e)}'}), 500

        # Handle other profile updates
        allergies = request.form.get('allergies')
        illness = request.form.get('illness')
        medication = request.form.get('medication')

        if allergies:
            update_fields['allergies'] = allergies
        if illness:
            update_fields['illness'] = illness
        if medication:
            update_fields['medication'] = medication

        if update_fields:
            users_collection.update_one(
                {"email": email},
                {"$set": update_fields}
            )

        return jsonify({
            'status': 'success',
            'message': 'Profile updated successfully!',
            'profile_picture': update_fields.get('profile_picture', user.get('profile_picture')),
            'allergies': update_fields.get('allergies', user.get('allergies')),
            'illness': update_fields.get('illness', user.get('illness')),
            'medication': update_fields.get('medication', user.get('medication')),
        })
    else:
        return jsonify({'status': 'error', 'message': 'User not logged in'}), 401
@app.route('/recommend', methods=['POST'])
def recommend():
    if 'email' in session:
        name = request.form['recommendName']
        email = request.form['recommendEmail']
        username = session['username']
        app_url = app.config['APP_URL']
        
        email_body = render_template(
            'recommend.html', 
            name=name, 
            username=username, 
            app_url=app_url
        )

        msg = Message(
            subject=f"Recommendation from {username}",
            recipients=[email],
            html=email_body
        )

        try:
            mail.send(msg)
            response = {
                'message': 'Recommendation sent successfully!',
                'category': 'success'
            }
        except Exception as e:
            response = {
                'message': f'Failed to send recommendation. Error: {str(e)}',
                'category': 'danger'
            }

    else:
        response = {
            'message': 'You need to log in to send a recommendation.',
            'category': 'warning'
        }

    return jsonify(response)




@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('logout_page'))

@app.route('/logout_page')
def logout_page():
    return render_template('logout.html')

@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form['email']
        user = users_collection.find_one({"email": email})

        if user:
            token = s.dumps(email, salt='password-reset')
            reset_url = url_for('reset_password', token=token, _external=True)
            html = render_template('reset_password_email.html', reset_url=reset_url)
            msg = Message('Reset Your Password', recipients=[email])
            msg.html = html
            mail.send(msg)

        # Redirect to a page instructing the user to check their email
        return redirect(url_for('check_your_email'))

    return render_template('reset_password_request.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset', max_age=3600)
    except SignatureExpired:
        flash('The reset link has expired.', 'danger')
        return redirect(url_for('reset_password_request'))
    except BadTimeSignature:
        flash('Invalid token.', 'danger')
        return redirect(url_for('reset_password_request'))

    if request.method == 'POST':
        new_password = request.form['password']
        hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
        users_collection.update_one({"email": email}, {"$set": {"password": hashed_password}})
        flash('Your password has been updated!', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html')

if __name__ == '__main__':
    app.run(debug=True)

