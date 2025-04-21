from flask import Flask, render_template, request, redirect, url_for, session
from flask_pymongo import PyMongo, MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
import random
import string
from datetime import timedelta,datetime
from flask import jsonify
from flask_cors import CORS
from twilio.rest import Client 
import os
from pymongo import ASCENDING, DESCENDING 
import base64
import requests
from geopy.geocoders import Nominatim
from bson import ObjectId
from bson.objectid import ObjectId
from werkzeug.utils import secure_filename  
import cv2
import requests
from PIL import Image
from transformers import pipeline
from ultralytics import YOLO
from collections import defaultdict


# Twilio credentials (replace with your actual credentials)
TWILIO_ACCOUNT_SID = 'AC5eafe5c77d22c3b19763490032f51f42'
TWILIO_AUTH_TOKEN = '9dfd112a18e87a7abe03a4856dca96c6'
TWILIO_PHONE_NUMBER = '+919025861380'

twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

app = Flask(__name__) 
app.secret_key = "mysecret"
CORS(app)  # For Flask apps
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024  # 16 MB limit for file uploads


# Configure Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'balaji.k.2021.csbs@ritchennai.edu.in'  
app.config['MAIL_PASSWORD'] = 'ygzlaqckxeoovadc'  
mail = Mail(app) 

# Session TimeOut
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes = 150) 

# MongoDB setup
client = MongoClient('mongodb://localhost:27017/mydb')
db = client['users']

@app.before_request
def make_session_permanent():
    session.permanent = True

API_URL = "https://api-inference.huggingface.co/models/distilbert/distilbert-base-uncased-finetuned-sst-2-english"
HEADERS = {"Authorization": f"Bearer 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"}  # Use your HF API token

# MongoDB Configuration
app.config["MONGO_URI"] = "mongodb://localhost:27017/mydb"
mongo = PyMongo(app) 

@app.route('/status', methods=['GET'])
def status():
    # Check if the user is logged in 
    if 'username' not in session: 
        return redirect(url_for('user_login')) 
    
    # Get the logged-in user's username 
    username = session['username'] 
    
    # Find the user in the database
    user = mongo.db.users.find_one({'username': username})  
    
    if not user:
        return "User not found", 404 
    
    # Fetch user's queries
    queries=user.get('queries','')
    
    # Render the template and pass the data
    return render_template('status.html', user=user, queries=queries)


UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True) 

def encode_image(image_path):
    """ Convert image to Base64 string """
    with open(image_path, "rb") as img_file:
        return base64.b64encode(img_file.read()).decode("utf-8") 
    
def get_image_size(image):
    img = Image.open(image)
    return img.width, img.height
    

def get_severity(issue_text, road_type):
    payload = {"inputs": issue_text} 
    response = requests.post(API_URL, headers=HEADERS, json=payload)
    
    if response.status_code == 200: 
        sentiment = response.json()[0] # Get the response 
        label = sentiment[0]['label'] 
        score = sentiment[0]['score']
        
        # Map sentiment to severity levels
        if label == "NEGATIVE" and (score < 0.993):
            if road_type == "highway":
                return "Medium Severity" 
            else:
                return "Low Severity"
        elif label == "NEGATIVE" and (score >= 0.993 and score<=0.996):
            if road_type == "Highway":
                return "High Severity" 
            else:
                return "Medium Severity"
        else:
            return "High Severity" 
    else:
        return "Error in API request" 


def detect(file_path):
    model = YOLO(r"E:\\image\\models\\YOLOv8_Small_RDD.pt") 
    results = model(file_path) 

    # Process detections 
    detections = [] 
    image = cv2.imread(file_path) 
    
    for result in results:
        for box in result.boxes:
            x1, y1, x2, y2 = map(int, box.xyxy[0])  # Bounding box coordinates
            class_id = int(box.cls[0])  # Class ID
            confidence = float(box.conf[0])  # Confidence score

            detections.append({"bbox": [x1, y1, x2, y2], "class": class_id, "confidence": confidence})

            # Draw bounding box
            cv2.rectangle(image, (x1, y1), (x2, y2), (0, 255, 0), 3)
            cv2.putText(image, f'Class {class_id} ({confidence:.2f})', 
                        (x1, y1 - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 0), 2)

    # Save processed image
    processed_path = os.path.join(UPLOAD_FOLDER, "processed_image.jpg")
    cv2.imwrite(processed_path, image) 

    # Convert processed image to Base64
    processed_image_base64 = encode_image(processed_path)

    return detections, processed_image_base64

def image_severity(detections, image_width, image_height):
    # Define class weights (higher for severe damage
    CLASS_WEIGHTS = {
        0: 1.25,  # Longitudinal crack
        1: 1.15,  # Transverse crack
        2: 1.7,  # Alligator crack
        3: 1.8,  # Potholes 
    }
     # Define class names for readable output
    CLASS_NAMES = {
        0: "Longitudinal Crack",
        1: "Transverse Crack",
        2: "Alligator Crack",
        3: "Potholes",
    }

    weighted_score = 0  
    total_damage_ratio = 0  
    class_area = defaultdict(int)  
    image_area = image_width * image_height  # Total image size

    for det in detections:
        x1, y1, x2, y2 = det["bbox"]
        if det["class"]== 3:

            length=len(detections)

            if length>2 and length<4:
                area = (x2 - x1) * (y2 - y1) * 10 
                normalized_area = area / image_area 
            elif length>=4:
                area = (x2 - x1) * (y2 - y1) * 18 
                normalized_area = area / image_area 
            elif length==1:
                area = (x2 - x1) * (y2 - y1) * 1.7  
                normalized_area = area / image_area
            else:
                area = (x2 - x1) * (y2 - y1) 
                normalized_area = area / image_area 
        else:
            area = (x2 - x1) * (y2 - y1)
            normalized_area = area / image_area 

        confidence = det["confidence"]  
        damage_class = det["class"]  
        
        # Get class weight
        class_weight = CLASS_WEIGHTS.get(damage_class, 1.0)

        # Compute weighted severity contribution
        weighted_score += normalized_area * confidence * class_weight  

        # Track total area per class
        class_area[damage_class] += normalized_area  
        total_damage_ratio += normalized_area  

    # Determine majority damage class
    majority_class = max(class_area, key=class_area.get, default=None)
    majority_class_name = CLASS_NAMES.get(majority_class, "Unknown")

    # **Updated Scaling for Better Severity Calculation**
    if weighted_score > 0.35:
        severity_label = "High Severity"
    elif 0.15 <= weighted_score <= 0.35:
        severity_label = "Medium Severity" 
    else:
        severity_label = "Low Severity"

    return {
        "majority_class_name": majority_class_name,
        "total_damage_ratio": total_damage_ratio,
        "weighted_severity_score": weighted_score,
        "overall_severity": severity_label
    } 

@app.route('/queries',methods=['GET','POST'])
def queries():
    if 'admin_username' in session: 
        return redirect(url_for('admin_dashboard'))
    if 'username' not in session:
        return redirect(url_for('user_login')) 
    
    # Allowed file extensions
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg','svg'} 
    
    def allowed_file(filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    
    if request.method == 'POST':
        name = request.form.get('name')
        address = request.form.get('address')
        issue_detail = request.form.get('issue_detail')
        prevailing_days = request.form.get('prevailing_days')
        image1 = request.files.get('image1')
        road_type=request.files.get('RoadType') 

        image_base64_list = []
        if image1 and allowed_file(image1.filename):
            # Sanitize the file name
            filename = secure_filename(image1.filename) 
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            image1.save(file_path) 

            mime_type = image1.mimetype 

            # Read the file and convert to Base64
            base64_image = encode_image(file_path) 
            image_base64_list.append({ 
            "mime_type": mime_type, 
            "data": base64_image 
        }) 
            
        width, height = get_image_size(file_path) 
        detections, processed_image_base64 = detect(file_path)
        processed_image_base64_list=[5]

        if detections==[]: 
            severity = "Needs Manual Review !" 
            scenario = severity 
            processed_image_base64_list == [5]

        else:
            text_severity_level = get_severity(issue_detail, road_type) 
            image_severityy = image_severity(detections,width,height)
            processed_image_base64_list = [{"mime_type": mime_type, "data": processed_image_base64}]

            scenario = image_severityy["majority_class_name"] 
            image_severity_level = image_severityy["overall_severity"] 

            if text_severity_level in ["High Severity","Low Severity"] and image_severity_level in ["High Severity", "Low Severity"]:
                severity="Medium Severity" 
            else:
                severity = image_severity_level 

        username = session.get('username') 
        user = mongo.db.users.find_one({"username": username}) 
        
        # Insert data into MongoDB 
        query_data = { 
            "user_id" : user['_id'],
            "_id": ObjectId(),
            "problem_name": name,
            "Location": address,
            "issue_detail": issue_detail,
            "prevailing_days": prevailing_days, 
            "images": image_base64_list,  # Store image binaries directly in the database
            "severity": severity,
            "scenario": scenario,
            "processed_image":processed_image_base64_list,
            "status": "Pending",
            'username': username,
            'timestamp': datetime.now()
        } 

        if user:
            # Append the query to the user's queries array
            mongo.db.users.update_one(
                {'username': username},
                {'$push': {'queries': query_data}}  # Push the query into the queries array
            ) 
        else: 
            # If the user doesn't exist, you can handle this case
            return "User not found!" 

        user_email=user.get('email')
        subject = f"Status Update: {name}"
        tracking_link = "http://127.0.0.1:5000/status"  # Change to your actual deployment URL
        body = (f"Hello {username},\n\n"
        f"The status of your complaint '{name}' is Pending.\n\n"
        f"📌 You can track the live status here: {tracking_link}\n\n"
                        "Thank you for using Resolve IT.\n\n"
                        "Best Regards,\nResolve IT Team")

        msg = Message(subject, sender="balaji.k.2021.csbs@ritchennai.edu.in", recipients=[user_email])
        msg.body = body
        mail.send(msg)                

        return redirect(url_for('status')) 

    return render_template('queries.html') 

# Landing page
@app.route('/') 
def landing():
     return redirect(url_for('home')) 

# Home 
@app.route('/home') 
def home():
    if 'admin_username' in session: 
        return redirect(url_for('admin_dashboard'))
    if 'username' in session:  
        return redirect(url_for('user_dashboard')) 
    return render_template('home.html') 

# Flask Route for Profile
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'username' not in session:
        return redirect(url_for('user_login'))
    elif 'admin_username' in session:
        return redirect(url_for('admin_dashboard'))

    user = mongo.db.users.find_one({'username': session['username']})

    error_username = error_email = None
    
    if request.method == 'POST':
        updated_username = request.form.get('username')
        updated_email = request.form.get('email')

        # Check if username is already taken by another user 
        if updated_username and updated_username != user['username']:
            if mongo.db.users.find_one({'username': updated_username}): 
                error_username = 'User name already taken, use a different one'
            else: 
                session['username']=updated_username
        if error_username or error_email:
            return render_template('profile.html',user=user, error_username=error_username,error_email=error_email)
        
        
        mobile = request.form.get('mobile') 
        mobile_number = user.get('username', '')
        
        if mobile == mobile_number:
            error_mobile = "Mobile number already exist. Use different one"
            return render_template('profile.html', user=user, error_mobile=error_mobile )

        # Update user details
        updated_details = { 
            "username": updated_username ,
            "email": updated_email ,
            "address": request.form.get('address'),
            "state": request.form.get('state'),
            "district": request.form.get('district'),
            "country": request.form.get('country'),
            "gender": request.form.get('gender'),
            "mobile": mobile 
        }

        mongo.db.users.update_one({'username': user['username']}, {'$set': updated_details})

        # Update session with new username if it was changed
        session['username'] = updated_details['username']
        return redirect(url_for('profile'))
    
    return render_template('profile.html', user=user) 


@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'admin_username' in session: 
        return redirect(url_for('admin_dashboard'))
        
    elif 'username' in session: 
        return redirect(url_for('user_dashboard'))
    
    if request.method == 'POST':
        # Check if the request is JSON for sending OTP
        if request.is_json:
            data = request.get_json()
            if data.get('action') == 'send_emailotp':
                email = data.get('email')
                if not email:
                    return jsonify({"success": False, "message": "Email is required."}), 400

                # Generate a 6-digit OTP
                otp = ''.join(random.choices(string.digits, k=6))

                # Save OTP in session
                session['emailotp'] = otp

                # Send OTP to the email
                msg = Message(
                    "Your OTP for Verification", 
                    sender="balaji.k.2021.csbs@ritchennai.edu.in", 
                    recipients=[email]
                )
                msg.body = f"Your OTP is: {otp}"
                mail.send(msg)

                return jsonify({"success": True, "message": "OTP sent successfully."})
            
        # Handle form submission for registration
        username = request.form.get('username')
        email = request.form.get('email') 
        mobile = request.form.get('mobile')
        password = request.form.get('password') 
        address = request.form.get('address') 
        state = request.form.get('state')
        district = request.form.get('district')
        gender = request.form.get('gender')
        country = request.form.get('country')
        email_otp = request.form.get('emailotp')
        # mobile_otp=request.form.get('mobileotp')
        
        # Initialize error messages
        error_username = error_email = None

        # Check for duplicate username or email in the database
        if mongo.db.users.find_one({'username': username}):
            error_username = 'Username already exists. Try a different one.'
        
        if mongo.db.users.find_one({'email': email}):
            error_email = 'Email already exists. Try logging in.'

        # Check for any validation errors
        if error_username or error_email:
            return render_template(
                'register.html', 
                error_username=error_username, 
                error_email=error_email
            )

        # Verify Email OTP
        if email_otp != session.get('emailotp'):
            session.pop('emailotp',None) 
            return render_template(
                'register.html', 
                error_emailotp="Invalid Email OTP. Please try again."
            )

        # Check for phone number exist
        if mongo.db.users.find_one({'mobile': mobile}):
            error_mobile = 'Mobile Number already Exist, Use different one'
            return render_template('register.html',error_mobile=error_mobile)


        ''' # Verify Mobile OTP
        if mobile_otp != session.get('mobileotp'):
            session.pop('mobileotp',None) 
            return render_template(
                'register.html', 
                error_mobileotp="Invalid Mobile OTP. Please try again."
            )'''
        # Hash the password and insert the new user into the database
        hashed_password = generate_password_hash(password, 'pbkdf2:sha256')
        mongo.db.users.insert_one({ 
            'username': username,
            'email': email,
            'mobile': mobile,
            'password': hashed_password,
            'address': address,
            'state': state,
            'district': district,
            'country': country,
            'gender': gender,
            'queries': []        # Initialize with an empty array
        })  

        return render_template('user_login.html',success_message=" Registered successfully try logging in! ")

    return render_template('register.html')

# User Login 
@app.route('/user_login', methods=['GET', 'POST']) 
def user_login(): 
    if 'admin_username' in session: 
        return redirect(url_for('admin_dashboard')) 
        
    elif 'username' in session: 
        return redirect(url_for('user_dashboard')) 

    elif request.method == 'POST':  

        identifier = request.form['identifier'] 
        password = request.form['password'] 
        
        # Check for user by username or email 
        user = mongo.db.users.find_one({'$or': [{'username': identifier}, {'email': identifier}]})
        if user and check_password_hash(user['password'], password): 
            session['username'] = user['username']
            return redirect(url_for('user_dashboard')) 
        else:
            error_identifier='Incorrect username/password combination'
        
        return render_template( 
            'user_login.html', error_identifier=error_identifier) 
    return render_template('user_login.html') 

# Admin Login
@app.route('/admin_login', methods=['GET', 'POST']) 
def admin_login(): 
    if 'admin_username' in session: 
        return redirect(url_for('admin_dashboard')) 

    elif 'username' in session: 
        return redirect(url_for('user_dashboard'))

    elif request.method == 'POST': 

        admin_username = request.form['username']  
        admin_password = request.form['password'] 

        user = mongo.db.admin.find_one( {'admin_username': admin_username})
        pwd = check_password_hash(user['admin_password'], admin_password)

        if user and pwd : 
            session['admin_username'] = user['admin_username']
            return redirect(url_for('admin_dashboard'))
        else:
            error_admin='Incorrect credentials to access admin Try again'
            return render_template('admin_login.html',error_admin=error_admin)
    return render_template('admin_login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    
    if request.method == 'POST':
        email = request.form['email']
        user = mongo.db.users.find_one({'email': email}) 

        if not user:
            return render_template('forgot_password.html',error_email="Email does not exist")

        # Generate OTP 
        otp = ''.join(random.choices(string.digits, k=6)) 
        session['otp'] = otp 
        session['reset_email'] = email 
        
        # Send OTP to email 
        msg = Message("Password Reset OTP", sender="balaji.k.2021.csbs@ritchennai.edu.in", recipients=[email]) 
        msg.body = f"Your OTP for password reset is: {otp}" 
        mail.send(msg) 
        return redirect(url_for('verify_otp')) 

    if request.method == 'GET':
        user=None 
        if 'username' in session:
            user = mongo.db.users.find_one({'username': session['username']}) 
        return render_template('forgot_password.html',user=user) 

# Verify OTP 
@app.route('/verify_otp', methods=['GET', 'POST']) 
def verify_otp(): 
    error_name = None
    if 'admin_username' in session: 
        return redirect(url_for('admin_dashboard')) 
    elif request.method == 'POST':  
        user_otp = request.form['otp'] 
        if user_otp == session.get('otp'): 
            return render_template('reset_password.html')
        else: 
            return render_template('verify_otp.html',error_name = "incorrect otp")
    return render_template('verify_otp.html') 

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if 'admin_username' in session: 
        return redirect(url_for('admin_dashboard')) 
    
    if request.method == 'POST':
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        email = session.get('reset_email')

        if not new_password or not confirm_password:
            return render_template('reset_password.html', error_password="⚠ Both fields are required!")

        if new_password != confirm_password:
            return render_template('reset_password.html', error_password="⚠ Passwords do not match!")

        if not email:  # If email is missing, redirect to forgot password page
            return redirect(url_for('forgot_password'))  

        # Hash the new password and update it in MongoDB
        hashed_password = generate_password_hash(new_password, 'pbkdf2:sha256')
        mongo.db.users.update_one({'email': email}, {'$set': {'password': hashed_password}})
        
        # Clear session data
        session.pop('otp', None)
        session.pop('reset_email', None)
        session.clear()

        return render_template('user_login.html', success_passwd_message="Password Changed Successfully! Try logging in.")

    return render_template('reset_password.html') 

@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if 'admin_username' not in session:
        return redirect(url_for('admin_login'))

    option = request.args.get('option', 'show_database')

    if option == 'show_database':
        users = list(mongo.db.users.find({}, {'queries': 0}))
        return render_template('admin_dashboard.html', option=option, users=users)

    elif option == 'show_problems':
        queries = []
        for user in mongo.db.users.find({'queries': {'$exists': True}}):
            for query in user['queries']:
                query['user_id'] = str(user['_id'])
                query['username'] = user['username']
                queries.append(query)

        queries.sort(key=lambda x: x.get('severity', float('-inf')), reverse=True)
        return render_template('admin_dashboard.html', option=option, queries=queries)

    elif option == 'show_analytics':
        queries = []
        user_counts = {}
        status_counts = {"Pending": 0, "In Progress": 0, "Done": 0}
        severity_counts={"High Severity": 0, "Medium Severity":0, "Low Severity":0, "Needs Manual Review !":0}
        scenario_counts={"Longitudinal Crack":0, "Latitudinal Crack":0, "Alligator Crack":0, "Potholes":0, "Needs Manual Review !":0}
        total_users = 0
        total_queries = 0
        heatmap_data = []
        resolution_times = [] 
        resolution_times_by_severity = {
                "High Severity": [],
                "Medium Severity": [],
                "Low Severity": []
            }

        for user in mongo.db.users.find({"queries": {"$exists": True}}):
            username = user["username"]
            query_count = len(user["queries"])
            user_counts[username] = query_count
            total_queries += query_count
            total_users += 1

            for query in user["queries"]:
                query["user_id"] = str(user["_id"])
                query["username"] = username
                query["_id"] = str(query["_id"]) if "_id" in query else None
                queries.append(query)

                severity = query.get("severity")
                if severity in severity_counts:
                    severity_counts[severity] += 1

                scenario = query.get("scenario")
                if scenario in scenario_counts:
                    scenario_counts[scenario] += 1

                status = query.get("status", "Pending")
                if status in status_counts:
                    status_counts[status] += 1 
                # Calculate resolution time for "Done" status only
                if status == "Done":
                    resolved_at = query.get("resolved_at")
                    created_at = query.get("timestamp")

                    if resolved_at and created_at:
                        try:
                            created_dt = datetime.strptime(created_at, "%Y-%m-%d %H:%M:%S")
                            resolved_dt = datetime.strptime(resolved_at, "%Y-%m-%d %H:%M:%S")
                            resolution_time = (resolved_dt - created_dt).days

                            # Add resolution time to the corresponding severity category
                            if severity in resolution_times_by_severity:
                                resolution_times_by_severity[severity].append(resolution_time)

                        except Exception as e:
                            print(f"Date parsing error: {e}")
                print(resolution_times_by_severity)

        avg_queries_per_user = round(total_queries / total_users, 2) if total_users > 0 else 0
        return render_template(
            'admin_dashboard.html',
            option = 'show_analytics',
            queries = queries,
            user_counts = user_counts,
            severity_counts = severity_counts,
            scenario_counts = scenario_counts,
            status_counts = status_counts,
            avg_queries_per_user = avg_queries_per_user,
            resolution_times_by_severity = resolution_times_by_severity,
        )

    elif option == "show_Heatmap":
        heatmap_data = []
        geolocator = Nominatim(user_agent="heatmap_test")

        for user in mongo.db.users.find({"queries": {"$exists": True}}):
            for query in user["queries"]:
                address = query.get("Location") 
                location = geolocator.geocode(address)
                if location:
                    heatmap_data += [{"lat": location.latitude, "lon": location.longitude}]
                
        return render_template(
            'admin_dashboard.html',
            option="show_Heatmap",
            heatmap_data=heatmap_data
        )

    return('admin_dashboard.html') 

@app.route("/update_scenario", methods=["POST"])
def update_scenario():
    try:
        data = request.get_json()
        query_id = data.get("query_id")
        user_id = data.get("user_id")
        new_scenario = data.get("scenario")

        if not query_id or not user_id or not new_scenario:
            return jsonify({"error": "Invalid request - Missing parameters"}), 400

        user = mongo.db.users.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'error': 'User not found'}), 404

        updated = False
        for query in user.get('queries', []):
            if str(query['_id']) == query_id:
                query['scenario'] = new_scenario
                updated = True
                break
            
        if updated:
            mongo.db.users.update_one({'_id': ObjectId(user_id)}, {'$set': {'queries': user['queries']}})
            return jsonify({'success': True, 'new_scenario': new_scenario})

        return jsonify({'error': 'Query not found'}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route("/update_severity", methods=["POST"])
def update_severity():
    try:
        data = request.get_json()
        query_id = data.get("query_id")
        user_id = data.get("user_id")  # Added user_id
        new_severity = data.get("severity")

        if not query_id or not user_id or not new_severity:
            return jsonify({"error": "Invalid request - Missing parameters"}), 400

        user = mongo.db.users.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'error': 'User not found'}), 404 

        updated = False 
        for query in user.get('queries', []): 
            if str(query['_id']) == query_id: 
                query['severity'] = new_severity  
                updated = True 
                break 

        if updated:
            mongo.db.users.update_one({'_id': ObjectId(user_id)}, {'$set': {'queries': user['queries']}})
            send_email_notification(user['email'], user['username'], query['problem_name'], new_severity)
            return jsonify({'success': True, 'new_severity': new_severity})

        return jsonify({'error': 'Query not found'}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/update_status', methods=['POST'])
def update_status():
    try:
        data = request.get_json()
        query_id = data.get('query_id')
        user_id = data.get('user_id')
        new_status = data.get('status')

        if not query_id or not user_id or not new_status:
            return jsonify({'error': 'Invalid request - Missing parameters'}), 400

        user = mongo.db.users.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'error': 'User not found'}), 404

        updated = False
        for query in user.get('queries', []):
            if str(query['_id']) == query_id:
                old_status = query.get('status', 'Unknown')
                query['status'] = new_status

                # ✅ If status changed to "Done", add "resolved_at" timestamp
                if new_status == "Done" and "resolved_at" not in query:
                    query["resolved_at"] = datetime.now()

                updated = True
                break

        if updated:
            mongo.db.users.update_one({'_id': ObjectId(user_id)}, {'$set': {'queries': user['queries']}})
            send_email_notification(user['email'], user['username'], query['problem_name'], new_status)
            return jsonify({'success': True, 'new_status': new_status, 'resolved_at': query.get("resolved_at", "N/A")})

        return jsonify({'error': 'Query not found'}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500

def send_email_notification(user_email, username, problem_name, new_status):
    """Send an email to notify the user of the status update, including a tracking link."""
    try:
        subject = f"Status Update: {problem_name}"
        tracking_link = "http://127.0.0.1:5000/status"  # Change to your actual deployment URL
        body = (f"Hello {username},\n\n"
                f"The status of your complaint '{problem_name}' has been updated to: {new_status}.\n\n"
                f"📌 You can track the live status here: {tracking_link}\n\n"
                "Thank you for using Resolve IT.\n\n"
                "Best Regards,\nResolve IT Team")

        msg = Message(subject, sender="balaji.k.2021.csbs@ritchennai.edu.in", recipients=[user_email])
        msg.body = body
        mail.send(msg)
    except Exception as e:
        print(f"Error sending email: {e}")

    except Exception as e:
        print(f"Error sending email: {e}")

@app.route('/delete_query', methods=['POST']) 
def delete_query_admin():
    query_id = request.form.get('query_id')
    user_id = request.form.get('user_id')

    if not query_id or not user_id: 
        return jsonify({"error": "Invalid request"}), 400

    # Delete the query from the user's queries in the database
    result = mongo.db.users.update_one(
        {'_id': ObjectId(user_id)},
        {'$pull': {'queries': {'_id': ObjectId(query_id)}}}
    )

    if result.modified_count > 0:
        return jsonify({"success": True})  # Return JSON success response
    else:
        return jsonify({"error": "Query not found"}), 404
    
# user dashboard 
@app.route('/user_dashboard') 
def user_dashboard(): 
    if 'username' in session:
        return render_template('user_dashboard.html') 
    else:
        return redirect(url_for('home'))

# Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home')) 

if __name__ == '__main__':
    app.run(debug=True)
