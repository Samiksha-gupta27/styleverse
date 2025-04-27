from flask import Flask, g, jsonify, request, render_template, redirect, url_for, flash , session
from uuid import uuid4
from functools import wraps
from flask_cors import CORS
# from ultralytics import YOLO
from neo4j import GraphDatabase   
import os
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
import cv2
import base64


# Allow cross-origin requests

# YOLO model setup
#model = YOLO("yolov8n-seg.pt")


app = Flask(__name__)
CORS(app)  
app.secret_key = 'random_key_idkwhattotype'
app.secret_key = os.environ.get("SECRET_KEY", "dev_default_key")

# Configuration for Neo4j connection

uri = "bolt://localhost:7687"
user = "neo4j"
password = "123456789"  # <- double check this
driver = GraphDatabase.driver(uri, auth=(user, password))


def get_neo4j_driver():
    if not hasattr(g, 'neo4j_driver'):
        g.neo4j_driver = GraphDatabase.driver(uri, auth=(user, password))
    return g.neo4j_driver

@app.teardown_appcontext
def close_neo4j_driver(error):
    if hasattr(g, 'neo4j_driver'):
        g.neo4j_driver.close()

def query_neo4j(query, **kwargs):
    driver = get_neo4j_driver()
    with driver.session() as session:
        result = session.run(query, **kwargs)
        return result.data()
    
users = {}

@app.route("/")
def home():
    return render_template("landing.html")

@app.route('/search')
def search():
    return render_template('search.html')


@app.route('/profile', methods=["GET", "POST"])
def profile():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    # Fetch user details
    user_query = "MATCH (u:User {userId: $user_id}) RETURN u"
    user_data = query_neo4j(user_query, user_id=user_id)

    # Fetch user's uploads
    uploads_query = """
    MATCH (u:User {userId: $user_id})-[:UPLOADED]->(img:Image)
    RETURN img
    """
    uploads_data = query_neo4j(uploads_query, user_id=user_id)

    images = []
    for record in uploads_data:
        img_node = record['img']
        images.append({
            "imageId": img_node.get('imageId'),
            "fileName": img_node.get('fileName'),
            "tags": img_node.get('tags'),
            "uploadedAt": img_node.get('uploadedAt'),
            "data": img_node.get('data')
        })

    return render_template('profile.html', user=user_data[0]['u'], images=images)


@app.route('/logout', methods=['GET'])
def logout():
    session.clear()
    flash("You have been logged out successfully.", "info")
    return redirect(url_for('home'))

# Replace with your actual import
  # Needed for flash messages

@app.route("/signup", methods=["GET"])
def signup_form():
    return render_template("signup.html")

@app.route("/signup", methods=["POST"])
def register_user():
    username = request.form.get("username").strip()
    email = request.form.get("email").strip()
    first_name = request.form.get("firstName").strip()
    last_name = request.form.get("lastName").strip()
    password = request.form.get("password").strip()

    if not all([username, email, first_name, last_name, password]):
        flash("All fields are required.", "warning")
        return redirect(url_for("signup_form"))

    # Check if username or email already exists
    check_query = """
    MATCH (u:User)
    WHERE u.username = $username OR u.email = $email
    RETURN u
    """
    existing_user = query_neo4j(check_query, username=username, email=email)

    if existing_user:
        flash("Username or email already exists.", "danger")
        return redirect(url_for("login"))

    user_id = str(uuid4())
    hashed_password = generate_password_hash(password)

    # Create new user
    create_query = """
    CREATE (u:User {
        userId: $userId,
        username: $username,
        email: $email,
        firstName: $firstName,
        lastName: $lastName,
        password: $password
    })
    RETURN u
    """
    result = query_neo4j(create_query,
                         userId=user_id,
                         username=username,
                         email=email,
                         firstName=first_name,
                         lastName=last_name,
                         password=hashed_password)

    if result:
        flash("User registered successfully!", "success")
        return redirect(url_for("login"))
    else:
        flash("Registration failed. Please try again.", "danger")
        return redirect(url_for("signup_form"))



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.form
        email = data.get('email')
        password = data.get('password')

        # You can query Neo4j to verify the user instead of this simple dict
        query = """
        MATCH (u:User {email: $email})
        RETURN u
        """
        result = query_neo4j(query, email=email)

        if result:
            user_node = result[0]['u']
            hashed_pw = user_node['password']

            from werkzeug.security import check_password_hash
            if check_password_hash(hashed_pw, password):
                session['user'] = user_node['username']
                session['user_id'] = user_node['userId']  # Optional: store userId
                flash(f"Welcome back, {user_node['username']}!", "success")
                return redirect(url_for('landing_page'))  # ✅ REDIRECT TO HOME

        flash("Invalid credentials", "danger")
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route("/users/login", methods=["POST"])
def login_user():
    data = request.get_json()
    username_or_email = data.get("username") or data.get("email")
    password = data.get("password")

    if not username_or_email or not password:
        return jsonify({"message": "Missing username/email or password"}), 400

    query = """
    MATCH (u:User)
    WHERE u.username = $username_or_email OR u.email = $username_or_email
    RETURN u
    """
    result = query_neo4j(query, username_or_email=username_or_email)

    if result:
        user = result[0]['u']
        if check_password_hash(user['passwordHash'], password):
            token = jwt.encode({
                "user_id": user['userId'],
                "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
            }, app.config["SECRET_KEY"], algorithm="HS256")
            return jsonify({
                "token": token,
                "user": {
                    "userId": user['userId'],
                    "username": user['username'],
                    "email": user['email'],
                    "firstName": user['firstName'],
                    "lastName": user['lastName']
                },
                "message": "Login successful"
            }), 200
        else:
            return jsonify({"message": "Invalid credentials"}), 401
    else:
        return jsonify({"message": "Invalid credentials"}), 401



@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        file = request.files.get('file')
        if file:
            # Save or process file here
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            flash('File uploaded successfully!', 'success')
            return redirect(url_for('upload'))
    return render_template('upload.html')

@app.route("/favourite_items", methods=["POST"])
def favorite_item(item_id):
    user_id = session.get('user_id')
    
    query = """
    MATCH (u:User {userId: $user_id})-[:OWNS]->(i:ClothingItem {itemId: $item_id})
    SET i.favorite = true
    RETURN i
    """
    result = query_neo4j(query, user_id=user_id, item_id=item_id)
    if result:
        flash("Item marked as favorite!", "success")
        return redirect(url_for('profile'))  # Redirect back to profile page
    flash("Item not found.", "danger")
    return redirect(url_for('profile')) 


@app.route('/generate', methods=['GET'])
def generate_page():
    return render_template('generate.html')

@app.route('/search', methods=['GET'])
def search_inspiration():
    return render_template('search.html')

@app.route("/home", methods=["GET"])
def landing_page():
    return render_template("home.html")

def query_neo4j(query, **kwargs):
    with driver.session() as session:
        session.run(query, kwargs)

# Save image data to Neo4j
def save_to_neo4j(image_data, bounding_boxes, masks, user_id=None):
    query = """
    CREATE (img:Image {
        data: $data,
        bounding_boxes: $bounding_boxes,
        masks: $masks,
        uploaded_at: datetime()
    })
    """ + ("""
    WITH img
    MATCH (u:User {userId: $user_id})
    MERGE (u)-[:UPLOADED]->(img)
    """ if user_id else "")

    query_neo4j(
        query,
        data=image_data,
        bounding_boxes=bounding_boxes,
        masks=masks,
        user_id=user_id
    ) 

# @app.route('/upload-image', methods=['POST'])
# def upload_image():
#     # Check for image in request
#     image = request.files.get('image')
#     if not image:
#         return jsonify({"error": "No image file provided"}), 400

#     # Save image temporarily
#     os.makedirs("uploads", exist_ok=True)
#     image_path = os.path.join("uploads", image.filename)
#     image.save(image_path)

#     # Load image with OpenCV
#     img = cv2.imread(image_path)
#     if img is None:
#         return jsonify({"error": "Failed to read uploaded image"}), 500
#     img_rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)

#     # YOLOv8 segmentation
#     # Encode image as base64
#     _, img_encoded = cv2.imencode('.jpg', img)
#     image_base64 = base64.b64encode(img_encoded).decode('utf-8')

#     # Optional: check for logged-in user
#     user_id = session.get('user_id')  # Optional: attach to user node

#     # Save all to Neo4j
#     save_to_neo4j(image_base64, user_id)

if __name__ == '__main__':

    if not os.path.exists("uploads"):
        os.makedirs("uploads")
    app.run(debug=True)