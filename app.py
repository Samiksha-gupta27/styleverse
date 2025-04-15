from flask import Flask, g, jsonify, request, render_template, redirect, url_for, flash , session
from uuid import uuid4
from functools import wraps
from neo4j import GraphDatabase   
import os
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime

app = Flask(__name__)

app.secret_key = 'random_key_idkwhattotype'
app.secret_key = os.environ.get("SECRET_KEY", "dev_default_key")

# Configuration for Neo4j connection

uri = "bolt://localhost:7687"
user = "neo4j"
password = "12345678"  # <- double check this
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


@app.route('/profile')
def profile():
    return render_template('profile.html')

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

@app.route("/users/me/wardrobe/items", methods=["POST"])
# Assuming you have authentication middleware
def add_wardrobe_item():
    user_id = g.user_id  # Get user ID from authentication
    data = request.get_json()
    item_id = str(uuid4())
    query = """
    MATCH (u:User {userId: $userId})
    CREATE (i:ClothingItem {
        itemId: $itemId,
        name: $name,
        category: $category,
        imageUrl: $imageUrl,
        colors: $colors,
        sizes: $sizes
    })
    CREATE (u)-[:OWNS]->(i)
    RETURN i
    """
    result = query_neo4j(query, userId=user_id, itemId=item_id, **data)
    if result:
        item = result[0]['i']
        return jsonify({"item": dict(item), "message": "Wardrobe item added"}), 201
    return jsonify({"message": "Failed to add wardrobe item"}), 500


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

@app.route("/users/me/wardrobe/items", methods=["GET"])
# Assuming you have authentication middleware
def get_wardrobe_items():
    user_id = g.user_id
    query = """
    MATCH (u:User {userId: $userId})-[:OWNS]->(i:ClothingItem)
    RETURN collect(i) AS items
    """
    result = query_neo4j(query, userId=user_id)
    if result and result[0]['items']:
        items = [dict(item) for item in result[0]['items']]
        return jsonify(items), 200
    return jsonify([]), 200

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

@app.route('/generate-outfit', methods=['POST'])
def generate_outfit():
    data = request.get_json()
    user_id = session.get("user_id")

    # You can base the generation on preferences
    preferences = data.get("preferences", {})
    
    # Sample query (you can improve logic with ML or rule-based outfit generation)
    query = """
    MATCH (u:User {userId: $userId})-[:OWNS]->(item:ClothingItem)
    RETURN item
    LIMIT 5
    """
    items = query_neo4j(query, userId=user_id)

    if not items:
        return jsonify({"message": "No items found"}), 404

    outfit = [dict(item['item']) for item in items]
    return jsonify({"outfit": outfit}), 200

@app.route('/generate', methods=['GET'])
def generate_page():
    return render_template('generate.html')


@app.route('/inspiration', methods=['GET'])
def get_inspiration():
    style = request.args.get('style', 'casual')

    # Sample query to fetch public inspiration outfits
    query = """
    MATCH (i:InspirationOutfit)
    WHERE $style IN i.styles
    RETURN i
    LIMIT 10
    """
    result = query_neo4j(query, style=style)

    if not result:
        return jsonify({"message": "No inspiration found"}), 404

    outfits = [dict(item['i']) for item in result]
    return jsonify({"inspiration": outfits}), 200


@app.route('/search', methods=['GET'])
def search_inspiration():
    return render_template('search.html')

@app.route("/home", methods=["GET"])
def landing_page():
    return render_template("home.html")


if __name__ == '__main__':
    app.run(debug=True)