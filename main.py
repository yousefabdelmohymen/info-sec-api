import os
import datetime
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask app
app = Flask(__name__)

# Configuration using environment variables for production
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'super-secret-key')  # Change for production

# Initialize extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    username = db.Column(db.String(128), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)

class Product(db.Model):
    pid = db.Column(db.Integer, primary_key=True)
    pname = db.Column(db.String(128), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# Routes

# User signup: Registers a new user with hashed password
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    name = data.get('name')
    username = data.get('username')
    password = data.get('password')

    if not all([name, username, password]):
        return jsonify({'msg': 'Missing required fields'}), 400

    # Check if username already exists
    if User.query.filter_by(username=username).first():
        return jsonify({'msg': 'Username already exists'}), 400

    hashed_password = generate_password_hash(password)
    new_user = User(name=name, username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'msg': 'User created successfully'}), 201

# User login: Authenticates user and returns a JWT valid for 10 minutes
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not all([username, password]):
        return jsonify({'msg': 'Missing required fields'}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({'msg': 'Bad username or password'}), 401

    access_token = create_access_token(identity=user.id, expires_delta=datetime.timedelta(minutes=10))
    return jsonify({'access_token': access_token}), 200

# Update user details: Only the authenticated user can update their own details
@app.route('/users/<int:id>', methods=['PUT'])
@jwt_required()
def update_user(id):
    current_user_id = get_jwt_identity()
    if current_user_id != id:
        return jsonify({'msg': 'Unauthorized access'}), 403

    data = request.get_json()
    user = User.query.get_or_404(id)

    if 'name' in data:
        user.name = data['name']
    if 'password' in data:
        user.password = generate_password_hash(data['password'])

    db.session.commit()
    return jsonify({'msg': 'User updated successfully'}), 200

# Create a new product: Protected endpoint
@app.route('/products', methods=['POST'])
@jwt_required()
def create_product():
    data = request.get_json()
    pname = data.get('pname')
    price = data.get('price')
    stock = data.get('stock')
    description = data.get('description', '')

    if not all([pname, price, stock is not None]):
        return jsonify({'msg': 'Missing required product fields'}), 400

    new_product = Product(pname=pname, description=description, price=price, stock=stock)
    db.session.add(new_product)
    db.session.commit()

    return jsonify({'msg': 'Product created', 'pid': new_product.pid}), 201

# Retrieve all products: Protected endpoint
@app.route('/products', methods=['GET'])
@jwt_required()
def get_products():
    products = Product.query.all()
    output = [{
        'pid': prod.pid,
        'pname': prod.pname,
        'description': prod.description,
        'price': prod.price,
        'stock': prod.stock,
        'created_at': prod.created_at
    } for prod in products]
    return jsonify({'products': output}), 200

# Retrieve a single product by ID: Protected endpoint
@app.route('/products/<int:pid>', methods=['GET'])
@jwt_required()
def get_product(pid):
    product = Product.query.get_or_404(pid)
    output = {
        'pid': product.pid,
        'pname': product.pname,
        'description': product.description,
        'price': product.price,
        'stock': product.stock,
        'created_at': product.created_at
    }
    return jsonify({'product': output}), 200

# Update product details: Protected endpoint
@app.route('/products/<int:pid>', methods=['PUT'])
@jwt_required()
def update_product(pid):
    product = Product.query.get_or_404(pid)
    data = request.get_json()

    if 'pname' in data:
        product.pname = data['pname']
    if 'description' in data:
        product.description = data['description']
    if 'price' in data:
        product.price = data['price']
    if 'stock' in data:
        product.stock = data['stock']

    db.session.commit()
    return jsonify({'msg': 'Product updated successfully'}), 200

# Delete a product: Protected endpoint
@app.route('/products/<int:pid>', methods=['DELETE'])
@jwt_required()
def delete_product(pid):
    product = Product.query.get_or_404(pid)
    db.session.delete(product)
    db.session.commit()
    return jsonify({'msg': 'Product deleted successfully'}), 200

# Run the application
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables if they don't exist
    app.run(debug=True)
