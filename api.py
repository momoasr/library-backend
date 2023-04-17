from flask import Flask, request, jsonify, make_response
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

app.config['SECRET_KEY'] = 'thisisscret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///example.sqlite'
app.config['SQLALCHEMY_TRAC_MODIFICATIONS'] = False
app.permanent_session_lifetime = timedelta(minutes=5)

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)


class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    author = db.Column(db.String(100))


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Missing token!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.filter_by(
                public_id=data['public_id']).first()
        except Exception as e:
            if hasattr(e, 'message'):
                print(f'Error message: {e.message}')
            else:
                print(f'Error message: {e}')
            return jsonify({'message': 'Invalid token!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated


@app.route("/users", methods=['GET'])
@token_required
def get_all_users(current_user):
    if not current_user.admin:
        return jsonify({'message': 'You have not enough permission to perform this action!'})

    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)
    return jsonify(output)


@app.route("/users/<public_id>", methods=['GET'])
def get_user_by_id(public_id):
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message': 'No user found!'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin
    return jsonify(user_data)


@app.route("/signup", methods=['POST'])
def create_user():
    data = request.get_json()

    h_pw = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()),
                    name=data['userName'], password=h_pw, admin=False)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'New user Created!'})


@app.route("/login", methods=['POST'])
def login():
    auth = request.get_json()
    name = auth['userName']
    password = auth['password']
    
    if not auth or not name or not password:
        return make_response('Missing user name or password.', 401, {'WWW-authenticate': 'Basic realm="Login failed!"'})

    user = User.query.filter_by(name=name).first()
    if not user:
        return make_response('Incorrect user name or password.', 401, {'WWW-authenticate': 'Basic realm="Login failed!"'})

    if check_password_hash(user.password, password):
        token = jwt.encode({'public_id': user.public_id, 'userName': user.name, 'exp': datetime.utcnow(
        ) + timedelta(minutes=5)}, app.config['SECRET_KEY'])

        return jsonify({'token': token})

    return make_response('Incorrect user name or password.', 401, {'WWW-authenticate': 'Basic realm="Login failed!"'})


if __name__ == '__main__':
    db.create_all()
    app.debug(debug=True)
