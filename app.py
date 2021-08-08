import datetime
import os
import re

from bson.objectid import ObjectId
from flask import Flask, jsonify, request, make_response
from flask_jwt_extended import JWTManager
from flask_jwt_extended import create_access_token, create_refresh_token, get_jwt
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'DefaultValue_d5049c7d')
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = datetime.timedelta(minutes=30)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = datetime.timedelta(hours=24)
app.config["MONGO_URI"] = "mongodb://localhost:27017/barcode"
app.config['DEBUG'] = True

mongo = PyMongo(app)
jwt = JWTManager(app)
current_time = datetime.datetime.utcnow()


# Регистрация пользователя
@app.route('/registration', methods=['POST'])
def create_user():
    data = request.get_json()
    existing_user = mongo.db.users.find_one({'name': data['name']})
    if existing_user is None:
        hash_pass = generate_password_hash(data['password'], method='sha256')
        user = {
            'name': data['name'],
            'password': hash_pass,
            "unacceptable_products": [],
        }
        mongo.db.users.insert(user)
        user = mongo.db.users.find_one({'name': data['name']}, {'_id': 1, 'name': 1, 'password': 1})
        access_token = create_access_token(identity=str(user['_id']))
        refresh_token = create_refresh_token(identity=str(user['_id']))
        return jsonify(access_token=access_token, refresh_token=refresh_token)
    return 'User exist'


# Авторизация пользователя
@app.route('/login', methods=['POST'])
def user_login():
    data = request.get_json()
    if not data or not data['name'] or not data['password']:
        return make_response('Could not verify', 401)
    user = mongo.db.users.find_one({'name': data['name']}, {'_id': 1, 'name': 1, 'password': 1})
    if not user:
        return make_response('Could not verify', 401)
    if check_password_hash(user['password'], data['password']):
        access_token = create_access_token(identity=str(user['_id']))
        refresh_token = create_refresh_token(identity=str(user['_id']))
        return jsonify(access_token=access_token, refresh_token=refresh_token)
    return make_response('Could not verify', 401)


# Обновление токена доступа
@app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    jti = get_jwt()["jti"]
    existing_jti = mongo.db.token_blacklist.find_one({'user_id': current_user, 'jti': jti})
    if existing_jti:
        return jsonify('this token invalid')
    token_blacklist = {
        'jti': jti,
        'created_at': current_time,
        'user_id': current_user
    }
    mongo.db.token_blacklist.insert(token_blacklist)
    access_token = create_access_token(identity=current_user)
    refresh_token = create_refresh_token(identity=current_user)
    return jsonify(access_token=access_token, refresh_token=refresh_token)


# Добавление и удаление недопустимых продуктов
# надо проработать обработку исключения если продукты не добавились в бд
@app.route("/unacceptable_products", methods=['POST', 'DELETE'])
@jwt_required()
def add_unacceptable_products():
    current_user = get_jwt_identity()
    unacceptable_products = request.json['unacceptable_products']
    if request.method == 'POST':
        mongo.db.users.update({"_id": ObjectId(current_user)},
                              {'$addToSet': {'unacceptable_products': {'$each': unacceptable_products}}})

    if request.method == 'DELETE':
        mongo.db.users.update({"_id": ObjectId(current_user)},
                              {'$pullAll': {'unacceptable_products': unacceptable_products}})

    unacceptable_products = mongo.db.users.find_one_or_404({"_id": ObjectId(current_user)},
                                                           {'unacceptable_products': 1})
    return_result = {
        "unacceptable_products": unacceptable_products["unacceptable_products"]
    }
    return jsonify(return_result)


# получение продукта по штрих-коду
@app.route("/product", methods=['POST'])
@jwt_required()
def test_req():
    current_user = get_jwt_identity()
    barcode = request.json['barcode']
    product = mongo.db.goods.find_one_or_404({"barcode": barcode},
                                             {'composition': 1, '_id': 0, 'name': 1, 'esl': 1})
    unacceptable_products = mongo.db.users.find_one_or_404({"_id": ObjectId(current_user)},
                                                           {'unacceptable_products': 1})
    # result = list(set(product['composition']) & set(unacceptable_products['unacceptable_products']))
    result = []
    for unacceptable in unacceptable_products['unacceptable_products']:
        for composition in product['composition']:
            temp = re.search(f"(?i){unacceptable}", composition)
            if temp is not None:
                result.append(composition)
    return_result = {
        "name": product['name'],
        "composition": product['composition'],
        "unacceptable_products": result,
        "esl": product['esl']
    }
    return jsonify(return_result)


if __name__ == '__main__':
    app.run(host='192.168.1.116', debug=True, port=5000)
