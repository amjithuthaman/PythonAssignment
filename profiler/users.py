from flask import Blueprint, g, jsonify, request
from werkzeug.security import generate_password_hash, check_password_hash
from .db import get_db
from .auth import login_required

blueprint = Blueprint("users", __name__, url_prefix="/users")


@blueprint.route("/", methods=["POST"])
def create_user():
    data = request.json

    first_name = data.get("first_name")
    last_name = data.get("last_name")
    email = data.get("email")
    password = data.get("password")

    if not all([first_name, last_name, email, password]):
        return {"error": "Required fields are missing"}, 400

    db = get_db()
    hashed_password = generate_password_hash(password)
    try:
        cursor = db.execute(
            "INSERT INTO user (first_name, last_name, email, password) VALUES (?, ?, ?, ?)",
            (first_name, last_name, email, hashed_password),
        )
        db.commit()
    except db.IntegrityError:
        return {"error": "This email is already registered"}, 400

    return jsonify({"id": cursor.lastrowid}), 201


@blueprint.route("/", methods=["GET"])
def list_users():
    db = get_db()

    cursor = db.execute("SELECT * FROM user")
    users = cursor.fetchall()

    user_list = []
    for user in users:
        user_list.append(
            {
                "id": user["id"],
                "first_name": user["first_name"],
                "last_name": user["last_name"],
                "email": user["email"],
                "created_on": user["created_on"],
            }
        )

    return jsonify(user_list)


@blueprint.route("/<int:user_id>/", methods=["GET"])
def get_user(user_id):
    db = get_db()
    cursor = db.execute("SELECT * FROM user WHERE id=?", (user_id,))
    user = cursor.fetchone()
    if user is None:
        return {"error": "Invalid user id"}, 404
    return {
        "id": user["id"],
        "first_name": user["first_name"],
        "last_name": user["last_name"],
        "email": user["email"],
        "created_on": user["created_on"],
    }


@blueprint.route("/<int:user_id>/", methods=["PUT"])
def update_user(user_id):
    data = request.json
    first_name = data.get("first_name")
    last_name = data.get("last_name")
    email = data.get("email")

    if not all([first_name, last_name, email]):
        return {"error": "Required fields are missing"}, 400
    db = get_db()
    try:
        db.execute(
            "UPDATE user SET first_name=?, last_name=?, email=? WHERE id=?",
            (first_name, last_name, email, user_id),
        )
        db.commit()
    except db.IntegrityError:
        return {"error": "This email is already registered"}, 400
    return jsonify({"id": user_id}), 200


@blueprint.route("/<int:user_id>/", methods=["DELETE"])
def delete_user(user_id):
    db = get_db()
    db.execute("DELETE FROM user WHERE id=?", (user_id,))
    db.commit()
    return "", 204

@blueprint.route("/password-change/", methods=["POST"])
def password_change():
    data = request.json
    email = data.get("email")
    current_password = data.get("current_password")
    new_password = data.get("new_password")
    if not all([current_password, new_password, email]):
        return {"error": "Required fields are missing"}, 400
    
    hashed_new_password = generate_password_hash(new_password)
    db = get_db()
    cursor = db.execute("SELECT * FROM user where email=?", (email,))
    user = cursor.fetchone()

    if user is None:
        return {"error": "Incorrect email"}, 401
    
    if not check_password_hash(user["password"], current_password):
        return {"error": "Incorrect password"}, 401

    user_id = user["id"]
    try:
        db.execute(
            "UPDATE user SET password=? WHERE id=?",
            (hashed_new_password, user_id),
        )
        db.commit()
    except db.IntegrityError:
        return {"error": "This email is already registered"}, 400
    
    return jsonify({"id": user_id, "email": email, "message":"Password changed successfully" }), 200





