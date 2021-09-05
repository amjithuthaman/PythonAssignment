from flask import Blueprint, jsonify, request
from werkzeug.security import generate_password_hash
from .db import get_db

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
    return {"action": "list all users"}


@blueprint.route("/<int:user_id>/", methods=["GET"])
def get_user(user_id):
    return {"action": f"get user {user_id}"}


@blueprint.route("/<int:user_id>/", methods=["PUT"])
def update_user(user_id):
    return {"action": f"update user {user_id}"}


@blueprint.route("/<int:user_id>/", methods=["DELETE"])
def delete_user(user_id):
    return "", 204
