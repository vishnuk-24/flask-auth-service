import datetime
import os

import jwt
import psycopg2
from flask import Flask, jsonify, request

app = Flask(__name__)


def get_db():
    return psycopg2.connect(
        host=os.getenv("DB_HOST"),
        database=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
    )


@app.route("/login", methods=["POST"])
def login():
    auth_table = os.getenv("AUTH_TABLE")
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return jsonify({"msg": "Missing username or password"}), 400

    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            f"SELECT email, password FROM {auth_table} WHERE username = %s",
            (auth.username,),
        )
        user = cur.fetchone()
        if not user:
            return jsonify({"msg": "Invalid username or password"}), 400

        if user[1] != auth.password:
            return jsonify({"msg": "Invalid username or password"}), 400

        token = jwt.encode(
            {
                "username": user[0],
                "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1),
                "iat": datetime.datetime.utcnow(),
            },
            os.getenv("SECRET_KEY"),
            algorithm="HS256",
        )

        return jsonify({"token": token.decode("UTF-8")})
    except Exception as e:
        return jsonify({"msg": str(e)}), 500
    finally:
        cur.close()
        conn.close()


@app.route("/validate", methods=["GET"])
def validate():
    encoded_jwt = request.headers.get("Authorization")

    if not encoded_jwt:
        return jsonify({"msg": "Missing token"}), 400

    encoded_jwt = encoded_jwt.split(" ")[1]
    try:
        jwt.decode(encoded_jwt, os.getenv("SECRET_KEY"), algorithms=["HS256"])
        return jsonify({"msg": "Valid token"}), 200
    except Exception as e:
        return jsonify({"msg": str(e)}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
