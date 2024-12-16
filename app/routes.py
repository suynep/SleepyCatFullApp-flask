from flask import request, jsonify, render_template, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from app import users_collection, create_app
from functools import wraps
import jwt
import datetime
from datetime import timedelta
from app.models import User, Journal

app = create_app()


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if "x-access-token" in request.headers:
            token = request.headers["x-access-token"]
        # return 401 if token is not passed
        if not token:
            return jsonify({"message": "Token is missing !!"}), 401

        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token, app.config["SECRET_KEY"])
            current_user = users_collection.find_one({"id": data["_id"]})
        except:
            return jsonify({"message": "Token is invalid !!"}), 401
        # returns the current logged in users context to the routes
        return f(current_user, *args, **kwargs)

    return decorated

@app.route("/")
@app.route("/index")
def index():
    return render_template("index.html")

@app.route("/login", methods=["GET" "POST"])
def login():
    # creates dictionary of form data
    if request.method == "POST":
        auth = request.form

        if not auth or not auth.get("email") or not auth.get("password"):
            # returns 401 if any email or / and password is missing
            return make_response(
                "Could not verify",
                401,
                {"WWW-Authenticate": 'Basic realm ="Login required !!"'},
            )

        user = users_collection.find_one({"email": auth.get("email")})

        if not user:
            # returns 401 if user does not exist
            return make_response(
                "Could not verify",
                401,
                {"WWW-Authenticate": 'Basic realm ="User does not exist !!"'},
            )

        if check_password_hash(user.password, auth.get("password")):
            # generates the JWT Token
            token = jwt.encode(
                {
                    "public_id": user.uid,
                    "exp": datetime.utcnow() + timedelta(minutes=30),
                },
                app.config["SECRET_KEY"],
            )

            return make_response(jsonify({"token": token.decode("UTF-8")}), 201)
        # returns 403 if password is wrong
        return make_response(
            "Could not verify",
            403,
            {"WWW-Authenticate": 'Basic realm ="Wrong Password !!"'},
        )
    return render_template("login.html")


@app.route("/register", methods=["GET" "POST"])
def signup():
    if request.method == "POST":
        data = request.form

        # gets name, email and password
        name, email = data.get("name"), data.get("email")
        password = data.get("password")

        # checking for existing user
        user = users_collection.find_one({"email": email})
        if not user:
            # database ORM object
            user = User(name, email, generate_password_hash(password).decode("utf-8"))
            # insert user
            users_collection.insert_one(user)

            return make_response("Successfully registered.", 201)
        else:
            # returns 202 if user already exists
            return make_response("User already exists. Please Log in.", 202)
    return render_template("signup.html")




@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.route("/journal")
def journal():
    return render_template("journal.html")
