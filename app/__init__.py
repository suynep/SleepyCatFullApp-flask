from flask import Flask, session
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from os import getenv
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = f"mongodb+srv://suynepal:{getenv('MONGODB_USER_PW')}@dbs-0.odezw.mongodb.net/?retryWrites=true&w=majority&appName=DBs-0"
# Create a new client and connect to the server
MONGO_CLIENT = MongoClient(MONGO_URI, server_api=ServerApi("1"))
db = MONGO_CLIENT["sleepycat"]  # Replace 'my_database' with your database name

# Collections
users_collection = db["users"]
journals_collection = db["journals"]


from flask import (
    request,
    jsonify,
    render_template,
    make_response,
    redirect,
    flash,
    url_for,
)
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import jwt
from datetime import datetime
from datetime import timedelta
from app.models import User, Journal
from bson import ObjectId

app = Flask(__name__)
app.config.from_object("config.Config")


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the Auth request header
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split(" ")[1]
        if not token:
            return jsonify({"message": "Token is missing !!"}), 401

        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            current_user = users_collection.find_one({"_id": ObjectId(data["id"])})
        except:
            return jsonify({"message": "Token is invalid !!"}), 401
        # returns the current logged in users context to the routes
        return f(current_user, *args, **kwargs)

    return decorated

@app.before_request
def auto_set_authorization_header():
    if "jwt" in session:
        # Add the Authorization header to the request object
        request.headers.environ["HTTP_AUTHORIZATION"] = f"Bearer {session['jwt']}"



@app.route("/")
@app.route("/index")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    # creates dictionary of form data
    if request.method == "POST":
        auth = request.form

        if not auth or not auth.get("username") or not auth.get("password"):
            # returns 401 if any email or / and password is missing
            return make_response(
                "Could not verify",
                401,
                {"WWW-Authenticate": 'Basic realm ="Login required !!"'},
            )

        user = users_collection.find_one({"username": auth.get("username")})

        if not user:
            # returns 401 if user does not exist
            return make_response(
                "Could not verify",
                401,
                {"WWW-Authenticate": 'Basic realm ="User does not exist !!"'},
            )

        if check_password_hash(user["password"], auth.get("password")):
            # generates the JWT Token
            token = jwt.encode(
                {
                    "id": str(user["_id"]),
                    "exp": datetime.utcnow() + timedelta(minutes=30),
                },
                app.config["SECRET_KEY"],
                algorithm="HS256",
            )
            session["jwt"] = token
            return redirect(url_for("dashboard"))
        # returns 403 if password is wrong
        return jsonify({"message": "wrong password"}), 403
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        data = request.form

        # gets name, email and password
        username, email = data.get("username"), data.get("email")
        password = data.get("password")
        confirm_password = data.get("confirm_password")

        if password != confirm_password:
            flash("Passwords do not match. Please try again.", "danger")

        # checking for existing user
        user = users_collection.find_one({"username": username})
        if not user:
            # create a dictionary for the user
            hashed_password = generate_password_hash(password)
            user_data = {
                "username": username,
                "email": email,
                "password": hashed_password,
                "profilepic": None,
            }

            # insert user into the database
            users_collection.insert_one(user_data)

            return redirect(url_for("login"))
        else:
            # returns 202 if user already exists
            flash("User already exists. Please Log in.", "danger")
    return render_template("signup.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/dashboard")
# @token_required
def dashboard():
    # print(current_user + " accessed dashboard")
    return render_template("dashboard.html")


@app.route("/journal")
# @token_required
def journal():
    return render_template("journal.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.pop("jwt", None)  # Remove the JWT from the session
    return jsonify({"message": "Logged out successfully"}), 200
    
