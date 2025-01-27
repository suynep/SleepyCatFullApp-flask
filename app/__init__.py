from flask import Flask, session, send_file
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from os import getenv
from dotenv import load_dotenv
from flask_socketio import SocketIO
from app.ai import sentiment_analyser, color_mapper
import tempfile
import os
from markdown_pdf import MarkdownPdf, Section

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
socketio = SocketIO(app) #, async_mode='asyncio', cors_allowed_origins="*")
app.config.from_object("config.Config")


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the Auth request header
        if "jwt" in session:
            token = session["jwt"]
        if not token:
            flash("Token is missing. Please Log in.", "danger")
            return jsonify({"message": "Token is missing !!"}), 401

        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            current_user = users_collection.find_one({"_id": ObjectId(data["id"])})
        except:
            flash("Token is invalid. Please Log in.", "danger")
            return jsonify({"message": "Token is invalid !!"}), 401
        # returns the current logged in users context to the routes
        return f(current_user, *args, **kwargs)

    return decorated


# @app.before_request
# def auto_set_authorization_header():
#     if "jwt" in session:
#         # Add the Authorization header to the request object
#         request.headers.environ["HTTP_AUTHORIZATION"] = f"Bearer {session['jwt']}"


@app.errorhandler(401)
@app.errorhandler(403)
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html", error_message=e), 401


@app.route("/")
@app.route("/index")
def index():
    return render_template("home.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    # creates dictionary of form data
    if request.method == "POST":
        auth = request.form

        if not auth or not auth.get("username") or not auth.get("password"):
            # returns 401 if any email or / and password is missing
            flash("Please enter both username and password", "danger")
            # return render_template("404.html", error_msg="Could not verify"), 401

        user = users_collection.find_one({"username": auth.get("username")})

        if not user:
            # returns 401 if user does not exist
            flash("User does not exist. Please register.", "danger")
            # return render_template("login.html")

        if user:
            if check_password_hash(user["password"], auth.get("password")):
                # generates the JWT Token
                token = jwt.encode(
                    {
                        "id": str(user["_id"]),
                        "exp": datetime.utcnow() + timedelta(hours=1),
                    },
                    app.config["SECRET_KEY"],
                    algorithm="HS256",
                )
                session["jwt"] = token
                flash("Logged in successfully.", "success")
                return redirect(url_for("dashboard"))
            # returns 403 if password is wrong
            flash("Wrong password. Please try again.", "danger")
        # return jsonify({"message": "wrong password"}), 403
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
            return redirect(url_for("signup"))

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
            flash("User created successfully. Please Log in.", "success")
            return redirect(url_for("login"))
        else:
            # returns 202 if user already exists
            flash("User already exists. Please Log in.", "danger")
    return render_template("signup.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/dashboard")
@token_required
def dashboard(current_user):
    print(session["jwt"])
    return render_template("dashboard.html", user=current_user)


@app.route("/journal/<journal_id>")
@token_required
def journal_entry(current_user, journal_id):
    # print("received json: " + str(json))
    # journal_id = json["journalid"]
    journal = journals_collection.find_one({"_id": ObjectId(journal_id)})
    if journal:
        print("Journal found: ", journal)
        return render_template("journal.html", user=current_user, journalid=journal_id, body=journal["body"], title=journal["title"])
    else:
        return render_template("journal.html", user=current_user, journalid=journal_id, body="", title="Untitled")
    # socketio.emit("update", {"data": journal["body"], "title": journal["title"]})
    # journal = journals_collection.find_one({"_id": ObjectId(journal_id)})

@app.route("/journal/delete/<journal_id>")
@token_required
def delete_journal(current_user, journal_id):
    print(journal_id)
    result = journals_collection.delete_one({"_id": ObjectId(journal_id)})
    print(result.raw_result)
    if result.deleted_count == 1:
        print(f"Successfully deleted: <{journal_id}>")

    entries = journals_collection.find({"user_id": str(current_user["_id"])})
    return render_template("journalmenu.html", user=current_user, entries=entries)

@app.route("/journal")
@token_required
def journal(current_user):
    entries = journals_collection.find({"user_id": str(current_user["_id"])})
    print(entries)
    return render_template("journalmenu.html", user=current_user, entries=entries)


@app.route("/logout", methods=["GET"])
def logout():
    session.pop("jwt", None)  # Remove the JWT from the session
    flash("Logged out successfully.", "success")
    return redirect(url_for("about"))


@socketio.on("analyse")
def handle_analyse(json):
    print("data: ", json["data"], "\n", sentiment_analyser(json["data"]), color_mapper(sentiment_analyser(json["data"])))
    socketio.emit("ui_update", {"color": color_mapper(sentiment_analyser(json["data"]))})


@socketio.on("join")
def update_journal(json):
    print("received json: " + str(json))
    journal_id = json["journalid"]
    journal = journals_collection.find_one({"_id": ObjectId(journal_id)})
    socketio.emit("update", {"data": journal["body"], "title": journal["title"]})

@socketio.on("update_title")
def update_journal_title(json):
    print("received title" + str(json))
    new_title = json["title"]
    journal_id = json["journalID"]
    result = journals_collection.update_one(
        {"_id": ObjectId(journal_id)},
        {"$set": {"title": new_title}}
    )
    if result.modified_count > 0:
        print(f"Journal title updated to: {new_title}")
        socketio.emit("title_updated", {"status": "success"})
    else:
        print("Failed to update journal title")
        socketio.emit("title_updated", {"status": "failure"})

@app.route("/download", methods=["POST"])
def download_markdown_as_pdf():
    # Assuming journal content comes from a form submission
    content = request.get_json()
    journal_content = content["body"]
    title = content["title"]

    # Generate the PDF
    temp_dir = tempfile.gettempdir()
    pdf_path = os.path.join(temp_dir, 'journal.pdf')

    print(pdf_path)

    pdf = MarkdownPdf(toc_level=2)
    pdf.add_section(Section(journal_content))
    pdf.save(pdf_path)

    
    # with open(pdf_path, 'wb') as pdf_file:
    #     markdown2pdf3.convert_markdown_to_pdf(journal_content, pdf_file)

    # Serve the PDF for download
    response = send_file(pdf_path, as_attachment=True, download_name=f'{title}.pdf')

    # Clean up the temporary file
    @response.call_on_close
    def cleanup():
        os.remove(pdf_path)

    return response

@app.route("/save", methods=["GET", "POST"])
@token_required
def handle_save(current_user):
    user_id = jwt.decode(
        session["jwt"], app.config["SECRET_KEY"], algorithms=["HS256"]
    )["id"]

    data = request.get_json()

    journal_id = journals_collection.find_one({"_id": ObjectId(data["journalid"])})
    if not journal_id:
        print("Creating new journal" + str(data))
        body = data["data"]
        journals_collection.insert_one({"body": body, "user_id": user_id})
        print("Journal created + saved successfully")
    else:
        print("Updating journal" + str(data))
        title = data["title"]
        journals_collection.update_one(
            {"_id": ObjectId(data["journalid"])}, {"$set": {"body": data["data"], "title": title}}
        )
        socketio.emit(
            "ui_update", {"color": color_mapper(sentiment_analyser(data["data"]))}
        )
        print("data: ", data["data"], "\n", sentiment_analyser(data["data"]), color_mapper(sentiment_analyser(data["data"])))
        print("Journal updated + saved successfully")

    # return redirect(url_for("journal_entry", current_user=current_user, journal_id=data["journalid"]))


    return redirect(f"/journal/{data['journalid']}")
# @socketio.on("save")
# def handle_save(json):
#     user_id = jwt.decode(
#         session["jwt"], app.config["SECRET_KEY"], algorithms=["HS256"]
#     )["id"]
#     journal_id = journals_collection.find_one({"_id": ObjectId(json["journalid"])})
#     if not journal_id:
#         print("Creating new journal" + str(json))
#         body = json["data"]
#         journals_collection.insert_one({"body": body, "user_id": user_id})
#         print("Journal created + saved successfully")
#     else:
#         print("Updating journal" + str(json))
#         journals_collection.update_one(
#             {"_id": ObjectId(json["journalid"])}, {"$set": {"body": json["data"]}}
#         )
#         socketio.emit(
#             "ui_update", {"color": color_mapper(sentiment_analyser(json["data"]))}
#         )
#         print("data: ", json["data"], "\n", sentiment_analyser(json["data"]), color_mapper(sentiment_analyser(json["data"])))
#         print("Journal updated + saved successfully")


@app.route("/create_entry", methods=["GET"])
@token_required
def create_entry(current_user):
    title = "Untitled"
    user_id = jwt.decode(
        session["jwt"], app.config["SECRET_KEY"], algorithms=["HS256"]
    )["id"]
    req_journal = journals_collection.insert_one(
        {"body": "", "user_id": user_id, "title": title, "created": datetime.now()}
    )
    journal_id = str(req_journal.inserted_id)
    flash("Journal entry created successfully.", "success")
    return redirect(url_for("journal_entry", journal_id=journal_id))
    # return render_template("create_entry.html", user=current_user, journal_id=journal_id)
